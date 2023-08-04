// Copyright 2023 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !withoutebpf

package tracer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	beespec "github.com/solo-io/bumblebee/pkg/spec"
	orascontent "oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/netnsenter"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	bpfiterns "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/bpf-iter-ns"
)

// keep aligned with pkg/gadgets/common/types.h
type l3EndpointT struct {
	addr    [16]byte
	version uint8
	pad     [3]uint8 // manual padding to avoid issues between C and Go
}

type l4EndpointT struct {
	l3    l3EndpointT
	port  uint16
	proto uint16
}

type Config struct {
	RegistryAuth orascontent.RegistryOptions
	ProgLocation string
	ProgContent  []byte
	MountnsMap   *ebpf.Map
}

type linkIter struct {
	link *link.Iter
	typ  string
}

type Tracer struct {
	config             *Config
	eventCallback      func(*types.Event)
	eventArrayCallback func([]*types.Event)

	spec       *ebpf.CollectionSpec
	collection *ebpf.Collection
	// Type describing the format the gadget uses
	eventType *btf.Struct

	// Printers related
	printMap          *ebpf.MapSpec
	ringbufReader     *ringbuf.Reader
	perfReader        *perf.Reader
	printMapValueSize uint32

	links []link.Link

	// Iterators related
	linksIter []*linkIter

	// containers
	// TODO: do we need a lock?
	containers map[string]*containercollection.Container
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config:     &Config{},
		containers: make(map[string]*containercollection.Container),
	}
	return tracer, nil
}

func (t *Tracer) Init(gadgetCtx gadgets.GadgetContext) error {
	return nil
}

// Close is needed because of the StartStopGadget interface
func (t *Tracer) Close() {
}

func (t *Tracer) getByobEbpfPackage() (*beespec.EbpfPackage, error) {
	localRegistry := orascontent.NewMemory()

	remoteRegistry, err := orascontent.NewRegistry(t.config.RegistryAuth)
	if err != nil {
		return nil, fmt.Errorf("create new oras registry: %w", err)
	}

	_, err = oras.Copy(
		context.Background(),
		remoteRegistry,
		t.config.ProgLocation,
		localRegistry,
		t.config.ProgLocation,
	)
	if err != nil {
		return nil, fmt.Errorf("copy oras: %w", err)
	}
	byobClient := beespec.NewEbpfOCICLient()
	return byobClient.Pull(context.Background(), t.config.ProgLocation, localRegistry)
}

func (t *Tracer) Stop() {
	if t.collection != nil {
		t.collection.Close()
		t.collection = nil
	}
	for _, l := range t.links {
		gadgets.CloseLink(l)
	}
	t.links = nil

	if t.ringbufReader != nil {
		t.ringbufReader.Close()
	}
	if t.perfReader != nil {
		t.perfReader.Close()
	}
}

func (t *Tracer) handlePrint() error {
	t.printMap = getPrintMap(t.spec)
	if t.printMap == nil {
		return nil
	}

	eventType, ok := t.printMap.Value.(*btf.Struct)
	if !ok {
		return fmt.Errorf("BPF map %q does not have BTF info for values", t.printMap.Name)
	}
	t.eventType = eventType

	// Almost same hack as in bumblebee/pkg/loader/loader.go
	t.printMapValueSize = t.printMap.ValueSize
	switch t.printMap.Type {
	case ebpf.RingBuf:
		t.printMap.ValueSize = 0
	case ebpf.PerfEventArray:
		t.printMap.KeySize = 4
		t.printMap.ValueSize = 4
	}

	return nil
}

func (t *Tracer) handleIter() error {
	eventType := getIterType(t.spec)
	if eventType == nil {
		return nil
	}

	t.eventType = eventType
	return nil
}

func (t *Tracer) installTracer() error {
	// Load the spec
	var err error
	t.spec, err = loadSpec(t.config.ProgContent)
	if err != nil {
		return err
	}

	mapReplacements := map[string]*ebpf.Map{}
	consts := map[string]interface{}{}

	if err := t.handlePrint(); err != nil {
		return fmt.Errorf("handling print_ programs: %w", err)
	}

	if err := t.handleIter(); err != nil {
		return fmt.Errorf("handling iterator programs: %w", err)
	}

	if t.eventType == nil {
		return fmt.Errorf("the gadget doesn't provide event type information")
	}

	// Handle special maps like mount ns filter, socket enricher, etc.
	if t.config.MountnsMap != nil {
		for _, m := range t.spec.Maps {
			// Replace filter mount ns map
			if m.Name == gadgets.MntNsFilterMapName {
				mapReplacements[gadgets.MntNsFilterMapName] = t.config.MountnsMap
				consts[gadgets.FilterByMntNsName] = true
			}
		}

		if err := t.spec.RewriteConstants(consts); err != nil {
			return fmt.Errorf("rewriting constants: %w", err)
		}
	}

	// Load the ebpf objects
	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}
	t.collection, err = ebpf.NewCollectionWithOptions(t.spec, opts)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}

	// Some logic before loading the programs
	if t.printMap != nil {
		m := t.collection.Maps[t.printMap.Name]
		switch m.Type() {
		case ebpf.RingBuf:
			t.ringbufReader, err = ringbuf.NewReader(t.collection.Maps[t.printMap.Name])
		case ebpf.PerfEventArray:
			t.perfReader, err = perf.NewReader(t.collection.Maps[t.printMap.Name], gadgets.PerfBufferPages*os.Getpagesize())
		}
		if err != nil {
			return fmt.Errorf("create BPF map reader: %w", err)
		}
	}

	// Attach programs
	for progName, p := range t.spec.Programs {
		if p.Type == ebpf.Kprobe && strings.HasPrefix(p.SectionName, "kprobe/") {
			l, err := link.Kprobe(p.AttachTo, t.collection.Programs[progName], nil)
			if err != nil {
				return fmt.Errorf("attach BPF program %q: %w", progName, err)
			}
			t.links = append(t.links, l)
		} else if p.Type == ebpf.Kprobe && strings.HasPrefix(p.SectionName, "kretprobe/") {
			l, err := link.Kretprobe(p.AttachTo, t.collection.Programs[progName], nil)
			if err != nil {
				return fmt.Errorf("attach BPF program %q: %w", progName, err)
			}
			t.links = append(t.links, l)
		} else if p.Type == ebpf.TracePoint && strings.HasPrefix(p.SectionName, "tracepoint/") {
			parts := strings.Split(p.AttachTo, "/")
			l, err := link.Tracepoint(parts[0], parts[1], t.collection.Programs[progName], nil)
			if err != nil {
				return fmt.Errorf("attach BPF program %q: %w", progName, err)
			}
			t.links = append(t.links, l)
		} else if p.Type == ebpf.Tracing && strings.HasPrefix(p.SectionName, "iter/") {
			switch p.AttachTo {
			case "task", "tcp", "udp":
				l, err := link.AttachIter(link.IterOptions{
					Program: t.collection.Programs[progName],
				})
				if err != nil {
					return fmt.Errorf("attach BPF program %q: %w", progName, err)
				}
				t.links = append(t.links, l)
				t.linksIter = append(t.linksIter, &linkIter{link: l, typ: p.AttachTo})
			default:
				return fmt.Errorf("unsupported iter type %q", p.AttachTo)
			}
		}
	}

	return nil
}

// processEventFunc returns a callback that parses a binary encoded event in data, enriches and
// returns it.
func (t *Tracer) processEventFunc(gadgetCtx gadgets.GadgetContext) func(data []byte) *types.Event {
	typ := t.eventType

	var mntNsIdstart uint32
	mountNsIdFound := false

	type endpointType int

	const (
		U endpointType = iota
		L3
		L4
	)

	type endpointDef struct {
		name  string
		start uint32
		typ   endpointType
	}

	endpointDefs := []endpointDef{}

	// The same same data structure is always sent, so we can precalculate the offsets for
	// different fields like mount ns id, endpoints, etc.
	for _, member := range typ.Members {
		switch member.Type.TypeName() {
		case gadgets.MntNsIdTypeName:
			typDef, ok := member.Type.(*btf.Typedef)
			if !ok {
				continue
			}

			underlying, err := getUnderlyingType(typDef)
			if err != nil {
				continue
			}

			intM, ok := underlying.(*btf.Int)
			if !ok {
				continue
			}

			if intM.Size != 8 {
				continue
			}

			mntNsIdstart = member.Offset.Bytes()
			mountNsIdFound = true
		case gadgets.L3EndpointTypeName:
			typ, ok := member.Type.(*btf.Struct)
			if !ok {
				gadgetCtx.Logger().Warn("%s is not a struct", member.Name)
				continue
			}
			if typ.Size != uint32(unsafe.Sizeof(l3EndpointT{})) {
				gadgetCtx.Logger().Warn("%s is not the expected size", member.Name)
				continue
			}
			e := endpointDef{name: member.Name, start: member.Offset.Bytes(), typ: L3}
			endpointDefs = append(endpointDefs, e)
		case gadgets.L4EndpointTypeName:
			typ, ok := member.Type.(*btf.Struct)
			if !ok {
				gadgetCtx.Logger().Warn("%s is not a struct", member.Name)
				continue
			}
			if typ.Size != uint32(unsafe.Sizeof(l4EndpointT{})) {
				gadgetCtx.Logger().Warn("%s is not the expected size", member.Name)
				continue
			}
			e := endpointDef{name: member.Name, start: member.Offset.Bytes(), typ: L4}
			endpointDefs = append(endpointDefs, e)
		}
	}

	return func(data []byte) *types.Event {
		// get mnt_ns_id for enriching the event
		mtn_ns_id := uint64(0)
		if mountNsIdFound {
			mtn_ns_id = *(*uint64)(unsafe.Pointer(&data[mntNsIdstart]))
		}

		// enrich endpoints
		l3endpoints := []types.L3Endpoint{}
		l4endpoints := []types.L4Endpoint{}

		for _, endpoint := range endpointDefs {
			endpointC := (*l3EndpointT)(unsafe.Pointer(&data[endpoint.start]))
			var size int
			switch endpointC.version {
			case 4:
				size = 4
			case 6:
				size = 16
			default:
				gadgetCtx.Logger().Warnf("bad IP version received: %d", endpointC.version)
				continue
			}

			ipBytes := make(net.IP, size)
			copy(ipBytes, endpointC.addr[:])

			l3endpoint := eventtypes.L3Endpoint{
				Addr:    ipBytes.String(),
				Version: endpointC.version,
			}

			switch endpoint.typ {
			case L3:
				endpoint := types.L3Endpoint{
					Name:       endpoint.name,
					L3Endpoint: l3endpoint,
				}
				l3endpoints = append(l3endpoints, endpoint)
			case L4:
				l4EndpointC := (*l4EndpointT)(unsafe.Pointer(&data[endpoint.start]))
				endpoint := types.L4Endpoint{
					Name: endpoint.name,
					L4Endpoint: eventtypes.L4Endpoint{
						L3Endpoint: l3endpoint,
						Port:       l4EndpointC.port,
						Proto:      l4EndpointC.proto,
					},
				}
				l4endpoints = append(l4endpoints, endpoint)
			}
		}

		return &types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
			},
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: mtn_ns_id},
			RawData:       data,
			L3Endpoints:   l3endpoints,
			L4Endpoints:   l4endpoints,
		}
	}
}

func (t *Tracer) runPrint(gadgetCtx gadgets.GadgetContext) {
	cb := t.processEventFunc(gadgetCtx)

	for {
		var rawSample []byte

		if t.ringbufReader != nil {
			record, err := t.ringbufReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					// nothing to do, we're done
					return
				}
				gadgetCtx.Logger().Errorf("read ring buffer: %w", err)
				return
			}
			rawSample = record.RawSample
		} else if t.perfReader != nil {
			record, err := t.perfReader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				gadgetCtx.Logger().Errorf("read perf ring buffer: %w", err)
				return
			}

			if record.LostSamples != 0 {
				gadgetCtx.Logger().Warnf("lost %d samples", record.LostSamples)
				continue
			}
			rawSample = record.RawSample
		}

		// TODO: this check is not valid for all cases. For instance trace exec sends a variable length
		if uint32(len(rawSample)) < t.printMapValueSize {
			gadgetCtx.Logger().Errorf("read ring buffer: len(RawSample)=%d!=%d",
				len(rawSample), t.printMapValueSize)
			return
		}

		// data will be decoded in the client
		data := rawSample[:t.printMapValueSize]
		ev := cb(data)
		t.eventCallback(ev)
	}
}

func (t *Tracer) runIterInAllNetNs(it *link.Iter, cb func([]byte) *types.Event) ([]*types.Event, error) {
	events := []*types.Event{}
	s := int(t.eventType.Size)

	namespacesToVisit := map[uint64]*containercollection.Container{}
	for _, c := range t.containers {
		namespacesToVisit[c.Netns] = c
	}

	for _, container := range namespacesToVisit {
		err := netnsenter.NetnsEnter(int(container.Pid), func() error {
			reader, err := it.Open()
			if err != nil {
				return err
			}
			defer reader.Close()

			buf, err := io.ReadAll(reader)
			if err != nil {
				return err
			}

			eventsLocal := splitAndConvert(buf, s, cb)
			for _, ev := range eventsLocal {
				// TODO: set all the values here to avoid depending on the enricher?
				ev.NetNsID = container.Netns
			}

			events = append(events, eventsLocal...)

			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return events, nil
}

func splitAndConvert(data []byte, size int, cb func([]byte) *types.Event) []*types.Event {
	events := make([]*types.Event, len(data)/size)
	for i := 0; i < len(data)/size; i++ {
		ev := cb(data[i*size : (i+1)*size])
		events[i] = ev
	}
	return events
}

func (t *Tracer) runIter(gadgetCtx gadgets.GadgetContext) error {
	cb := t.processEventFunc(gadgetCtx)

	events := []*types.Event{}

	for _, l := range t.linksIter {
		switch l.typ {
		// Iterators that have to be run in the root pid namespace
		case "task":
			buf, err := bpfiterns.Read(l.link)
			if err != nil {
				return fmt.Errorf("reading iterator: %w", err)
			}
			eventsL := splitAndConvert(buf, int(t.eventType.Size), cb)
			events = append(events, eventsL...)
		// Iterators that have to be run on each network namespace
		case "tcp", "udp":
			var err error
			eventsL, err := t.runIterInAllNetNs(l.link, cb)
			if err != nil {
				return fmt.Errorf("reading iterator: %w", err)
			}
			events = append(events, eventsL...)
		}
	}

	t.eventArrayCallback(events)

	return nil
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	if len(params.Get(ProgramContent).AsBytes()) != 0 {
		t.config.ProgContent = params.Get(ProgramContent).AsBytes()
	} else {
		args := gadgetCtx.Args()
		if len(args) != 1 {
			return fmt.Errorf("expected exactly one argument, got %d", len(args))
		}

		param := args[0]
		t.config.ProgLocation = param
		// Download the BPF module
		byobEbpfPackage, err := t.getByobEbpfPackage()
		if err != nil {
			return fmt.Errorf("download byob ebpf package: %w", err)
		}
		t.config.ProgContent = byobEbpfPackage.ProgramFileBytes
	}

	if err := t.installTracer(); err != nil {
		t.Stop()
		return fmt.Errorf("install tracer: %w", err)
	}

	if t.printMap != nil {
		go t.runPrint(gadgetCtx)
	}
	if len(t.linksIter) > 0 {
		return t.runIter(gadgetCtx)
	}
	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	return nil
}

func (t *Tracer) SetMountNsMap(mountnsMap *ebpf.Map) {
	t.config.MountnsMap = mountnsMap
}

func (t *Tracer) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *types.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

func (t *Tracer) SetEventHandlerArray(handler any) {
	nh, ok := handler.(func(ev []*types.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventArrayCallback = nh
}

func (t *Tracer) AttachContainer(container *containercollection.Container) error {
	// TODO: should we use another ID?
	t.containers[container.Runtime.ContainerID] = container
	return nil
}

func (t *Tracer) DetachContainer(container *containercollection.Container) error {
	delete(t.containers, container.Runtime.ContainerID)
	return nil
}
