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

package tracer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/solo-io/bumblebee/pkg/decoder"
	"gopkg.in/yaml.v3"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/frontends"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

const (
	ParamOCIImage   = "oci-image"
	ProgramContent  = "prog"
	ParamDefinition = "definition"
	printMapPrefix  = "print_"
)

type GadgetDesc struct{}

func (g *GadgetDesc) Name() string {
	return "run"
}

func (g *GadgetDesc) Category() string {
	return gadgets.CategoryNone
}

func (g *GadgetDesc) Type() gadgets.GadgetType {
	// Currently trace only
	return gadgets.TypeTrace
}

func (g *GadgetDesc) Description() string {
	return "Run an eBPF program"
}

func (g *GadgetDesc) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		// TODO: implement
		{
			Key:          ProgramContent,
			Title:        "eBPF program",
			DefaultValue: "",
			Description:  "For development only: The compiled eBPF program. Prepend an @ in front of the path to input a file",
			TypeHint:     params.TypeBytes,
		},
		{
			Key:          ParamDefinition,
			Title:        "Gadget definition",
			DefaultValue: "",
			Description:  "Yaml with the gadget definition",
			TypeHint:     params.TypeBytes,
		},
	}
}

func (g *GadgetDesc) Parser() parser.Parser {
	return nil
}

func getUnderlyingType(tf *btf.Typedef) (btf.Type, error) {
	switch typedMember := tf.Type.(type) {
	case *btf.Typedef:
		return getUnderlyingType(typedMember)
	default:
		return typedMember, nil
	}
}

func getPrintMap(progContent []byte) (*ebpf.MapSpec, error) {
	progReader := bytes.NewReader(progContent)
	spec, err := ebpf.LoadCollectionSpecFromReader(progReader)
	if err != nil {
		return nil, fmt.Errorf("loading spec: %w", err)
	}

	for _, m := range spec.Maps {
		if m.Type != ebpf.RingBuf && m.Type != ebpf.PerfEventArray {
			continue
		}

		if !strings.HasPrefix(m.Name, printMapPrefix) {
			continue
		}

		return m, nil
	}

	return nil, fmt.Errorf("no BPF map with %q prefix found", printMapPrefix)
}

func getValueStructBTF(progContent []byte) (*btf.Struct, error) {
	m, err := getPrintMap(progContent)
	if err != nil {
		return nil, err
	}

	var valueStruct *btf.Struct
	var ok bool
	valueStruct, ok = m.Value.(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("BPF map %q does not have BTF info for values", m.Name)
	}

	return valueStruct, nil
}

func getType(typ btf.Type) reflect.Type {
	switch typedMember := typ.(type) {
	case *btf.Array:
		arrType := getSimpleType(typedMember.Type)
		return reflect.ArrayOf(int(typedMember.Nelems), arrType)
	default:
		return getSimpleType(typ)
	}
}

func getSimpleType(typ btf.Type) reflect.Type {
	switch typedMember := typ.(type) {
	case *btf.Int:
		switch typedMember.Encoding {
		case btf.Signed:
			switch typedMember.Size {
			case 1:
				return reflect.TypeOf(int8(0))
			case 2:
				return reflect.TypeOf(int16(0))
			case 4:
				return reflect.TypeOf(int32(0))
			case 8:
				return reflect.TypeOf(int64(0))
			}
		case btf.Unsigned:
			switch typedMember.Size {
			case 1:
				return reflect.TypeOf(uint8(0))
			case 2:
				return reflect.TypeOf(uint16(0))
			case 4:
				return reflect.TypeOf(uint32(0))
			case 8:
				return reflect.TypeOf(uint64(0))
			}
		case btf.Bool:
			return reflect.TypeOf(bool(false))
		case btf.Char:
			return reflect.TypeOf(uint8(0))
		}
	case *btf.Float:
		switch typedMember.Size {
		case 4:
			return reflect.TypeOf(float32(0))
		case 8:
			return reflect.TypeOf(float64(0))
		}
	case *btf.Typedef:
		typ, _ := getUnderlyingType(typedMember)
		return getSimpleType(typ)
	}

	return nil
}

func (g *GadgetDesc) CustomParser(params *params.Params, args []string) (parser.Parser, error) {
	if len(args) != 0 {
		return nil, fmt.Errorf("no arguments expected: received %d", len(args))
	}
	progContent := params.Get(ProgramContent).AsBytes()
	definitionBytes := params.Get(ParamDefinition).AsBytes()
	if len(definitionBytes) == 0 {
		return nil, fmt.Errorf("no definition provided")
	}

	valueStruct, err := getValueStructBTF(progContent)
	if err != nil {
		return nil, fmt.Errorf("getting value struct: %w", err)
	}

	cols := types.GetColumns()

	var gadgetDefinition types.GadgetDefinition

	if err := yaml.Unmarshal(definitionBytes, &gadgetDefinition); err != nil {
		return nil, fmt.Errorf("unmarshaling definition: %w", err)
	}

	colAttrs := map[string]columns.Attributes{}
	for _, col := range gadgetDefinition.ColumnsAttrs {
		colAttrs[col.Name] = col
	}

	fields := []columns.DynamicField{}

	for _, member := range valueStruct.Members {
		member := member

		attrs, ok := colAttrs[member.Name]
		if !ok {
			continue
		}

		switch typedMember := member.Type.(type) {
		case *btf.Union:
			if typedMember.Name == "ip_addr" {
				cols.AddColumn(attrs, func(ev *types.Event) string {
					// TODO: Handle IPv6
					offset := uintptr(member.Offset.Bytes())
					ipSlice := unsafe.Slice(&ev.RawData[offset], 4)
					ipBytes := make(net.IP, 4)
					copy(ipBytes, ipSlice)
					return ipBytes.String()
				})
				continue
			}
		}

		rType := getType(member.Type)
		if rType == nil {
			continue
		}

		field := columns.DynamicField{
			Attributes: &attrs,
			// TODO: remove once this is part of attributes
			Template: attrs.Template,
			Type:     rType,
			Offset:   uintptr(member.Offset.Bytes()),
		}

		fields = append(fields, field)
	}

	base := func(ev *types.Event) unsafe.Pointer {
		return unsafe.Pointer(&ev.RawData[0])
	}
	if err := cols.AddFields(fields, base); err != nil {
		return nil, fmt.Errorf("adding fields: %w", err)
	}

	return parser.NewParser[types.Event](cols), nil
}

func genericConverter(params *params.Params, fe frontends.Frontend, convert func(any) ([]byte, error)) func(ev any) {
	decoderFactory := decoder.NewDecoderFactory()()

	// TODO: add support for OCI programs
	progContent := params.Get(ProgramContent).AsBytes()

	valueStruct, err := getValueStructBTF(progContent)
	if err != nil {
		fe.Logf(logger.WarnLevel, "coult not get value struct BTF: %s", err)
		return nil
	}

	ctx := context.TODO()

	return func(ev any) {
		event := ev.(*types.Event)

		result, err := decoderFactory.DecodeBtfBinary(ctx, valueStruct, event.RawData)
		if err != nil {
			fe.Logf(logger.WarnLevel, "decoding %+v: %s", ev, err)
			return
		}

		// TODO: flatten the results?
		event.Data = result

		d, err := convert(event)
		if err != nil {
			fe.Logf(logger.WarnLevel, "marshalling %+v: %s", ev, err)
			return
		}
		fe.Output(string(d))
	}
}

func (g *GadgetDesc) JsonConverter(params *params.Params, fe frontends.Frontend) func(ev any) {
	return genericConverter(params, fe, json.Marshal)
}

func (g *GadgetDesc) JsonPrettyConverter(params *params.Params, fe frontends.Frontend) func(ev any) {
	convert := func(ev any) ([]byte, error) {
		return json.MarshalIndent(ev, "", "  ")
	}
	return genericConverter(params, fe, convert)
}

func (g *GadgetDesc) YamlConverter(params *params.Params, fe frontends.Frontend) func(ev any) {
	return genericConverter(params, fe, k8syaml.Marshal)
}

func (g *GadgetDesc) EventPrototype() any {
	return &types.Event{}
}

func init() {
	gadgetregistry.Register(&GadgetDesc{})
}
