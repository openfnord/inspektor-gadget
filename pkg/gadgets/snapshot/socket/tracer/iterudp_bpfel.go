// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || loong64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadIterUDP returns the embedded CollectionSpec for iterUDP.
func loadIterUDP() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_IterUDPBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load iterUDP: %w", err)
	}

	return spec, err
}

// loadIterUDPObjects loads iterUDP and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*iterUDPObjects
//	*iterUDPPrograms
//	*iterUDPMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadIterUDPObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadIterUDP()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// iterUDPSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type iterUDPSpecs struct {
	iterUDPProgramSpecs
	iterUDPMapSpecs
}

// iterUDPSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type iterUDPProgramSpecs struct {
	IgSnapUdp *ebpf.ProgramSpec `ebpf:"ig_snap_udp"`
}

// iterUDPMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type iterUDPMapSpecs struct {
}

// iterUDPObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadIterUDPObjects or ebpf.CollectionSpec.LoadAndAssign.
type iterUDPObjects struct {
	iterUDPPrograms
	iterUDPMaps
}

func (o *iterUDPObjects) Close() error {
	return _IterUDPClose(
		&o.iterUDPPrograms,
		&o.iterUDPMaps,
	)
}

// iterUDPMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadIterUDPObjects or ebpf.CollectionSpec.LoadAndAssign.
type iterUDPMaps struct {
}

func (m *iterUDPMaps) Close() error {
	return _IterUDPClose()
}

// iterUDPPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadIterUDPObjects or ebpf.CollectionSpec.LoadAndAssign.
type iterUDPPrograms struct {
	IgSnapUdp *ebpf.Program `ebpf:"ig_snap_udp"`
}

func (p *iterUDPPrograms) Close() error {
	return _IterUDPClose(
		p.IgSnapUdp,
	)
}

func _IterUDPClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed iterudp_bpfel.o
var _IterUDPBytes []byte
