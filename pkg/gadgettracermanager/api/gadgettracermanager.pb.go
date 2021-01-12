// Code generated by protoc-gen-go. DO NOT EDIT.
// source: gadgettracermanager.proto

/*
Package gadgettracermanager is a generated protocol buffer package.

It is generated from these files:
	gadgettracermanager.proto

It has these top-level messages:
	Label
	AddTracerRequest
	RemoveTracerResponse
	QueryTracerResponse
	AddContainerResponse
	RemoveContainerResponse
	ContainerSelector
	TracerID
	ContainerDefinition
	DumpStateRequest
	Dump
*/
package gadgettracermanager

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Label struct {
	Key   string `protobuf:"bytes,1,opt,name=key" json:"key,omitempty"`
	Value string `protobuf:"bytes,2,opt,name=value" json:"value,omitempty"`
}

func (m *Label) Reset()                    { *m = Label{} }
func (m *Label) String() string            { return proto.CompactTextString(m) }
func (*Label) ProtoMessage()               {}
func (*Label) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Label) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *Label) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

type AddTracerRequest struct {
	Id       string             `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
	Selector *ContainerSelector `protobuf:"bytes,2,opt,name=selector" json:"selector,omitempty"`
}

func (m *AddTracerRequest) Reset()                    { *m = AddTracerRequest{} }
func (m *AddTracerRequest) String() string            { return proto.CompactTextString(m) }
func (*AddTracerRequest) ProtoMessage()               {}
func (*AddTracerRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *AddTracerRequest) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *AddTracerRequest) GetSelector() *ContainerSelector {
	if m != nil {
		return m.Selector
	}
	return nil
}

type RemoveTracerResponse struct {
	Debug string `protobuf:"bytes,1,opt,name=debug" json:"debug,omitempty"`
}

func (m *RemoveTracerResponse) Reset()                    { *m = RemoveTracerResponse{} }
func (m *RemoveTracerResponse) String() string            { return proto.CompactTextString(m) }
func (*RemoveTracerResponse) ProtoMessage()               {}
func (*RemoveTracerResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *RemoveTracerResponse) GetDebug() string {
	if m != nil {
		return m.Debug
	}
	return ""
}

type QueryTracerResponse struct {
	Response string `protobuf:"bytes,1,opt,name=response" json:"response,omitempty"`
}

func (m *QueryTracerResponse) Reset()                    { *m = QueryTracerResponse{} }
func (m *QueryTracerResponse) String() string            { return proto.CompactTextString(m) }
func (*QueryTracerResponse) ProtoMessage()               {}
func (*QueryTracerResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *QueryTracerResponse) GetResponse() string {
	if m != nil {
		return m.Response
	}
	return ""
}

type AddContainerResponse struct {
	Debug string `protobuf:"bytes,1,opt,name=debug" json:"debug,omitempty"`
}

func (m *AddContainerResponse) Reset()                    { *m = AddContainerResponse{} }
func (m *AddContainerResponse) String() string            { return proto.CompactTextString(m) }
func (*AddContainerResponse) ProtoMessage()               {}
func (*AddContainerResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *AddContainerResponse) GetDebug() string {
	if m != nil {
		return m.Debug
	}
	return ""
}

type RemoveContainerResponse struct {
	Debug string `protobuf:"bytes,1,opt,name=debug" json:"debug,omitempty"`
}

func (m *RemoveContainerResponse) Reset()                    { *m = RemoveContainerResponse{} }
func (m *RemoveContainerResponse) String() string            { return proto.CompactTextString(m) }
func (*RemoveContainerResponse) ProtoMessage()               {}
func (*RemoveContainerResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *RemoveContainerResponse) GetDebug() string {
	if m != nil {
		return m.Debug
	}
	return ""
}

type ContainerSelector struct {
	Namespace     string   `protobuf:"bytes,1,opt,name=namespace" json:"namespace,omitempty"`
	Podname       string   `protobuf:"bytes,2,opt,name=podname" json:"podname,omitempty"`
	Labels        []*Label `protobuf:"bytes,3,rep,name=labels" json:"labels,omitempty"`
	ContainerName string   `protobuf:"bytes,4,opt,name=container_name,json=containerName" json:"container_name,omitempty"`
}

func (m *ContainerSelector) Reset()                    { *m = ContainerSelector{} }
func (m *ContainerSelector) String() string            { return proto.CompactTextString(m) }
func (*ContainerSelector) ProtoMessage()               {}
func (*ContainerSelector) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *ContainerSelector) GetNamespace() string {
	if m != nil {
		return m.Namespace
	}
	return ""
}

func (m *ContainerSelector) GetPodname() string {
	if m != nil {
		return m.Podname
	}
	return ""
}

func (m *ContainerSelector) GetLabels() []*Label {
	if m != nil {
		return m.Labels
	}
	return nil
}

func (m *ContainerSelector) GetContainerName() string {
	if m != nil {
		return m.ContainerName
	}
	return ""
}

type TracerID struct {
	Id string `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
}

func (m *TracerID) Reset()                    { *m = TracerID{} }
func (m *TracerID) String() string            { return proto.CompactTextString(m) }
func (*TracerID) ProtoMessage()               {}
func (*TracerID) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func (m *TracerID) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

type ContainerDefinition struct {
	ContainerId   string   `protobuf:"bytes,1,opt,name=container_id,json=containerId" json:"container_id,omitempty"`
	CgroupPath    string   `protobuf:"bytes,2,opt,name=cgroup_path,json=cgroupPath" json:"cgroup_path,omitempty"`
	CgroupId      uint64   `protobuf:"varint,3,opt,name=cgroup_id,json=cgroupId" json:"cgroup_id,omitempty"`
	Mntns         uint64   `protobuf:"varint,4,opt,name=mntns" json:"mntns,omitempty"`
	Namespace     string   `protobuf:"bytes,5,opt,name=namespace" json:"namespace,omitempty"`
	Podname       string   `protobuf:"bytes,6,opt,name=podname" json:"podname,omitempty"`
	ContainerName string   `protobuf:"bytes,7,opt,name=container_name,json=containerName" json:"container_name,omitempty"`
	Labels        []*Label `protobuf:"bytes,8,rep,name=labels" json:"labels,omitempty"`
	// Data required to find the container to Pod association in the
	// gadgettracermanager.
	CgroupV1     string   `protobuf:"bytes,9,opt,name=cgroup_v1,json=cgroupV1" json:"cgroup_v1,omitempty"`
	CgroupV2     string   `protobuf:"bytes,10,opt,name=cgroup_v2,json=cgroupV2" json:"cgroup_v2,omitempty"`
	MountSources []string `protobuf:"bytes,11,rep,name=mount_sources,json=mountSources" json:"mount_sources,omitempty"`
}

func (m *ContainerDefinition) Reset()                    { *m = ContainerDefinition{} }
func (m *ContainerDefinition) String() string            { return proto.CompactTextString(m) }
func (*ContainerDefinition) ProtoMessage()               {}
func (*ContainerDefinition) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{8} }

func (m *ContainerDefinition) GetContainerId() string {
	if m != nil {
		return m.ContainerId
	}
	return ""
}

func (m *ContainerDefinition) GetCgroupPath() string {
	if m != nil {
		return m.CgroupPath
	}
	return ""
}

func (m *ContainerDefinition) GetCgroupId() uint64 {
	if m != nil {
		return m.CgroupId
	}
	return 0
}

func (m *ContainerDefinition) GetMntns() uint64 {
	if m != nil {
		return m.Mntns
	}
	return 0
}

func (m *ContainerDefinition) GetNamespace() string {
	if m != nil {
		return m.Namespace
	}
	return ""
}

func (m *ContainerDefinition) GetPodname() string {
	if m != nil {
		return m.Podname
	}
	return ""
}

func (m *ContainerDefinition) GetContainerName() string {
	if m != nil {
		return m.ContainerName
	}
	return ""
}

func (m *ContainerDefinition) GetLabels() []*Label {
	if m != nil {
		return m.Labels
	}
	return nil
}

func (m *ContainerDefinition) GetCgroupV1() string {
	if m != nil {
		return m.CgroupV1
	}
	return ""
}

func (m *ContainerDefinition) GetCgroupV2() string {
	if m != nil {
		return m.CgroupV2
	}
	return ""
}

func (m *ContainerDefinition) GetMountSources() []string {
	if m != nil {
		return m.MountSources
	}
	return nil
}

type DumpStateRequest struct {
}

func (m *DumpStateRequest) Reset()                    { *m = DumpStateRequest{} }
func (m *DumpStateRequest) String() string            { return proto.CompactTextString(m) }
func (*DumpStateRequest) ProtoMessage()               {}
func (*DumpStateRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{9} }

type Dump struct {
	State string `protobuf:"bytes,1,opt,name=state" json:"state,omitempty"`
}

func (m *Dump) Reset()                    { *m = Dump{} }
func (m *Dump) String() string            { return proto.CompactTextString(m) }
func (*Dump) ProtoMessage()               {}
func (*Dump) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{10} }

func (m *Dump) GetState() string {
	if m != nil {
		return m.State
	}
	return ""
}

func init() {
	proto.RegisterType((*Label)(nil), "gadgettracermanager.Label")
	proto.RegisterType((*AddTracerRequest)(nil), "gadgettracermanager.AddTracerRequest")
	proto.RegisterType((*RemoveTracerResponse)(nil), "gadgettracermanager.RemoveTracerResponse")
	proto.RegisterType((*QueryTracerResponse)(nil), "gadgettracermanager.QueryTracerResponse")
	proto.RegisterType((*AddContainerResponse)(nil), "gadgettracermanager.AddContainerResponse")
	proto.RegisterType((*RemoveContainerResponse)(nil), "gadgettracermanager.RemoveContainerResponse")
	proto.RegisterType((*ContainerSelector)(nil), "gadgettracermanager.ContainerSelector")
	proto.RegisterType((*TracerID)(nil), "gadgettracermanager.TracerID")
	proto.RegisterType((*ContainerDefinition)(nil), "gadgettracermanager.ContainerDefinition")
	proto.RegisterType((*DumpStateRequest)(nil), "gadgettracermanager.DumpStateRequest")
	proto.RegisterType((*Dump)(nil), "gadgettracermanager.Dump")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for GadgetTracerManager service

type GadgetTracerManagerClient interface {
	AddTracer(ctx context.Context, in *AddTracerRequest, opts ...grpc.CallOption) (*TracerID, error)
	RemoveTracer(ctx context.Context, in *TracerID, opts ...grpc.CallOption) (*RemoveTracerResponse, error)
	QueryTracer(ctx context.Context, in *TracerID, opts ...grpc.CallOption) (*QueryTracerResponse, error)
	AddContainer(ctx context.Context, in *ContainerDefinition, opts ...grpc.CallOption) (*AddContainerResponse, error)
	RemoveContainer(ctx context.Context, in *ContainerDefinition, opts ...grpc.CallOption) (*RemoveContainerResponse, error)
	DumpState(ctx context.Context, in *DumpStateRequest, opts ...grpc.CallOption) (*Dump, error)
}

type gadgetTracerManagerClient struct {
	cc *grpc.ClientConn
}

func NewGadgetTracerManagerClient(cc *grpc.ClientConn) GadgetTracerManagerClient {
	return &gadgetTracerManagerClient{cc}
}

func (c *gadgetTracerManagerClient) AddTracer(ctx context.Context, in *AddTracerRequest, opts ...grpc.CallOption) (*TracerID, error) {
	out := new(TracerID)
	err := grpc.Invoke(ctx, "/gadgettracermanager.GadgetTracerManager/AddTracer", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gadgetTracerManagerClient) RemoveTracer(ctx context.Context, in *TracerID, opts ...grpc.CallOption) (*RemoveTracerResponse, error) {
	out := new(RemoveTracerResponse)
	err := grpc.Invoke(ctx, "/gadgettracermanager.GadgetTracerManager/RemoveTracer", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gadgetTracerManagerClient) QueryTracer(ctx context.Context, in *TracerID, opts ...grpc.CallOption) (*QueryTracerResponse, error) {
	out := new(QueryTracerResponse)
	err := grpc.Invoke(ctx, "/gadgettracermanager.GadgetTracerManager/QueryTracer", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gadgetTracerManagerClient) AddContainer(ctx context.Context, in *ContainerDefinition, opts ...grpc.CallOption) (*AddContainerResponse, error) {
	out := new(AddContainerResponse)
	err := grpc.Invoke(ctx, "/gadgettracermanager.GadgetTracerManager/AddContainer", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gadgetTracerManagerClient) RemoveContainer(ctx context.Context, in *ContainerDefinition, opts ...grpc.CallOption) (*RemoveContainerResponse, error) {
	out := new(RemoveContainerResponse)
	err := grpc.Invoke(ctx, "/gadgettracermanager.GadgetTracerManager/RemoveContainer", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gadgetTracerManagerClient) DumpState(ctx context.Context, in *DumpStateRequest, opts ...grpc.CallOption) (*Dump, error) {
	out := new(Dump)
	err := grpc.Invoke(ctx, "/gadgettracermanager.GadgetTracerManager/DumpState", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for GadgetTracerManager service

type GadgetTracerManagerServer interface {
	AddTracer(context.Context, *AddTracerRequest) (*TracerID, error)
	RemoveTracer(context.Context, *TracerID) (*RemoveTracerResponse, error)
	QueryTracer(context.Context, *TracerID) (*QueryTracerResponse, error)
	AddContainer(context.Context, *ContainerDefinition) (*AddContainerResponse, error)
	RemoveContainer(context.Context, *ContainerDefinition) (*RemoveContainerResponse, error)
	DumpState(context.Context, *DumpStateRequest) (*Dump, error)
}

func RegisterGadgetTracerManagerServer(s *grpc.Server, srv GadgetTracerManagerServer) {
	s.RegisterService(&_GadgetTracerManager_serviceDesc, srv)
}

func _GadgetTracerManager_AddTracer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddTracerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GadgetTracerManagerServer).AddTracer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gadgettracermanager.GadgetTracerManager/AddTracer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GadgetTracerManagerServer).AddTracer(ctx, req.(*AddTracerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GadgetTracerManager_RemoveTracer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TracerID)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GadgetTracerManagerServer).RemoveTracer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gadgettracermanager.GadgetTracerManager/RemoveTracer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GadgetTracerManagerServer).RemoveTracer(ctx, req.(*TracerID))
	}
	return interceptor(ctx, in, info, handler)
}

func _GadgetTracerManager_QueryTracer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TracerID)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GadgetTracerManagerServer).QueryTracer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gadgettracermanager.GadgetTracerManager/QueryTracer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GadgetTracerManagerServer).QueryTracer(ctx, req.(*TracerID))
	}
	return interceptor(ctx, in, info, handler)
}

func _GadgetTracerManager_AddContainer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ContainerDefinition)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GadgetTracerManagerServer).AddContainer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gadgettracermanager.GadgetTracerManager/AddContainer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GadgetTracerManagerServer).AddContainer(ctx, req.(*ContainerDefinition))
	}
	return interceptor(ctx, in, info, handler)
}

func _GadgetTracerManager_RemoveContainer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ContainerDefinition)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GadgetTracerManagerServer).RemoveContainer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gadgettracermanager.GadgetTracerManager/RemoveContainer",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GadgetTracerManagerServer).RemoveContainer(ctx, req.(*ContainerDefinition))
	}
	return interceptor(ctx, in, info, handler)
}

func _GadgetTracerManager_DumpState_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DumpStateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GadgetTracerManagerServer).DumpState(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/gadgettracermanager.GadgetTracerManager/DumpState",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GadgetTracerManagerServer).DumpState(ctx, req.(*DumpStateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _GadgetTracerManager_serviceDesc = grpc.ServiceDesc{
	ServiceName: "gadgettracermanager.GadgetTracerManager",
	HandlerType: (*GadgetTracerManagerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "AddTracer",
			Handler:    _GadgetTracerManager_AddTracer_Handler,
		},
		{
			MethodName: "RemoveTracer",
			Handler:    _GadgetTracerManager_RemoveTracer_Handler,
		},
		{
			MethodName: "QueryTracer",
			Handler:    _GadgetTracerManager_QueryTracer_Handler,
		},
		{
			MethodName: "AddContainer",
			Handler:    _GadgetTracerManager_AddContainer_Handler,
		},
		{
			MethodName: "RemoveContainer",
			Handler:    _GadgetTracerManager_RemoveContainer_Handler,
		},
		{
			MethodName: "DumpState",
			Handler:    _GadgetTracerManager_DumpState_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "gadgettracermanager.proto",
}

func init() { proto.RegisterFile("gadgettracermanager.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 588 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x94, 0x55, 0xe9, 0x6e, 0xd3, 0x40,
	0x10, 0xce, 0xd5, 0x36, 0x1e, 0xa7, 0xa5, 0x6c, 0x2a, 0xe1, 0x9a, 0x22, 0xc2, 0xa2, 0x22, 0x23,
	0x55, 0xad, 0x62, 0x9e, 0xa0, 0x10, 0x09, 0x45, 0xe2, 0x74, 0x10, 0x42, 0xfc, 0x89, 0x36, 0xde,
	0x69, 0x6a, 0x35, 0x3e, 0xb0, 0xd7, 0x91, 0xfa, 0x42, 0xbc, 0x09, 0xaf, 0x85, 0x90, 0xbd, 0xb6,
	0x73, 0x74, 0x93, 0x96, 0x7f, 0x9e, 0x6f, 0xee, 0x6f, 0x66, 0xd6, 0x70, 0x3c, 0x65, 0x7c, 0x8a,
	0x42, 0xc4, 0xcc, 0xc5, 0xd8, 0x67, 0x01, 0x9b, 0x62, 0x7c, 0x1e, 0xc5, 0xa1, 0x08, 0x49, 0x57,
	0xa1, 0xa2, 0x17, 0xb0, 0xf3, 0x81, 0x4d, 0x70, 0x46, 0x0e, 0xa1, 0x79, 0x83, 0xb7, 0x46, 0xbd,
	0x57, 0xb7, 0x34, 0x27, 0xfb, 0x24, 0x47, 0xb0, 0x33, 0x67, 0xb3, 0x14, 0x8d, 0x46, 0x8e, 0x49,
	0x81, 0x5e, 0xc1, 0xe1, 0x25, 0xe7, 0xdf, 0xf2, 0x20, 0x0e, 0xfe, 0x4a, 0x31, 0x11, 0xe4, 0x00,
	0x1a, 0x1e, 0x2f, 0x5c, 0x1b, 0x1e, 0x27, 0x6f, 0xa1, 0x9d, 0xe0, 0x0c, 0x5d, 0x11, 0xc6, 0xb9,
	0xb3, 0x6e, 0xbf, 0x3a, 0x57, 0xd5, 0xf5, 0x2e, 0x0c, 0x04, 0xf3, 0x02, 0x8c, 0x47, 0x85, 0xb5,
	0x53, 0xf9, 0xd1, 0x33, 0x38, 0x72, 0xd0, 0x0f, 0xe7, 0x58, 0xa6, 0x4a, 0xa2, 0x30, 0x48, 0x30,
	0xab, 0x8a, 0xe3, 0x24, 0x9d, 0x16, 0xe9, 0xa4, 0x40, 0xfb, 0xd0, 0xfd, 0x9a, 0x62, 0x7c, 0xbb,
	0x66, 0x6c, 0x42, 0x3b, 0x2e, 0xbe, 0x0b, 0xfb, 0x4a, 0xce, 0x12, 0x5c, 0x72, 0x5e, 0x95, 0x70,
	0x4f, 0x82, 0x0b, 0x78, 0x22, 0xcb, 0x79, 0xa8, 0xc3, 0xef, 0x3a, 0x3c, 0xbe, 0xd3, 0x1f, 0x39,
	0x01, 0x2d, 0x60, 0x3e, 0x26, 0x11, 0x73, 0xcb, 0x8a, 0x16, 0x00, 0x31, 0x60, 0x2f, 0x0a, 0x79,
	0x26, 0x17, 0x9c, 0x97, 0x22, 0xb1, 0x61, 0x77, 0x96, 0x8d, 0x29, 0x31, 0x9a, 0xbd, 0xa6, 0xa5,
	0xdb, 0xa6, 0x92, 0xcf, 0x7c, 0x92, 0x4e, 0x61, 0x49, 0x4e, 0xe1, 0xc0, 0x2d, 0x0b, 0x18, 0xe7,
	0x41, 0x5b, 0x79, 0xd0, 0xfd, 0x0a, 0xfd, 0xc4, 0x7c, 0xa4, 0x26, 0xb4, 0x25, 0x6b, 0xc3, 0xc1,
	0xfa, 0x20, 0xe9, 0xdf, 0x06, 0x74, 0xab, 0x26, 0x06, 0x78, 0xe5, 0x05, 0x9e, 0xf0, 0xc2, 0x80,
	0xbc, 0x80, 0xce, 0x22, 0x74, 0xe5, 0xa1, 0x57, 0xd8, 0x90, 0x93, 0xe7, 0xa0, 0xbb, 0xd3, 0x38,
	0x4c, 0xa3, 0x71, 0xc4, 0xc4, 0x75, 0xd1, 0x0f, 0x48, 0xe8, 0x0b, 0x13, 0xd7, 0xe4, 0x29, 0x68,
	0x85, 0x81, 0xc7, 0x8d, 0x66, 0xaf, 0x6e, 0xb5, 0x9c, 0xb6, 0x04, 0x86, 0x3c, 0xe3, 0xd4, 0x0f,
	0x44, 0x90, 0xe4, 0x25, 0xb7, 0x1c, 0x29, 0xac, 0xb2, 0xb7, 0xb3, 0x85, 0xbd, 0xdd, 0x55, 0xf6,
	0xee, 0x32, 0xb1, 0xa7, 0x60, 0x62, 0x89, 0xe4, 0xf6, 0x83, 0x49, 0x5e, 0x74, 0x31, 0xef, 0x1b,
	0x9a, 0x5c, 0x31, 0x09, 0x7c, 0xef, 0x2f, 0x2b, 0x6d, 0x03, 0x56, 0x94, 0x36, 0x79, 0x09, 0xfb,
	0x7e, 0x98, 0x06, 0x62, 0x9c, 0x84, 0x69, 0xec, 0x62, 0x62, 0xe8, 0xbd, 0xa6, 0xa5, 0x39, 0x9d,
	0x1c, 0x1c, 0x49, 0x8c, 0x12, 0x38, 0x1c, 0xa4, 0x7e, 0x34, 0x12, 0x4c, 0x60, 0x71, 0x6d, 0xf4,
	0x04, 0x5a, 0x19, 0x96, 0x71, 0x94, 0x64, 0x78, 0xb9, 0x77, 0xb9, 0x60, 0xff, 0x69, 0x41, 0xf7,
	0x7d, 0x5e, 0xb6, 0x9c, 0xea, 0x47, 0x59, 0x36, 0x19, 0x81, 0x56, 0xdd, 0x2d, 0x39, 0x55, 0x76,
	0xb6, 0x7e, 0xd7, 0xe6, 0x33, 0xa5, 0x59, 0xb9, 0x2d, 0xb4, 0x46, 0x7e, 0x42, 0x67, 0xf9, 0x48,
	0xc9, 0x76, 0x07, 0xf3, 0xb5, 0x52, 0xad, 0x3a, 0x73, 0x5a, 0x23, 0x3f, 0x40, 0x5f, 0x3a, 0xe9,
	0xfb, 0x42, 0x5b, 0x4a, 0xb5, 0xe2, 0x4d, 0xa0, 0x35, 0x82, 0xd0, 0x59, 0xbe, 0x7c, 0x62, 0x6d,
	0x7f, 0x9c, 0x16, 0x7b, 0xbf, 0xa1, 0x01, 0xd5, 0x33, 0x42, 0x6b, 0xe4, 0x06, 0x1e, 0xad, 0x3d,
	0x19, 0xff, 0x91, 0xe9, 0x6c, 0x0b, 0x55, 0xaa, 0x64, 0x9f, 0x41, 0xab, 0x16, 0x65, 0xc3, 0x78,
	0xd7, 0x17, 0xc9, 0x3c, 0xde, 0x68, 0x46, 0x6b, 0x93, 0xdd, 0xfc, 0xa7, 0xf1, 0xe6, 0x5f, 0x00,
	0x00, 0x00, 0xff, 0xff, 0xb4, 0xaf, 0x5a, 0x65, 0x51, 0x06, 0x00, 0x00,
}
