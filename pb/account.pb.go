// Code generated by protoc-gen-go.
// source: account.proto
// DO NOT EDIT!

/*
Package pb is a generated protocol buffer package.

It is generated from these files:
	account.proto

It has these top-level messages:
	Session
	CreateSessionRequest
	CreateSessionReply
	FindSessionByTokenRequest
	FindSessionByTokenReply
	DeleteSessionByTokenRequest
	DeleteSessionByTokenReply
	DeleteSessionsByOwnerTokenRequest
	DeleteSessionsByOwnerTokenReply
*/
package pb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import google_protobuf "github.com/golang/protobuf/ptypes/timestamp"

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

type Session struct {
	Created    *google_protobuf.Timestamp `protobuf:"bytes,1,opt,name=created" json:"created,omitempty"`
	ValidTo    *google_protobuf.Timestamp `protobuf:"bytes,2,opt,name=valid_to,json=validTo" json:"valid_to,omitempty"`
	Token      string                     `protobuf:"bytes,3,opt,name=token" json:"token,omitempty"`
	OwnerToken string                     `protobuf:"bytes,4,opt,name=owner_token,json=ownerToken" json:"owner_token,omitempty"`
	Agent      string                     `protobuf:"bytes,5,opt,name=agent" json:"agent,omitempty"`
	Ip         string                     `protobuf:"bytes,6,opt,name=ip" json:"ip,omitempty"`
	Policies   []string                   `protobuf:"bytes,7,rep,name=policies" json:"policies,omitempty"`
	Payload    []byte                     `protobuf:"bytes,8,opt,name=payload,proto3" json:"payload,omitempty"`
}

func (m *Session) Reset()                    { *m = Session{} }
func (m *Session) String() string            { return proto.CompactTextString(m) }
func (*Session) ProtoMessage()               {}
func (*Session) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Session) GetCreated() *google_protobuf.Timestamp {
	if m != nil {
		return m.Created
	}
	return nil
}

func (m *Session) GetValidTo() *google_protobuf.Timestamp {
	if m != nil {
		return m.ValidTo
	}
	return nil
}

type CreateSessionRequest struct {
	Session *Session `protobuf:"bytes,1,opt,name=session" json:"session,omitempty"`
}

func (m *CreateSessionRequest) Reset()                    { *m = CreateSessionRequest{} }
func (m *CreateSessionRequest) String() string            { return proto.CompactTextString(m) }
func (*CreateSessionRequest) ProtoMessage()               {}
func (*CreateSessionRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *CreateSessionRequest) GetSession() *Session {
	if m != nil {
		return m.Session
	}
	return nil
}

type CreateSessionReply struct {
	Session *Session `protobuf:"bytes,1,opt,name=session" json:"session,omitempty"`
	Err     string   `protobuf:"bytes,2,opt,name=err" json:"err,omitempty"`
}

func (m *CreateSessionReply) Reset()                    { *m = CreateSessionReply{} }
func (m *CreateSessionReply) String() string            { return proto.CompactTextString(m) }
func (*CreateSessionReply) ProtoMessage()               {}
func (*CreateSessionReply) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *CreateSessionReply) GetSession() *Session {
	if m != nil {
		return m.Session
	}
	return nil
}

type FindSessionByTokenRequest struct {
	Token string `protobuf:"bytes,1,opt,name=token" json:"token,omitempty"`
}

func (m *FindSessionByTokenRequest) Reset()                    { *m = FindSessionByTokenRequest{} }
func (m *FindSessionByTokenRequest) String() string            { return proto.CompactTextString(m) }
func (*FindSessionByTokenRequest) ProtoMessage()               {}
func (*FindSessionByTokenRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

type FindSessionByTokenReply struct {
	Session *Session `protobuf:"bytes,1,opt,name=session" json:"session,omitempty"`
	Err     string   `protobuf:"bytes,2,opt,name=err" json:"err,omitempty"`
}

func (m *FindSessionByTokenReply) Reset()                    { *m = FindSessionByTokenReply{} }
func (m *FindSessionByTokenReply) String() string            { return proto.CompactTextString(m) }
func (*FindSessionByTokenReply) ProtoMessage()               {}
func (*FindSessionByTokenReply) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *FindSessionByTokenReply) GetSession() *Session {
	if m != nil {
		return m.Session
	}
	return nil
}

type DeleteSessionByTokenRequest struct {
	Token string `protobuf:"bytes,1,opt,name=token" json:"token,omitempty"`
}

func (m *DeleteSessionByTokenRequest) Reset()                    { *m = DeleteSessionByTokenRequest{} }
func (m *DeleteSessionByTokenRequest) String() string            { return proto.CompactTextString(m) }
func (*DeleteSessionByTokenRequest) ProtoMessage()               {}
func (*DeleteSessionByTokenRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

type DeleteSessionByTokenReply struct {
	Session *Session `protobuf:"bytes,1,opt,name=session" json:"session,omitempty"`
	Err     string   `protobuf:"bytes,2,opt,name=err" json:"err,omitempty"`
}

func (m *DeleteSessionByTokenReply) Reset()                    { *m = DeleteSessionByTokenReply{} }
func (m *DeleteSessionByTokenReply) String() string            { return proto.CompactTextString(m) }
func (*DeleteSessionByTokenReply) ProtoMessage()               {}
func (*DeleteSessionByTokenReply) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *DeleteSessionByTokenReply) GetSession() *Session {
	if m != nil {
		return m.Session
	}
	return nil
}

type DeleteSessionsByOwnerTokenRequest struct {
	OwnerToken string `protobuf:"bytes,1,opt,name=owner_token,json=ownerToken" json:"owner_token,omitempty"`
}

func (m *DeleteSessionsByOwnerTokenRequest) Reset()         { *m = DeleteSessionsByOwnerTokenRequest{} }
func (m *DeleteSessionsByOwnerTokenRequest) String() string { return proto.CompactTextString(m) }
func (*DeleteSessionsByOwnerTokenRequest) ProtoMessage()    {}
func (*DeleteSessionsByOwnerTokenRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor0, []int{7}
}

type DeleteSessionsByOwnerTokenReply struct {
	Sessions []*Session `protobuf:"bytes,1,rep,name=sessions" json:"sessions,omitempty"`
	Err      string     `protobuf:"bytes,2,opt,name=err" json:"err,omitempty"`
}

func (m *DeleteSessionsByOwnerTokenReply) Reset()                    { *m = DeleteSessionsByOwnerTokenReply{} }
func (m *DeleteSessionsByOwnerTokenReply) String() string            { return proto.CompactTextString(m) }
func (*DeleteSessionsByOwnerTokenReply) ProtoMessage()               {}
func (*DeleteSessionsByOwnerTokenReply) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{8} }

func (m *DeleteSessionsByOwnerTokenReply) GetSessions() []*Session {
	if m != nil {
		return m.Sessions
	}
	return nil
}

func init() {
	proto.RegisterType((*Session)(nil), "pb.Session")
	proto.RegisterType((*CreateSessionRequest)(nil), "pb.CreateSessionRequest")
	proto.RegisterType((*CreateSessionReply)(nil), "pb.CreateSessionReply")
	proto.RegisterType((*FindSessionByTokenRequest)(nil), "pb.FindSessionByTokenRequest")
	proto.RegisterType((*FindSessionByTokenReply)(nil), "pb.FindSessionByTokenReply")
	proto.RegisterType((*DeleteSessionByTokenRequest)(nil), "pb.DeleteSessionByTokenRequest")
	proto.RegisterType((*DeleteSessionByTokenReply)(nil), "pb.DeleteSessionByTokenReply")
	proto.RegisterType((*DeleteSessionsByOwnerTokenRequest)(nil), "pb.DeleteSessionsByOwnerTokenRequest")
	proto.RegisterType((*DeleteSessionsByOwnerTokenReply)(nil), "pb.DeleteSessionsByOwnerTokenReply")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion3

// Client API for Account service

type AccountClient interface {
	CreateSession(ctx context.Context, in *CreateSessionRequest, opts ...grpc.CallOption) (*CreateSessionReply, error)
	FindSessionByToken(ctx context.Context, in *FindSessionByTokenRequest, opts ...grpc.CallOption) (*FindSessionByTokenReply, error)
	DeleteSessionByToken(ctx context.Context, in *DeleteSessionByTokenRequest, opts ...grpc.CallOption) (*DeleteSessionByTokenReply, error)
	DeleteSessionsByOwnerToken(ctx context.Context, in *DeleteSessionsByOwnerTokenRequest, opts ...grpc.CallOption) (*DeleteSessionsByOwnerTokenReply, error)
}

type accountClient struct {
	cc *grpc.ClientConn
}

func NewAccountClient(cc *grpc.ClientConn) AccountClient {
	return &accountClient{cc}
}

func (c *accountClient) CreateSession(ctx context.Context, in *CreateSessionRequest, opts ...grpc.CallOption) (*CreateSessionReply, error) {
	out := new(CreateSessionReply)
	err := grpc.Invoke(ctx, "/pb.Account/CreateSession", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accountClient) FindSessionByToken(ctx context.Context, in *FindSessionByTokenRequest, opts ...grpc.CallOption) (*FindSessionByTokenReply, error) {
	out := new(FindSessionByTokenReply)
	err := grpc.Invoke(ctx, "/pb.Account/FindSessionByToken", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accountClient) DeleteSessionByToken(ctx context.Context, in *DeleteSessionByTokenRequest, opts ...grpc.CallOption) (*DeleteSessionByTokenReply, error) {
	out := new(DeleteSessionByTokenReply)
	err := grpc.Invoke(ctx, "/pb.Account/DeleteSessionByToken", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *accountClient) DeleteSessionsByOwnerToken(ctx context.Context, in *DeleteSessionsByOwnerTokenRequest, opts ...grpc.CallOption) (*DeleteSessionsByOwnerTokenReply, error) {
	out := new(DeleteSessionsByOwnerTokenReply)
	err := grpc.Invoke(ctx, "/pb.Account/DeleteSessionsByOwnerToken", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Account service

type AccountServer interface {
	CreateSession(context.Context, *CreateSessionRequest) (*CreateSessionReply, error)
	FindSessionByToken(context.Context, *FindSessionByTokenRequest) (*FindSessionByTokenReply, error)
	DeleteSessionByToken(context.Context, *DeleteSessionByTokenRequest) (*DeleteSessionByTokenReply, error)
	DeleteSessionsByOwnerToken(context.Context, *DeleteSessionsByOwnerTokenRequest) (*DeleteSessionsByOwnerTokenReply, error)
}

func RegisterAccountServer(s *grpc.Server, srv AccountServer) {
	s.RegisterService(&_Account_serviceDesc, srv)
}

func _Account_CreateSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateSessionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccountServer).CreateSession(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.Account/CreateSession",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccountServer).CreateSession(ctx, req.(*CreateSessionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Account_FindSessionByToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FindSessionByTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccountServer).FindSessionByToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.Account/FindSessionByToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccountServer).FindSessionByToken(ctx, req.(*FindSessionByTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Account_DeleteSessionByToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteSessionByTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccountServer).DeleteSessionByToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.Account/DeleteSessionByToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccountServer).DeleteSessionByToken(ctx, req.(*DeleteSessionByTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Account_DeleteSessionsByOwnerToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteSessionsByOwnerTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AccountServer).DeleteSessionsByOwnerToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/pb.Account/DeleteSessionsByOwnerToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AccountServer).DeleteSessionsByOwnerToken(ctx, req.(*DeleteSessionsByOwnerTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Account_serviceDesc = grpc.ServiceDesc{
	ServiceName: "pb.Account",
	HandlerType: (*AccountServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateSession",
			Handler:    _Account_CreateSession_Handler,
		},
		{
			MethodName: "FindSessionByToken",
			Handler:    _Account_FindSessionByToken_Handler,
		},
		{
			MethodName: "DeleteSessionByToken",
			Handler:    _Account_DeleteSessionByToken_Handler,
		},
		{
			MethodName: "DeleteSessionsByOwnerToken",
			Handler:    _Account_DeleteSessionsByOwnerToken_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: fileDescriptor0,
}

func init() { proto.RegisterFile("account.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 461 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xa4, 0x54, 0xc1, 0x6e, 0xd3, 0x40,
	0x10, 0xc5, 0x0e, 0xa9, 0x93, 0x09, 0x45, 0x68, 0x14, 0xc1, 0x76, 0xab, 0x2a, 0xc6, 0xa8, 0x22,
	0x27, 0x57, 0xb4, 0x70, 0xe4, 0x40, 0x5b, 0x71, 0x43, 0x48, 0x4b, 0x0e, 0x1c, 0x90, 0x2a, 0x27,
	0x59, 0xa2, 0x05, 0xd7, 0xbb, 0x78, 0x37, 0x20, 0x7f, 0x02, 0x7f, 0xca, 0x67, 0x20, 0xef, 0x66,
	0xad, 0x36, 0x71, 0xda, 0x4a, 0xb9, 0x79, 0x66, 0xde, 0x1b, 0xbf, 0x99, 0x79, 0x36, 0xec, 0x67,
	0xb3, 0x99, 0x5c, 0x16, 0x26, 0x55, 0xa5, 0x34, 0x12, 0x43, 0x35, 0xa5, 0xa3, 0x85, 0x94, 0x8b,
	0x9c, 0x9f, 0xd8, 0xcc, 0x74, 0xf9, 0xfd, 0xc4, 0x88, 0x6b, 0xae, 0x4d, 0x76, 0xad, 0x1c, 0x28,
	0xf9, 0x1b, 0x42, 0xf4, 0x85, 0x6b, 0x2d, 0x64, 0x81, 0x6f, 0x21, 0x9a, 0x95, 0x3c, 0x33, 0x7c,
	0x4e, 0x82, 0x38, 0x18, 0x0f, 0x4e, 0x69, 0xea, 0xe8, 0xa9, 0xa7, 0xa7, 0x13, 0x4f, 0x67, 0x1e,
	0x8a, 0xef, 0xa0, 0xf7, 0x3b, 0xcb, 0xc5, 0xfc, 0xca, 0x48, 0x12, 0xde, 0x4f, 0xb3, 0xd8, 0x89,
	0xc4, 0x21, 0x74, 0x8d, 0xfc, 0xc9, 0x0b, 0xd2, 0x89, 0x83, 0x71, 0x9f, 0xb9, 0x00, 0x47, 0x30,
	0x90, 0x7f, 0x0a, 0x5e, 0x5e, 0xb9, 0xda, 0x63, 0x5b, 0x03, 0x9b, 0x9a, 0x58, 0xc0, 0x10, 0xba,
	0xd9, 0x82, 0x17, 0x86, 0x74, 0x1d, 0xcd, 0x06, 0xf8, 0x14, 0x42, 0xa1, 0xc8, 0x9e, 0x4d, 0x85,
	0x42, 0x21, 0x85, 0x9e, 0x92, 0xb9, 0x98, 0x09, 0xae, 0x49, 0x14, 0x77, 0xc6, 0x7d, 0xd6, 0xc4,
	0x48, 0x20, 0x52, 0x59, 0x95, 0xcb, 0x6c, 0x4e, 0x7a, 0x71, 0x30, 0x7e, 0xc2, 0x7c, 0x98, 0xbc,
	0x87, 0xe1, 0x85, 0x1d, 0x6a, 0xb5, 0x10, 0xc6, 0x7f, 0x2d, 0xb9, 0x36, 0x78, 0x0c, 0x91, 0x76,
	0x99, 0xd5, 0x5e, 0x06, 0xa9, 0x9a, 0xa6, 0x1e, 0xe4, 0x6b, 0xc9, 0x27, 0xc0, 0x35, 0xba, 0xca,
	0xab, 0x07, 0x92, 0xf1, 0x19, 0x74, 0x78, 0x59, 0xda, 0x05, 0xf6, 0x59, 0xfd, 0x98, 0xbc, 0x81,
	0x83, 0x8f, 0xa2, 0x98, 0xaf, 0x90, 0xe7, 0x95, 0x9d, 0xdf, 0x4b, 0x6a, 0xb6, 0x17, 0xdc, 0xd8,
	0x5e, 0xc2, 0xe0, 0x45, 0x1b, 0x65, 0x27, 0x19, 0x67, 0x70, 0x78, 0xc9, 0x73, 0xde, 0x4c, 0xf5,
	0x20, 0x21, 0x13, 0x38, 0x68, 0x27, 0xed, 0x24, 0xe5, 0x12, 0x5e, 0xde, 0xea, 0xaa, 0xcf, 0xab,
	0xcf, 0x8d, 0x33, 0xbc, 0xa0, 0x35, 0x07, 0x05, 0xeb, 0x0e, 0x4a, 0xbe, 0xc1, 0xe8, 0xae, 0x2e,
	0xb5, 0xc2, 0xd7, 0xd0, 0x5b, 0xa9, 0xd0, 0x24, 0x88, 0x3b, 0xeb, 0x12, 0x9b, 0xe2, 0xa6, 0xc6,
	0xd3, 0x7f, 0x21, 0x44, 0x1f, 0xdc, 0x67, 0x88, 0x17, 0xb0, 0x7f, 0xcb, 0x10, 0x48, 0xea, 0x2e,
	0x6d, 0x16, 0xa3, 0xcf, 0x5b, 0x2a, 0x2a, 0xaf, 0x92, 0x47, 0xc8, 0x00, 0x37, 0x6f, 0x8a, 0x47,
	0x35, 0x7e, 0xab, 0x3d, 0xe8, 0xe1, 0xb6, 0xb2, 0xeb, 0xf9, 0x15, 0x86, 0x6d, 0xe7, 0xc1, 0x51,
	0x4d, 0xbb, 0xe3, 0xda, 0xf4, 0x68, 0x3b, 0xc0, 0x75, 0xfe, 0x01, 0x74, 0xfb, 0x72, 0xf1, 0x78,
	0x83, 0xde, 0x76, 0x42, 0xfa, 0xea, 0x3e, 0x98, 0x7d, 0xd7, 0x74, 0xcf, 0xfe, 0x5e, 0xce, 0xfe,
	0x07, 0x00, 0x00, 0xff, 0xff, 0xa1, 0xf3, 0xe5, 0x5d, 0xf7, 0x04, 0x00, 0x00,
}
