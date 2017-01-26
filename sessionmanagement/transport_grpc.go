package sessionmanagement

import (
	"github.com/go-kit/kit/log"
	client "github.com/solher/styx/sessionmanagement/client/grpc"

	grpctransport "github.com/go-kit/kit/transport/grpc"
	"github.com/golang/protobuf/ptypes"
	stdopentracing "github.com/opentracing/opentracing-go"
	"github.com/solher/kitty"
	"github.com/solher/styx/pb"
	"github.com/solher/styx/sessions"
	"golang.org/x/net/context"
)

// MakeGRPCServer makes a set of endpoints available as a gRPC server.
func MakeGRPCServer(ctx context.Context, endpoints Endpoints, tracer stdopentracing.Tracer, logger log.Logger) pb.SessionManagementServer {
	opts := []grpctransport.ServerOption{
		grpctransport.ServerErrorLogger(logger),
	}
	return &grpcServer{
		createSession: grpctransport.NewServer(
			ctx,
			endpoints.CreateSessionEndpoint,
			DecodeGRPCCreateSessionRequest,
			EncodeGRPCCreateSessionResponse,
			append(
				opts,
				grpctransport.ServerBefore(kitty.FromGRPCRequest(tracer, "Create session", logger)),
				grpctransport.ServerAfter(kitty.GRPCFinish()),
			)...,
		),
		findSessionByToken: grpctransport.NewServer(
			ctx,
			endpoints.FindSessionByTokenEndpoint,
			DecodeGRPCFindSessionByTokenRequest,
			EncodeGRPCFindSessionByTokenResponse,
			append(
				opts,
				grpctransport.ServerBefore(kitty.FromGRPCRequest(tracer, "Find session by token", logger)),
				grpctransport.ServerAfter(kitty.GRPCFinish()),
			)...,
		),
		deleteSessionByToken: grpctransport.NewServer(
			ctx,
			endpoints.DeleteSessionByTokenEndpoint,
			DecodeGRPCDeleteSessionByTokenRequest,
			EncodeGRPCDeleteSessionByTokenResponse,
			append(
				opts,
				grpctransport.ServerBefore(kitty.FromGRPCRequest(tracer, "Delete session by token", logger)),
				grpctransport.ServerAfter(kitty.GRPCFinish()),
			)...,
		),
		deleteSessionsByOwnerToken: grpctransport.NewServer(
			ctx,
			endpoints.DeleteSessionsByOwnerTokenEndpoint,
			DecodeGRPCDeleteSessionsByOwnerTokenRequest,
			EncodeGRPCDeleteSessionsByOwnerTokenResponse,
			append(
				opts,
				grpctransport.ServerBefore(kitty.FromGRPCRequest(tracer, "Delete sessions by owner token", logger)),
				grpctransport.ServerAfter(kitty.GRPCFinish()),
			)...,
		),
	}
}

type grpcServer struct {
	createSession              grpctransport.Handler
	findSessionByToken         grpctransport.Handler
	deleteSessionByToken       grpctransport.Handler
	deleteSessionsByOwnerToken grpctransport.Handler
}

func (s *grpcServer) CreateSession(ctx context.Context, req *pb.CreateSessionRequest) (*pb.CreateSessionReply, error) {
	_, rep, err := s.createSession.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep.(*pb.CreateSessionReply), nil
}

func (s *grpcServer) FindSessionByToken(ctx context.Context, req *pb.FindSessionByTokenRequest) (*pb.FindSessionByTokenReply, error) {
	_, rep, err := s.findSessionByToken.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep.(*pb.FindSessionByTokenReply), nil
}

func (s *grpcServer) DeleteSessionByToken(ctx context.Context, req *pb.DeleteSessionByTokenRequest) (*pb.DeleteSessionByTokenReply, error) {
	_, rep, err := s.deleteSessionByToken.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep.(*pb.DeleteSessionByTokenReply), nil
}

func (s *grpcServer) DeleteSessionsByOwnerToken(ctx context.Context, req *pb.DeleteSessionsByOwnerTokenRequest) (*pb.DeleteSessionsByOwnerTokenReply, error) {
	_, rep, err := s.deleteSessionsByOwnerToken.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	return rep.(*pb.DeleteSessionsByOwnerTokenReply), nil
}

// DecodeGRPCCreateSessionRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request.
func DecodeGRPCCreateSessionRequest(_ context.Context, request interface{}) (interface{}, error) {
	req := request.(*pb.CreateSessionRequest)
	return createSessionRequest{
		Session: toSession(req.Session),
	}, nil
}

// EncodeGRPCCreateSessionResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply.
func EncodeGRPCCreateSessionResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(createSessionResponse)
	return &pb.CreateSessionReply{
		Session: toPBSession(res.Session),
		Err:     toPBError(res.Err),
	}, nil
}

// DecodeGRPCFindSessionByTokenRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request.
func DecodeGRPCFindSessionByTokenRequest(_ context.Context, request interface{}) (interface{}, error) {
	req := request.(*pb.FindSessionByTokenRequest)
	return findSessionByTokenRequest{
		Token: req.Token,
	}, nil
}

// EncodeGRPCFindSessionByTokenResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply.
func EncodeGRPCFindSessionByTokenResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(findSessionByTokenResponse)
	return &pb.FindSessionByTokenReply{
		Session: toPBSession(res.Session),
		Err:     toPBError(res.Err),
	}, nil
}

// DecodeGRPCDeleteSessionByTokenRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request.
func DecodeGRPCDeleteSessionByTokenRequest(_ context.Context, request interface{}) (interface{}, error) {
	req := request.(*pb.DeleteSessionByTokenRequest)
	return deleteSessionByTokenRequest{
		Token: req.Token,
	}, nil
}

// EncodeGRPCDeleteSessionByTokenResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply.
func EncodeGRPCDeleteSessionByTokenResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(deleteSessionByTokenResponse)
	return &pb.DeleteSessionByTokenReply{
		Session: toPBSession(res.Session),
		Err:     toPBError(res.Err),
	}, nil
}

// DecodeGRPCDeleteSessionsByOwnerTokenRequest is a transport/grpc.DecodeRequestFunc that converts a
// gRPC request to a user-domain request.
func DecodeGRPCDeleteSessionsByOwnerTokenRequest(_ context.Context, request interface{}) (interface{}, error) {
	req := request.(*pb.DeleteSessionsByOwnerTokenRequest)
	return deleteSessionsByOwnerTokenRequest{
		OwnerToken: req.OwnerToken,
	}, nil
}

// EncodeGRPCDeleteSessionsByOwnerTokenResponse is a transport/grpc.EncodeResponseFunc that converts a
// user-domain response to a gRPC reply.
func EncodeGRPCDeleteSessionsByOwnerTokenResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(deleteSessionsByOwnerTokenResponse)
	return &pb.DeleteSessionsByOwnerTokenReply{
		Sessions: toPBSessions(res.Sessions),
		Err:      toPBError(res.Err),
	}, nil
}

func toPBError(err error) string {
	if err == nil {
		return ""
	}
	if _, _, ok := isErrValidation(err); ok {
		return client.ErrValidation.Error()
	} else if isErrNotFound(err) {
		return client.ErrNotFound.Error()
	}
	return err.Error()
}

func toPBSession(session *sessions.Session) *pb.Session {
	return toPBSessions([]sessions.Session{*session})[0]
}

func toPBSessions(sessions []sessions.Session) []*pb.Session {
	pbSessionSl := make([]*pb.Session, len(sessions))
	for i, n := range sessions {
		created, _ := ptypes.TimestampProto(*n.Created)
		validTo, _ := ptypes.TimestampProto(*n.ValidTo)
		pbSessionSl[i] = &pb.Session{
			Created:    created,
			ValidTo:    validTo,
			Token:      n.Token,
			OwnerToken: n.OwnerToken,
			Agent:      n.Agent,
			Ip:         n.IP,
			Policies:   n.Policies,
		}
	}
	return pbSessionSl
}

func toSession(pbSession *pb.Session) *sessions.Session {
	return &toSessions([]*pb.Session{pbSession})[0]
}

func toSessions(pbSessions []*pb.Session) []sessions.Session {
	sessionSl := make([]sessions.Session, len(pbSessions))
	for i, n := range pbSessions {
		created, _ := ptypes.Timestamp(n.Created)
		validTo, _ := ptypes.Timestamp(n.ValidTo)
		sessionSl[i] = sessions.Session{
			Created:    &created,
			ValidTo:    &validTo,
			Token:      n.Token,
			OwnerToken: n.OwnerToken,
			Agent:      n.Agent,
			IP:         n.Ip,
			Policies:   n.Policies,
		}
	}
	return sessionSl
}
