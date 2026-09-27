package scanapi

import (
	"context"
	"crypto/subtle"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// authHeader 是承载凭据的 metadata key。
// 协议文档 §7.3：`authorization: Bearer <token|node_secret>`。
const authHeader = "authorization"

// bearerPrefix 是凭据前缀（大小写不敏感）。
const bearerPrefix = "bearer "

// UnaryAuth 校验一元调用的凭据。
func UnaryAuth(token string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := checkToken(ctx, token); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamAuth 校验流式调用的凭据（StreamEvents 走这条）。
func StreamAuth(token string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := checkToken(ss.Context(), token); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// checkToken 用常量时间比较校验凭据，避免侧信道。
func checkToken(ctx context.Context, want string) error {
	got := bearerToken(ctx)
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return status.Error(codes.Unauthenticated, "invalid or missing credentials")
	}
	return nil
}

// bearerToken 从入参 metadata 里取出 Bearer 后面的凭据。
func bearerToken(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	values := md.Get(authHeader)
	if len(values) == 0 {
		return ""
	}
	raw := strings.TrimSpace(values[0])
	if len(raw) <= len(bearerPrefix) || !strings.EqualFold(raw[:len(bearerPrefix)], bearerPrefix) {
		return ""
	}
	return strings.TrimSpace(raw[len(bearerPrefix):])
}

// WithToken 把凭据放进出参 metadata，供客户端与测试使用。
func WithToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, authHeader, "Bearer "+token)
}
