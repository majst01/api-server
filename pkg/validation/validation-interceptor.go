package validation

import (
	"context"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
)

type interceptor struct {
	log *slog.Logger
}

type validate interface {
	Validate() error
}
type validateall interface {
	ValidateAll() error
}

func NewInterceptor(log *slog.Logger) *interceptor {
	return &interceptor{
		log: log,
	}
}

// UnaryInterceptor will check if the request contains a Msg with a Validate || ValidateAll func
// and calls this, if errors occur return them.
func (i *interceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		rq := req.Any()
		switch msg := rq.(type) {
		case validateall:
			err := msg.ValidateAll()
			i.log.Debug("validating all request", "method", req.Spec().Procedure)
			if err != nil {
				i.log.Error("unary validation of request failed", "error", err)
				return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("request validation failed %w", err))
			}
			return next(ctx, req)
		case validate:
			i.log.Debug("validating request", "method", req.Spec().Procedure)
			err := msg.Validate()
			if err != nil {
				i.log.Error("unary validation of request failed", "error", err)
				return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("request validation failed %w", err))
			}
			return next(ctx, req)
		default:
			return next(ctx, req)
		}
	})
}

func (i *interceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return connect.StreamingClientFunc(func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		return next(ctx, spec)
	})
}
func (i *interceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return connect.StreamingHandlerFunc(func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		return next(ctx, conn)
	})
}
