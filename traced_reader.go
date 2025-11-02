package ohttp

import (
	"context"
	"errors"
	"io"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// tracedReader starts a span from the first read to a read encountering a non-nil error.
type tracedReader struct {
	traceCtx context.Context
	name     string
	span     trace.Span
	tracer   trace.Tracer

	reads     int
	totalData int64
	ended     bool
	r         io.Reader
}

func newTracedReader(ctx context.Context, tracer trace.Tracer, r io.Reader, name string) *tracedReader {
	return &tracedReader{
		traceCtx: ctx,
		name:     name,
		span:     nil,
		tracer:   tracer,

		reads: 0,
		ended: false,
		r:     r,
	}
}

func (r *tracedReader) Read(p []byte) (int, error) {
	if r.reads == 0 && !r.ended {
		_, span := r.tracer.Start(r.traceCtx, r.name)
		r.span = span
	}

	n, err := r.r.Read(p)
	if !r.ended {
		r.reads++
		r.totalData += int64(n)

		if err != nil {
			// end span at the first error
			r.span.SetAttributes(
				attribute.Int("reads", r.reads),
				attribute.Int64("bytes_read", r.totalData),
			)
			r.ended = true
			if errors.Is(err, io.EOF) {
				r.span.SetStatus(codes.Ok, "")
			} else {
				r.span.SetStatus(codes.Ok, err.Error())
			}
			r.span.End()
		}
	}

	return n, err
}

func (r *tracedReader) Close() error {
	closer, ok := r.r.(io.Closer)
	if ok {
		return closer.Close()
	}
	return nil
}
