package protocol

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestPingRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ca := New(a)
	cb := New(b)

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := ca.Send(context.Background(), Message{Type: TypePing}); err != nil {
			t.Errorf("Send ping: %v", err)
			return
		}
	}()

	msg, err := cb.ReadNext(context.Background())
	<-done
	if err != nil {
		t.Fatalf("ReadNext: %v", err)
	}
	if msg.Type != TypePing || msg.StreamID != 0 {
		t.Fatalf("unexpected msg: %#v", msg)
	}
}

func TestAuthFrameRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ca := New(a)
	cb := New(b)

	payload := []byte(`{"type":"auth_begin","v":1,"agent_id":"abc"}`)

	go func() {
		_ = ca.Send(context.Background(), Message{
			Type:    TypeAuthBegin,
			Payload: payload,
		})
	}()

	msg, err := cb.ReadNext(context.Background())
	if err != nil {
		t.Fatalf("ReadNext: %v", err)
	}
	if msg.Type != TypeAuthBegin {
		t.Fatalf("type: got %v", msg.Type)
	}
	if msg.StreamID != 0 {
		t.Fatalf("stream id: got %d", msg.StreamID)
	}
	if string(msg.Payload) != string(payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestMessagePayloadRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	ca := New(a)
	cb := New(b)

	want := []byte("hello world")

	go func() {
		_ = ca.Send(context.Background(), Message{
			Type:     TypeMessagePayload,
			StreamID: 123,
			Kind:     PayloadKindRequest,
			Format:   PayloadFormatOpaqueBytes,
			Data:     want,
		})
	}()

	msg, err := cb.ReadNext(context.Background())
	if err != nil {
		t.Fatalf("ReadNext: %v", err)
	}
	if msg.Type != TypeMessagePayload {
		t.Fatalf("type: got %v", msg.Type)
	}
	if msg.StreamID != 123 {
		t.Fatalf("stream id: got %d", msg.StreamID)
	}
	if msg.Kind != PayloadKindRequest || msg.Format != PayloadFormatOpaqueBytes {
		t.Fatalf("envelope: got kind=%d format=%d", msg.Kind, msg.Format)
	}
	if string(msg.Data) != string(want) {
		t.Fatalf("data mismatch: got %q want %q", string(msg.Data), string(want))
	}
}

func TestMessagePayloadFragmentation(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	// Force fragmentation: max frame payload is small.
	ca := New(a, WithMaxFramePayloadBytes(16))
	cb := New(b, WithMaxFramePayloadBytes(16))

	want := make([]byte, 100)
	for i := range want {
		want[i] = byte(i)
	}

	go func() {
		_ = ca.Send(context.Background(), Message{
			Type:     TypeMessagePayload,
			StreamID: 999,
			Kind:     PayloadKindResponse,
			Data:     want,
		})
	}()

	msg, err := cb.ReadNext(context.Background())
	if err != nil {
		t.Fatalf("ReadNext: %v", err)
	}
	if msg.Type != TypeMessagePayload || msg.StreamID != 999 || msg.Kind != PayloadKindResponse {
		t.Fatalf("unexpected msg: %#v", msg)
	}
	if len(msg.Data) != len(want) {
		t.Fatalf("data length: got %d want %d", len(msg.Data), len(want))
	}
	for i := range want {
		if msg.Data[i] != want[i] {
			t.Fatalf("data mismatch at %d", i)
		}
	}
}

func TestUnknownTypeCloses(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	cb := New(b)

	// Write raw frame with unknown type.
	go func() {
		_ = encodeFrameTo(a, Type(0x99), startEndFlags, 0, nil)
	}()

	_, err := cb.ReadNext(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, ErrUnknownType) && !errors.Is(err, ErrProtocol) {
		t.Fatalf("expected unknown/protocol error, got: %v", err)
	}
}

func TestContextCancelUnblocksRead(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	cb := New(b)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := cb.ReadNext(ctx)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("ReadNext took too long after cancel")
	}
}
