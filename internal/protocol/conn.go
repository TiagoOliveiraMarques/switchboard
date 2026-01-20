package protocol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const defaultMaxFramePayload = 16 << 20 // 16 MiB

type Option func(*Conn)

func WithMaxFramePayloadBytes(n int) Option {
	return func(c *Conn) {
		if n > 0 {
			c.maxFramePayload = n
		}
	}
}

// Conn wraps a net.Conn and provides tunnel protocol send/receive.
//
// Conn is safe for one concurrent reader and one concurrent writer.
type Conn struct {
	nc net.Conn

	maxFramePayload int

	readMu  sync.Mutex
	writeMu sync.Mutex
}

func New(nc net.Conn, opts ...Option) *Conn {
	c := &Conn{
		nc:              nc,
		maxFramePayload: defaultMaxFramePayload,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Conn) Close() error { return c.nc.Close() }

func (c *Conn) Send(ctx context.Context, msg Message) error {
	if ctx == nil {
		ctx = context.Background()
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	restore, stop := c.applyWriteContext(ctx)
	defer func() {
		stop()
		restore()
	}()

	switch msg.Type {
	case TypePing, TypePong:
		if msg.StreamID != 0 {
			return errors.Join(ErrProtocol, ErrInvalidStreamID)
		}
		if len(msg.Payload) != 0 || len(msg.Data) != 0 {
			return fmt.Errorf("%w: ping/pong payload must be empty", ErrProtocol)
		}
		return encodeFrameTo(c.nc, msg.Type, startEndFlags, 0, nil)

	case TypeAuthBegin, TypeAuthChallenge, TypeAuthProof, TypeAuthOK, TypeAuthError:
		if msg.StreamID != 0 {
			return errors.Join(ErrProtocol, ErrInvalidStreamID)
		}
		return c.sendWithFragmentation(msg.Type, 0, msg.Payload)

	case TypeMessagePayload:
		if msg.StreamID == 0 {
			return errors.Join(ErrProtocol, ErrInvalidStreamID)
		}
		format := msg.Format
		if format == 0 {
			format = PayloadFormatOpaqueBytes
		}
		if format != PayloadFormatOpaqueBytes {
			return fmt.Errorf("%w: unsupported payload format %d", ErrProtocol, format)
		}
		if msg.Kind != PayloadKindRequest && msg.Kind != PayloadKindResponse && msg.Kind != PayloadKindOneway {
			return fmt.Errorf("%w: unsupported payload kind %d", ErrProtocol, msg.Kind)
		}

		// First fragment carries envelope + first chunk of Data.
		envelope := []byte{byte(msg.Kind), byte(format), 0x00, 0x00}

		if len(envelope) > c.maxFramePayload {
			return fmt.Errorf("%w: maxFramePayload too small for envelope", ErrProtocol)
		}

		// How much data can we pack into the first frame?
		firstDataCap := c.maxFramePayload - len(envelope)
		firstData := msg.Data
		if len(firstData) > firstDataCap {
			firstData = firstData[:firstDataCap]
		}
		firstPayload := append(envelope, firstData...)

		remaining := msg.Data[len(firstData):]
		if len(remaining) == 0 {
			return encodeFrameTo(c.nc, TypeMessagePayload, startEndFlags, msg.StreamID, firstPayload)
		}

		// Fragmented: first START (no END), then middle, then END.
		if err := encodeFrameTo(c.nc, TypeMessagePayload, flagStart, msg.StreamID, firstPayload); err != nil {
			return err
		}
		for len(remaining) > 0 {
			chunk := remaining
			if len(chunk) > c.maxFramePayload {
				chunk = chunk[:c.maxFramePayload]
			}
			remaining = remaining[len(chunk):]

			flags := uint16(0)
			if len(remaining) == 0 {
				flags = flagEnd
			}
			if err := encodeFrameTo(c.nc, TypeMessagePayload, flags, msg.StreamID, chunk); err != nil {
				return err
			}
		}
		return nil

	default:
		return errors.Join(ErrProtocol, ErrUnknownType)
	}
}

func (c *Conn) sendWithFragmentation(typ Type, streamID uint64, payload []byte) error {
	if len(payload) <= c.maxFramePayload {
		return encodeFrameTo(c.nc, typ, startEndFlags, streamID, payload)
	}

	remaining := payload
	first := true
	for len(remaining) > 0 {
		chunk := remaining
		if len(chunk) > c.maxFramePayload {
			chunk = chunk[:c.maxFramePayload]
		}
		remaining = remaining[len(chunk):]

		flags := uint16(0)
		if first {
			flags |= flagStart
			first = false
		}
		if len(remaining) == 0 {
			flags |= flagEnd
		}

		if err := encodeFrameTo(c.nc, typ, flags, streamID, chunk); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) ReadNext(ctx context.Context) (Message, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	restore, stop := c.applyReadContext(ctx)
	defer func() {
		stop()
		restore()
	}()

	fr, err := c.readFrame(ctx)
	if err != nil {
		return Message{}, err
	}

	if fr.flags&flagStart == 0 {
		_ = c.nc.Close()
		return Message{}, errors.Join(ErrProtocol, ErrFragmentation)
	}

	typ := fr.typ
	streamID := fr.streamID

	// Type-specific base validation.
	switch typ {
	case TypePing, TypePong:
		if streamID != 0 || len(fr.payload) != 0 || fr.flags != startEndFlags {
			_ = c.nc.Close()
			return Message{}, fmt.Errorf("%w: ping/pong must have stream_id=0, empty payload, START|END", ErrProtocol)
		}
		return Message{Type: typ, StreamID: 0}, nil
	case TypeAuthBegin, TypeAuthChallenge, TypeAuthProof, TypeAuthOK, TypeAuthError:
		if streamID != 0 {
			_ = c.nc.Close()
			return Message{}, errors.Join(ErrProtocol, ErrInvalidStreamID)
		}
	case TypeMessagePayload:
		if streamID == 0 {
			_ = c.nc.Close()
			return Message{}, errors.Join(ErrProtocol, ErrInvalidStreamID)
		}
	}

	isDone := fr.flags&flagEnd != 0

	if typ == TypeMessagePayload {
		if len(fr.payload) < 4 {
			_ = c.nc.Close()
			return Message{}, errors.Join(ErrProtocol, ErrEnvelope)
		}
		kind := PayloadKind(fr.payload[0])
		format := PayloadFormat(fr.payload[1])
		reserved := uint16(fr.payload[2])<<8 | uint16(fr.payload[3])
		if reserved != 0 {
			_ = c.nc.Close()
			return Message{}, errors.Join(ErrProtocol, ErrEnvelope)
		}
		if format != PayloadFormatOpaqueBytes {
			_ = c.nc.Close()
			return Message{}, errors.Join(ErrProtocol, ErrEnvelope)
		}
		if kind != PayloadKindRequest && kind != PayloadKindResponse && kind != PayloadKindOneway {
			_ = c.nc.Close()
			return Message{}, errors.Join(ErrProtocol, ErrEnvelope)
		}

		var data bytes.Buffer
		if len(fr.payload) > 4 {
			_, _ = data.Write(fr.payload[4:])
		}

		for !isDone {
			next, err := c.readFrame(ctx)
			if err != nil {
				return Message{}, err
			}
			if next.typ != typ || next.streamID != streamID {
				_ = c.nc.Close()
				return Message{}, errors.Join(ErrProtocol, ErrFragmentation)
			}
			if next.flags&flagStart != 0 {
				_ = c.nc.Close()
				return Message{}, errors.Join(ErrProtocol, ErrFragmentation)
			}
			if next.flags != 0 && next.flags != flagEnd {
				_ = c.nc.Close()
				return Message{}, errors.Join(ErrProtocol, ErrFragmentation)
			}

			_, _ = data.Write(next.payload)
			isDone = next.flags&flagEnd != 0
		}

		return Message{
			Type:     TypeMessagePayload,
			StreamID: streamID,
			Kind:     kind,
			Format:   format,
			Data:     data.Bytes(),
		}, nil
	}

	// Generic reassembly (concatenate payload fragments).
	var payload bytes.Buffer
	if len(fr.payload) > 0 {
		_, _ = payload.Write(fr.payload)
	}

	for !isDone {
		next, err := c.readFrame(ctx)
		if err != nil {
			return Message{}, err
		}
		if next.typ != typ || next.streamID != streamID {
			_ = c.nc.Close()
			return Message{}, errors.Join(ErrProtocol, ErrFragmentation)
		}
		if next.flags&flagStart != 0 {
			_ = c.nc.Close()
			return Message{}, errors.Join(ErrProtocol, ErrFragmentation)
		}
		if next.flags != 0 && next.flags != flagEnd {
			_ = c.nc.Close()
			return Message{}, errors.Join(ErrProtocol, ErrFragmentation)
		}

		if len(next.payload) > 0 {
			_, _ = payload.Write(next.payload)
		}
		isDone = next.flags&flagEnd != 0
	}

	return Message{
		Type:     typ,
		StreamID: streamID,
		Payload:  payload.Bytes(),
	}, nil
}

func (c *Conn) readFrame(ctx context.Context) (frame, error) {
	fr, err := decodeFrameFrom(c.nc, c.maxFramePayload)
	if err == nil {
		return fr, nil
	}

	// If context was cancelled, prefer ctx.Err().
	select {
	case <-ctx.Done():
		return frame{}, ctx.Err()
	default:
	}

	// On protocol errors, close connection best-effort.
	if isProtocolErr(err) {
		_ = c.nc.Close()
	}
	return frame{}, err
}

func isProtocolErr(err error) bool {
	return err != nil && (errors.Is(err, ErrProtocol) ||
		errors.Is(err, ErrBadMagic) ||
		errors.Is(err, ErrBadVersion) ||
		errors.Is(err, ErrFrameTooLarge) ||
		errors.Is(err, ErrUnknownType) ||
		errors.Is(err, ErrInvalidFlags) ||
		errors.Is(err, ErrFragmentation) ||
		errors.Is(err, ErrEnvelope) ||
		errors.Is(err, ErrInvalidStreamID))
}

func (c *Conn) applyReadContext(ctx context.Context) (restore func(), stop func() bool) {
	var (
		restoreDeadline             = func() { _ = c.nc.SetReadDeadline(time.Time{}) }
		stopAfter       func() bool = func() bool { return true }
	)

	if d, ok := ctx.Deadline(); ok {
		_ = c.nc.SetReadDeadline(d)
	}
	stopAfter = context.AfterFunc(ctx, func() { _ = c.nc.SetReadDeadline(time.Now()) })
	return restoreDeadline, stopAfter
}

func (c *Conn) applyWriteContext(ctx context.Context) (restore func(), stop func() bool) {
	var (
		restoreDeadline             = func() { _ = c.nc.SetWriteDeadline(time.Time{}) }
		stopAfter       func() bool = func() bool { return true }
	)

	if d, ok := ctx.Deadline(); ok {
		_ = c.nc.SetWriteDeadline(d)
	}
	stopAfter = context.AfterFunc(ctx, func() { _ = c.nc.SetWriteDeadline(time.Now()) })
	return restoreDeadline, stopAfter
}
