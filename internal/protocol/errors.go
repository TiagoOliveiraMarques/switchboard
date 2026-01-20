package protocol

import "errors"

var (
	// ErrProtocol is a generic sentinel for protocol violations.
	ErrProtocol = errors.New("tunnel protocol error")

	ErrBadMagic        = errors.New("bad magic")
	ErrBadVersion      = errors.New("unsupported version")
	ErrFrameTooLarge   = errors.New("frame payload too large")
	ErrUnknownType     = errors.New("unknown frame type")
	ErrInvalidFlags    = errors.New("invalid flags")
	ErrFragmentation   = errors.New("fragmentation error")
	ErrEnvelope        = errors.New("message_payload envelope error")
	ErrInvalidStreamID = errors.New("invalid stream id")
)

