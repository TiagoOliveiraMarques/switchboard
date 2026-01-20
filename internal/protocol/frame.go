package protocol

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	v1Magic0 byte = 0x53 // 'S'
	v1Magic1 byte = 0x42 // 'B'
	v1Version     = 0x01

	headerLen = 18
)

type frame struct {
	typ       Type
	flags     uint16
	streamID  uint64
	payload   []byte
	payloadLn uint32
}

func isKnownType(t Type) bool {
	switch t {
	case TypeAuthBegin, TypeAuthChallenge, TypeAuthProof, TypeAuthOK, TypeAuthError,
		TypeMessagePayload,
		TypePing, TypePong:
		return true
	default:
		return false
	}
}

func encodeFrameTo(w io.Writer, typ Type, flags uint16, streamID uint64, payload []byte) error {
	var hdr [headerLen]byte

	hdr[0] = v1Magic0
	hdr[1] = v1Magic1
	hdr[2] = v1Version
	hdr[3] = byte(typ)
	binary.BigEndian.PutUint16(hdr[4:6], flags)
	binary.BigEndian.PutUint64(hdr[6:14], streamID)
	binary.BigEndian.PutUint32(hdr[14:18], uint32(len(payload)))

	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

func decodeFrameFrom(r io.Reader, maxPayload int) (frame, error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return frame{}, err
	}

	if hdr[0] != v1Magic0 || hdr[1] != v1Magic1 {
		return frame{}, errors.Join(ErrProtocol, ErrBadMagic)
	}
	if hdr[2] != v1Version {
		return frame{}, errors.Join(ErrProtocol, ErrBadVersion)
	}

	typ := Type(hdr[3])
	if !isKnownType(typ) {
		return frame{}, errors.Join(ErrProtocol, ErrUnknownType)
	}

	flags := binary.BigEndian.Uint16(hdr[4:6])
	if flags&^(flagStart|flagEnd) != 0 {
		return frame{}, errors.Join(ErrProtocol, ErrInvalidFlags)
	}

	streamID := binary.BigEndian.Uint64(hdr[6:14])
	payloadLn := binary.BigEndian.Uint32(hdr[14:18])
	if payloadLn > uint32(maxPayload) {
		return frame{}, errors.Join(ErrProtocol, ErrFrameTooLarge)
	}

	var payload []byte
	if payloadLn > 0 {
		payload = make([]byte, payloadLn)
		if _, err := io.ReadFull(r, payload); err != nil {
			return frame{}, err
		}
	}

	return frame{
		typ:       typ,
		flags:     flags,
		streamID:  streamID,
		payload:   payload,
		payloadLn: payloadLn,
	}, nil
}

