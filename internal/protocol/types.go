package protocol

// Type is the tunnel frame type ID.
//
// See docs/architecture/tunnel-protocol.md.
type Type byte

const (
	TypeAuthBegin     Type = 0x01
	TypeAuthChallenge Type = 0x02
	TypeAuthProof     Type = 0x03
	TypeAuthOK        Type = 0x04
	TypeAuthError     Type = 0x05

	TypeMessagePayload Type = 0x10

	TypePing Type = 0xFE
	TypePong Type = 0xFF
)

// PayloadKind is the first byte of the message_payload envelope.
type PayloadKind byte

const (
	PayloadKindRequest  PayloadKind = 0x01
	PayloadKindResponse PayloadKind = 0x02
	PayloadKindOneway   PayloadKind = 0x03
)

// PayloadFormat is the second byte of the message_payload envelope.
type PayloadFormat byte

const (
	// PayloadFormatOpaqueBytes corresponds to Format=0x00 in v1.
	PayloadFormatOpaqueBytes PayloadFormat = 0x00
)

const (
	flagStart uint16 = 0x0001
	flagEnd   uint16 = 0x0002

	startEndFlags uint16 = flagStart | flagEnd
)

// Message represents one logical tunnel message (reassembled if fragmented).
//
// For TypeMessagePayload, Data/Kind/Format are used and Payload is empty.
// For other types, Payload contains the full logical payload and Data is empty.
type Message struct {
	Type     Type
	StreamID uint64

	// Payload is the logical payload for non-message_payload types.
	Payload []byte

	// Kind/Format/Data apply to TypeMessagePayload only.
	Kind   PayloadKind
	Format PayloadFormat
	Data   []byte
}

