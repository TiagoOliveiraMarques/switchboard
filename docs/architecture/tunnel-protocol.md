# Tunnel protocol (v1)

## Scope

This document defines the **binary framing protocol** used over the Agent ↔ Proxy tunnel connection.

It defines:

- How messages are framed over an ordered byte stream
- Message type IDs
- Fragmentation rules (for large messages)
- The `message_payload` frame used to carry proxied messages (opaque bytes)

It does **not** define the authentication message fields themselves; those are defined in
`architecture/agent-proxy-authentication.md`. This document only defines how those messages are carried on the wire.

## Assumptions

- The tunnel transport provides an **ordered, reliable byte stream** (e.g., TCP over TLS).
- All multi-byte integers are **unsigned** and encoded as **big-endian** (“network byte order”).

## Connection lifecycle (high-level)

1. Transport connection is established (MUST be TLS).
2. Agent and Proxy exchange authentication frames (see `agent-proxy-authentication.md`), until `auth_ok` or `auth_error`.
3. Once authenticated, either side may send `message_payload` frames.
4. Either side may send keepalive (`ping`/`pong`) frames.

## Frame format (v1)

Every message on the tunnel is a **frame**:

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------------------------------+-------------------------------+
|            Magic "SB"         |   Version    |     Type      |
+-------------------------------+-------------------------------+
|              Flags            |                               |
+-------------------------------+          Stream ID            |
|                                                               |
+-------------------------------+-------------------------------+
|                         Payload Length                        |
+-------------------------------+-------------------------------+
|                                                               |
|                            Payload                            |
|                                                               |
+-------------------------------+-------------------------------+
```

### Header fields

- **Magic** (2 bytes): ASCII `S` `B` (`0x53 0x42`)
- **Version** (1 byte): `0x01`
- **Type** (1 byte): message type ID (see below)
- **Flags** (2 bytes): bitflags (see below)
- **Stream ID** (8 bytes): unsigned 64-bit identifier used to correlate multi-frame messages
  - For auth and keepalive frames, MUST be `0`.
  - For `message_payload`, MUST be non-zero and is the **message ID** used for correlating request ↔ response.
- **Payload Length** (4 bytes): number of payload bytes that follow (0 is allowed)

### Limits

- Implementations MUST reject frames whose `Payload Length` exceeds a configured maximum.
  - Recommended default: **16 MiB** per frame.
- Larger logical messages MUST be sent using **fragmentation** (below).

## Flags

Flags are a 16-bit bitfield.

- `0x0001` **START**: this frame is the first fragment of a logical message
- `0x0002` **END**: this frame is the last fragment of a logical message

Rules:

- For non-fragmented messages, both **START** and **END** MUST be set.
- For fragmented messages:
  - First fragment: **START** set, **END** clear
  - Middle fragments: both clear
  - Last fragment: **START** clear, **END** set
- All fragments of one logical message MUST use the same `(Type, Stream ID)`.
- Because the underlying transport is ordered, fragments are reassembled **in arrival order**.

## Message types

Type IDs (v1):

- `0x01` `auth_begin`
- `0x02` `auth_challenge`
- `0x03` `auth_proof`
- `0x04` `auth_ok`
- `0x05` `auth_error`
- `0x10` `message_payload`
- `0xFE` `ping`
- `0xFF` `pong`

Unknown `Type` handling:

- If a peer receives an unknown `Type`, it SHOULD close the connection (protocol mismatch).

## Payload encoding per type

### Auth frames (`0x01`..`0x05`)

Payload is a **UTF-8 JSON object** as defined by `architecture/agent-proxy-authentication.md`.

Notes:

- Even though the tunnel framing is binary, keeping auth payload JSON makes the handshake easy to inspect/debug.
- Future versions can switch to CBOR/Protobuf by defining a new `Version` or new auth `Type` IDs.

### Keepalive (`ping` / `pong`)

- Payload MUST be empty (`Payload Length = 0`).
- Flags MUST be `START|END`.
- `Stream ID` MUST be `0`.
- Either side may send `ping` periodically (e.g., every 15–30s).
- Receiver SHOULD respond promptly with `pong`.
- Missing `pong` after a timeout SHOULD cause the connection to be closed and re-established.

### `message_payload` (`0x10`)

The `message_payload` frame carries the bytes of a proxied message.

The tunnel protocol is **payload-agnostic**: it does not assume the framed bytes are HTTP/1.1, HTTP/2, gRPC, etc.
Those semantics belong to the system that *produces* and *consumes* the bytes at the tunnel endpoints.

#### Logical message model

`message_payload` frames are grouped into a **logical message** by `Stream ID` (message ID).

- A logical message consists of 1+ frames that share:
  - `Type = 0x10`
  - the same `Stream ID`
- The start/end of the message is determined by the **START/END** flags.

#### Payload layout

The payload begins with a small binary envelope:

- **Kind** (1 byte):
  - `0x01` **request** (expects a correlated response with the same `Stream ID`)
  - `0x02` **response** (correlated to a prior request with the same `Stream ID`)
  - `0x03` **oneway** (no response expected; `Stream ID` is still used for tracing)
- **Format** (1 byte):
  - `0x00` **opaque_bytes** (default for v1)
- **Reserved** (2 bytes): MUST be `0x0000` (future use)
- **Data** (N bytes): message bytes (possibly fragmented across multiple frames)

So the payload is:

```
Kind (1) | Format (1) | Reserved (2) | Data (N)
```

#### `opaque_bytes` format (`Format = 0x00`)

`Data` is an **opaque byte sequence**.

Rules:

- The receiver MUST NOT assume the message fits in a single frame; it MUST reassemble fragments before handing the bytes
  to the consumer.
- The tunnel layer MUST NOT parse or transform `Data`.

#### Correlation (request ↔ response)

- The sender of a `request` chooses a unique, non-zero `Stream ID`.
- The receiver MUST send the corresponding `response` using the **same `Stream ID`**.
- `oneway` messages do not have a corresponding response.

#### Fragmentation example

If a request is large:

- Frame 1: `Type=message_payload`, `Stream ID=123`, `Flags=START`, payload contains envelope + first chunk of Data
- Frame 2: `Type=message_payload`, `Stream ID=123`, `Flags=0`, payload contains continuation of Data (no new envelope)
- Frame 3: `Type=message_payload`, `Stream ID=123`, `Flags=END`, payload contains final chunk of Data

Important: only the first fragment includes the 4-byte envelope (`Kind/Format/Reserved`). Continuation fragments contain
**only raw Data bytes**.

## Error handling

Peers MUST close the connection if:

- Magic is not `SB`
- Version is not supported
- A frame violates fragmentation rules (e.g., END without a prior START for a new `Stream ID`)
- Frame exceeds configured size limits
- Auth fails (as per `agent-proxy-authentication.md`)

## Security

- The tunnel MUST run over **TLS**.
- Authentication is required before accepting any `message_payload` frames as routable traffic.

## Open questions (for iteration)

- Do we want to define additional `Format` values in v1 (e.g., a structured encoding), or keep v1 strictly
  `opaque_bytes`?
- Should we allow multiple concurrent in-flight requests? (This protocol supports it via `Stream ID`.)
- Do we need an explicit `close` frame type, or is transport close enough for v1?