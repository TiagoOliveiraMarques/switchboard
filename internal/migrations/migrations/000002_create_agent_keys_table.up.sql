-- Registry of allowed agents and their public keys.
CREATE TABLE IF NOT EXISTS agent_keys (
  -- 64-char lowercase hex string: sha256(public_key)
  agent_id TEXT PRIMARY KEY
    CHECK (agent_id ~ '^[0-9a-f]{64}$'),

  -- Raw Ed25519 public key bytes (32 bytes).
  public_key BYTEA NOT NULL
    CHECK (octet_length(public_key) = 32),

  -- 'active' keys may authenticate; 'revoked' keys must be rejected.
  status agent_key_status NOT NULL,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ NULL,

  -- Self-consistency: if status is revoked, revoked_at must be set (and vice-versa).
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

-- Lookup by agent_id. (PRIMARY KEY also creates a unique btree index on agent_id.)
CREATE UNIQUE INDEX IF NOT EXISTS agent_keys_agent_id_idx ON agent_keys (agent_id);
