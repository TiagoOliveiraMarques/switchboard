-- Drop enum type (only if no tables are using it)
-- Note: This will fail if agent_keys table still exists
DROP TYPE IF EXISTS agent_key_status;
