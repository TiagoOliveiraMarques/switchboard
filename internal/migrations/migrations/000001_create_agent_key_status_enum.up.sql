-- Create enum type for agent key status
-- PostgreSQL doesn't support CREATE TYPE IF NOT EXISTS, so we use DO block
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'agent_key_status') THEN
    CREATE TYPE agent_key_status AS ENUM ('active', 'revoked');
  END IF;
END
$$;
