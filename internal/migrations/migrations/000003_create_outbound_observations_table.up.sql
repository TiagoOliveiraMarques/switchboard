-- Create partitioned table for outbound observations
-- Partitioned by expires_at (range partitioning) for efficient TTL management
CREATE TABLE IF NOT EXISTS outbound_observations (
  observation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id TEXT NOT NULL,
  seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  request_method TEXT NOT NULL,
  request_host TEXT NOT NULL,
  request_path TEXT NOT NULL,
  request_query JSONB NULL,
  request_headers JSONB NULL,
  request_body_json JSONB NULL,
  response_status INT NULL,
  response_headers JSONB NULL,
  response_body_json JSONB NULL
) PARTITION BY RANGE (expires_at);

-- Create indexes on the parent table (will be inherited by partitions)
CREATE INDEX IF NOT EXISTS outbound_observations_expires_at_idx ON outbound_observations (expires_at);
CREATE INDEX IF NOT EXISTS outbound_observations_seen_at_idx ON outbound_observations (seen_at DESC);

-- Create initial partition for the next day
-- This ensures there's at least one partition available immediately
DO $$
DECLARE
  tomorrow_start TIMESTAMPTZ;
  tomorrow_end TIMESTAMPTZ;
  partition_name TEXT;
BEGIN
  -- Calculate tomorrow's date range (start of day to start of next day)
  tomorrow_start := date_trunc('day', now() + interval '1 day');
  tomorrow_end := tomorrow_start + interval '1 day';
  partition_name := 'outbound_observations_' || to_char(tomorrow_start, 'YYYY_MM_DD');
  
  -- Create partition if it doesn't exist
  IF NOT EXISTS (
    SELECT 1 FROM pg_class WHERE relname = partition_name
  ) THEN
    EXECUTE format(
      'CREATE TABLE %I PARTITION OF outbound_observations FOR VALUES FROM (%L) TO (%L)',
      partition_name,
      tomorrow_start,
      tomorrow_end
    );
  END IF;
END
$$;
