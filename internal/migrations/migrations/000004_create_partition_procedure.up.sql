-- Create stored procedure to create new partitions for outbound_observations
-- This procedure is idempotent and can be called periodically to ensure partitions exist ahead of time
CREATE OR REPLACE FUNCTION create_outbound_observations_partition(
  start_date TIMESTAMPTZ,
  end_date TIMESTAMPTZ
) RETURNS void AS $$
DECLARE
  partition_name TEXT;
BEGIN
  -- Generate partition name from start_date: outbound_observations_YYYY_MM_DD
  partition_name := 'outbound_observations_' || to_char(start_date, 'YYYY_MM_DD');
  
  -- Check if partition already exists
  IF NOT EXISTS (
    SELECT 1 FROM pg_class WHERE relname = partition_name
  ) THEN
    -- Create the partition
    EXECUTE format(
      'CREATE TABLE %I PARTITION OF outbound_observations FOR VALUES FROM (%L) TO (%L)',
      partition_name,
      start_date,
      end_date
    );
  END IF;
END;
$$ LANGUAGE plpgsql;
