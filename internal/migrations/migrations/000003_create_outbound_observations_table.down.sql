-- Drop all partitions first, then the parent table
-- Note: This will drop all partitions, including any created by the stored procedure
DO $$
DECLARE
  r RECORD;
BEGIN
  FOR r IN 
    SELECT tablename 
    FROM pg_tables 
    WHERE schemaname = 'public' 
    AND tablename LIKE 'outbound_observations_%'
  LOOP
    EXECUTE format('DROP TABLE IF EXISTS %I CASCADE', r.tablename);
  END LOOP;
END
$$;

-- Drop the parent table
DROP TABLE IF EXISTS outbound_observations CASCADE;
