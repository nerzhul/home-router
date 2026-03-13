-- Drop enabled column from subnets and ia_prefixes tables.
-- Filtering by enabled state is no longer supported; all records are considered active.

ALTER TABLE subnets DROP COLUMN enabled;

DROP INDEX IF EXISTS idx_ia_prefixes_enabled;
ALTER TABLE ia_prefixes DROP COLUMN enabled;
