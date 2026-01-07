-- PostgreSQL initialization script for Support Agent
-- Executed when the database container starts for the first time

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "vector";

-- Create incidents table
CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(50) UNIQUE NOT NULL,
    job_name VARCHAR(255) NOT NULL,
    job_type VARCHAR(50) NOT NULL,
    source_system VARCHAR(100) NOT NULL,
    environment VARCHAR(20) NOT NULL,
    error_message TEXT,
    error_code VARCHAR(50),
    stack_trace TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    severity VARCHAR(10),
    category VARCHAR(50),
    resolution_summary TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create incidents history table for action tracking
CREATE TABLE IF NOT EXISTS incident_history (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(50) NOT NULL REFERENCES incidents(incident_id),
    action_type VARCHAR(50) NOT NULL,
    action_details JSONB,
    actor VARCHAR(100) DEFAULT 'system',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create known errors table
CREATE TABLE IF NOT EXISTS known_errors (
    id SERIAL PRIMARY KEY,
    error_id VARCHAR(50) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    error_pattern TEXT NOT NULL,
    root_cause TEXT,
    workaround TEXT,
    permanent_fix TEXT,
    affected_systems TEXT[],
    embedding vector(3072),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create past incidents table for similarity search
CREATE TABLE IF NOT EXISTS past_incidents (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(50) UNIQUE NOT NULL,
    job_name VARCHAR(255),
    error_message TEXT,
    root_cause TEXT,
    resolution_summary TEXT,
    resolution_verified BOOLEAN DEFAULT FALSE,
    embedding vector(3072),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create runbooks table
CREATE TABLE IF NOT EXISTS runbooks (
    id SERIAL PRIMARY KEY,
    runbook_id VARCHAR(50) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    job_types TEXT[],
    error_patterns TEXT[],
    steps JSONB,
    embedding vector(3072),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_job_name ON incidents(job_name);
CREATE INDEX IF NOT EXISTS idx_incident_history_incident_id ON incident_history(incident_id);

-- Create vector indexes for similarity search
CREATE INDEX IF NOT EXISTS idx_known_errors_embedding ON known_errors
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
CREATE INDEX IF NOT EXISTS idx_past_incidents_embedding ON past_incidents
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
CREATE INDEX IF NOT EXISTS idx_runbooks_embedding ON runbooks
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

-- Insert sample known errors for testing
INSERT INTO known_errors (error_id, title, error_pattern, root_cause, workaround, permanent_fix, affected_systems)
VALUES
    ('KE-001', 'OutOfMemory on Large Datasets', 'OutOfMemoryError.*Java heap space',
     'Insufficient cluster memory for data volume',
     'Clear Spark cache and restart with --conf spark.memory.fraction=0.8',
     'Increase cluster memory or implement data partitioning',
     ARRAY['databricks', 'spark']),
    ('KE-002', 'Connection Timeout to Azure SQL', 'Connection.*timeout.*Azure SQL',
     'Network connectivity issues or SQL server overload',
     'Retry with exponential backoff, check firewall rules',
     'Configure connection pooling and retry logic',
     ARRAY['adf', 'databricks']),
    ('KE-003', 'Delta Lake Concurrent Write Conflict', 'ConcurrentAppendException.*delta',
     'Multiple jobs writing to same Delta table simultaneously',
     'Implement write ordering or use merge operations',
     'Configure Delta Lake isolation level and retry logic',
     ARRAY['databricks', 'delta'])
ON CONFLICT (error_id) DO NOTHING;

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_incidents_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_known_errors_updated_at
    BEFORE UPDATE ON known_errors
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_runbooks_updated_at
    BEFORE UPDATE ON runbooks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Grant permissions (for production, use more restrictive permissions)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;
