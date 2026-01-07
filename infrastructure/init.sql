-- PostgreSQL initialization script for Support Agent
-- Creates necessary extensions and initial schema

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "vector";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create incidents table
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id VARCHAR(100) UNIQUE NOT NULL,
    job_name VARCHAR(255) NOT NULL,
    job_type VARCHAR(50) NOT NULL,
    source_system VARCHAR(100),
    environment VARCHAR(20),
    error_message TEXT,
    error_code VARCHAR(100),
    stack_trace TEXT,
    failure_timestamp TIMESTAMPTZ,

    -- Classification
    category VARCHAR(50),
    severity VARCHAR(10),

    -- Resolution
    status VARCHAR(50) DEFAULT 'open',
    resolution_summary TEXT,
    resolution_verified BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMPTZ,

    -- Vector embedding
    embedding vector(1536),

    -- Metadata
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create known_errors table (KEDB)
CREATE TABLE IF NOT EXISTS known_errors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    error_id VARCHAR(100) UNIQUE NOT NULL,
    title VARCHAR(500) NOT NULL,
    error_pattern TEXT NOT NULL,
    root_cause TEXT,
    workaround TEXT,
    permanent_fix TEXT,

    -- Matching
    embedding vector(1536),
    keywords TEXT[],

    -- Metadata
    job_types TEXT[],
    active BOOLEAN DEFAULT TRUE,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create runbooks table
CREATE TABLE IF NOT EXISTS runbooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    runbook_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    content TEXT NOT NULL,

    -- Matching
    embedding vector(1536),
    triggers JSONB,

    -- Metadata
    job_types TEXT[],
    version VARCHAR(20),
    active BOOLEAN DEFAULT TRUE,
    execution_count INTEGER DEFAULT 0,
    success_rate FLOAT DEFAULT 0.0,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create incident_history table (audit trail)
CREATE TABLE IF NOT EXISTS incident_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    action_params JSONB,
    result JSONB,
    cost_usd FLOAT DEFAULT 0.0,

    -- Audit
    performed_by VARCHAR(100) DEFAULT 'system',
    performed_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create circuit_breaker_state table
CREATE TABLE IF NOT EXISTS circuit_breaker_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key VARCHAR(500) UNIQUE NOT NULL,
    failure_count INTEGER DEFAULT 0,
    last_failure_at TIMESTAMPTZ,
    circuit_opened_at TIMESTAMPTZ,
    state VARCHAR(20) DEFAULT 'closed',

    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create workflow_state table (for LangGraph checkpoints)
CREATE TABLE IF NOT EXISTS workflow_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id VARCHAR(100) NOT NULL,
    thread_id VARCHAR(100) NOT NULL,
    checkpoint_id VARCHAR(100) NOT NULL,
    state JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(thread_id, checkpoint_id)
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_incidents_job_name ON incidents(job_name);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_environment ON incidents(environment);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);

CREATE INDEX IF NOT EXISTS idx_incident_history_incident_id ON incident_history(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_history_performed_at ON incident_history(performed_at DESC);

CREATE INDEX IF NOT EXISTS idx_known_errors_active ON known_errors(active);
CREATE INDEX IF NOT EXISTS idx_runbooks_active ON runbooks(active);

CREATE INDEX IF NOT EXISTS idx_circuit_breaker_state_key ON circuit_breaker_state(key);

CREATE INDEX IF NOT EXISTS idx_workflow_state_incident_id ON workflow_state(incident_id);
CREATE INDEX IF NOT EXISTS idx_workflow_state_thread_id ON workflow_state(thread_id);

-- Create vector similarity indexes (IVFFlat for approximate search)
-- Note: These require data to be present first, so we create them with smaller lists
CREATE INDEX IF NOT EXISTS idx_incidents_embedding
    ON incidents USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 10);

CREATE INDEX IF NOT EXISTS idx_known_errors_embedding
    ON known_errors USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 10);

CREATE INDEX IF NOT EXISTS idx_runbooks_embedding
    ON runbooks USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 10);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply trigger to tables
DROP TRIGGER IF EXISTS update_incidents_updated_at ON incidents;
CREATE TRIGGER update_incidents_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_known_errors_updated_at ON known_errors;
CREATE TRIGGER update_known_errors_updated_at
    BEFORE UPDATE ON known_errors
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_runbooks_updated_at ON runbooks;
CREATE TRIGGER update_runbooks_updated_at
    BEFORE UPDATE ON runbooks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Insert sample known errors
INSERT INTO known_errors (error_id, title, error_pattern, root_cause, workaround, job_types)
VALUES
    ('KE-001', 'Driver OutOfMemoryError', 'java.lang.OutOfMemoryError.*heap',
     'Driver memory exhausted due to large data collection',
     'Increase driver memory or refactor to avoid collect()',
     ARRAY['databricks']),
    ('KE-002', 'Cluster Terminated Unexpectedly', 'ClusterTerminatedException',
     'Spot instance preemption or cluster timeout',
     'Restart the job - transient issue',
     ARRAY['databricks']),
    ('KE-003', 'Connection Timeout', 'Connection.*timed out',
     'Network connectivity issue or service overload',
     'Retry with exponential backoff',
     ARRAY['databricks', 'iws', 'api'])
ON CONFLICT (error_id) DO NOTHING;

-- Insert sample runbook
INSERT INTO runbooks (runbook_id, name, description, content, job_types, triggers)
VALUES
    ('RB-001', 'Restart Failed Databricks Job',
     'Standard procedure to restart a failed Databricks job',
     'steps:\n  - name: Check cluster status\n    tool: get_cluster_status\n  - name: Restart job\n    tool: restart_databricks_job',
     ARRAY['databricks'],
     '{"error_patterns": ["SparkException", "ClusterTerminatedException"]}'::jsonb)
ON CONFLICT (runbook_id) DO NOTHING;

-- Grant permissions (for the application user)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO supportagent;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO supportagent;
