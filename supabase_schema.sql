-- GUARD SOC: Database Schema for Supabase (Postgres)
-- Paste this into your Supabase SQL Editor

-- 1. Users Table (Dashboard Access)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Clients Table (Site Identities & API Keys)
CREATE TABLE IF NOT EXISTS clients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    site_name TEXT NOT NULL,
    api_key TEXT UNIQUE NOT NULL,
    plan_type TEXT DEFAULT 'FREE', -- FREE, SENTINEL, ENTERPRISE
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Incidents Table (Threat Logs)
CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    client_id TEXT NOT NULL, -- This matches the API Key or Site Name
    agent TEXT NOT NULL,
    status TEXT NOT NULL,
    threat_level TEXT NOT NULL,
    payload TEXT,
    result JSONB NOT NULL
);

-- 4. Pipeline Runs Table (Full Orchestration History)
CREATE TABLE IF NOT EXISTS pipeline_runs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    client_id TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    payload TEXT,
    detection JSONB,
    ir_response JSONB,
    threat_intel JSONB,
    report JSONB,
    deadman_fired BOOLEAN DEFAULT FALSE,
    final_status TEXT NOT NULL
);

-- Enable RLS (Row Level Security) if you want extra security, 
-- but for now, we'll manage access via the API Keys.
