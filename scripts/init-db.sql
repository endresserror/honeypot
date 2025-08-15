-- Database initialization script for PostgreSQL
-- This script sets up the initial database structure and user permissions

-- Create database if it doesn't exist
-- Note: This command typically needs to be run by a superuser
-- CREATE DATABASE vulnerability_scanner;

-- Create user if it doesn't exist
-- CREATE USER scanner_user WITH PASSWORD 'scanner_password';

-- Grant privileges
-- GRANT ALL PRIVILEGES ON DATABASE vulnerability_scanner TO scanner_user;

-- Switch to the vulnerability_scanner database
-- \c vulnerability_scanner;

-- Grant schema privileges
GRANT ALL ON SCHEMA public TO scanner_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO scanner_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO scanner_user;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO scanner_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO scanner_user;

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create enum types for signatures
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'signaturestatus') THEN
        CREATE TYPE signaturestatus AS ENUM ('pending_review', 'approved', 'rejected');
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'attacktype') THEN
        CREATE TYPE attacktype AS ENUM (
            'SQL_INJECTION', 'XSS', 'LFI', 'RFI', 'COMMAND_INJECTION', 
            'PATH_TRAVERSAL', 'XXE', 'SSRF', 'UNKNOWN'
        );
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'risklevel') THEN
        CREATE TYPE risklevel AS ENUM ('Low', 'Medium', 'High', 'Critical');
    END IF;
END $$;

-- Create indexes for better performance (these will be created by Flask-SQLAlchemy)
-- But we can pre-create some if needed

-- Log message
DO $$
BEGIN
    RAISE NOTICE 'Database initialization completed successfully';
END $$;