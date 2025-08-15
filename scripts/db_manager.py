#!/usr/bin/env python3
"""
Database management script for the vulnerability scanner system

This script provides utilities for database operations like initialization,
migrations, backups, and maintenance.
"""

import os
import sys
import subprocess
import argparse
from datetime import datetime

# Add the MCP server to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'mcp-server'))

def run_command(command, cwd=None):
    """Run a shell command and return the result."""
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            check=True, 
            capture_output=True, 
            text=True,
            cwd=cwd
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}")
        print(f"Error output: {e.stderr}")
        raise

def init_database():
    """Initialize the database with tables and initial data."""
    print("Initializing database...")
    
    mcp_server_dir = os.path.join(os.path.dirname(__file__), '..', 'mcp-server')
    
    try:
        # Initialize Flask-Migrate
        print("Initializing Flask-Migrate...")
        run_command("flask db init", cwd=mcp_server_dir)
    except subprocess.CalledProcessError:
        print("Flask-Migrate already initialized")
    
    try:
        # Create initial migration
        print("Creating initial migration...")
        run_command("flask db migrate -m 'Initial migration'", cwd=mcp_server_dir)
    except subprocess.CalledProcessError:
        print("Migration already exists")
    
    # Apply migrations
    print("Applying migrations...")
    run_command("flask db upgrade", cwd=mcp_server_dir)
    
    print("Database initialized successfully!")

def create_migration(message):
    """Create a new database migration."""
    print(f"Creating migration: {message}")
    
    mcp_server_dir = os.path.join(os.path.dirname(__file__), '..', 'mcp-server')
    
    # Create migration
    run_command(f"flask db migrate -m '{message}'", cwd=mcp_server_dir)
    
    print("Migration created successfully!")

def apply_migrations():
    """Apply pending database migrations."""
    print("Applying database migrations...")
    
    mcp_server_dir = os.path.join(os.path.dirname(__file__), '..', 'mcp-server')
    
    # Apply migrations
    run_command("flask db upgrade", cwd=mcp_server_dir)
    
    print("Migrations applied successfully!")

def rollback_migration():
    """Rollback the last database migration."""
    print("Rolling back last migration...")
    
    mcp_server_dir = os.path.join(os.path.dirname(__file__), '..', 'mcp-server')
    
    # Rollback migration
    run_command("flask db downgrade", cwd=mcp_server_dir)
    
    print("Migration rolled back successfully!")

def backup_database(backup_path=None):
    """Create a database backup."""
    if not backup_path:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = f"backup_{timestamp}.sql"
    
    print(f"Creating database backup: {backup_path}")
    
    # Get database URL from environment or config
    db_url = os.environ.get('DATABASE_URL', 'postgresql://scanner_user:scanner_password@localhost:5432/vulnerability_scanner')
    
    # Extract connection details
    # Format: postgresql://user:password@host:port/database
    import re
    match = re.match(r'postgresql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', db_url)
    if not match:
        print("Error: Invalid DATABASE_URL format")
        return
    
    user, password, host, port, database = match.groups()
    
    # Set password environment variable
    env = os.environ.copy()
    env['PGPASSWORD'] = password
    
    # Create backup
    backup_command = f"pg_dump -h {host} -p {port} -U {user} -d {database} > {backup_path}"
    run_command(backup_command)
    
    print(f"Database backup created: {backup_path}")

def restore_database(backup_path):
    """Restore database from backup."""
    if not os.path.exists(backup_path):
        print(f"Error: Backup file not found: {backup_path}")
        return
    
    print(f"Restoring database from: {backup_path}")
    
    # Get database URL
    db_url = os.environ.get('DATABASE_URL', 'postgresql://scanner_user:scanner_password@localhost:5432/vulnerability_scanner')
    
    # Extract connection details
    import re
    match = re.match(r'postgresql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', db_url)
    if not match:
        print("Error: Invalid DATABASE_URL format")
        return
    
    user, password, host, port, database = match.groups()
    
    # Set password environment variable
    env = os.environ.copy()
    env['PGPASSWORD'] = password
    
    # Drop and recreate database
    drop_command = f"dropdb -h {host} -p {port} -U {user} {database}"
    create_command = f"createdb -h {host} -p {port} -U {user} {database}"
    restore_command = f"psql -h {host} -p {port} -U {user} -d {database} < {backup_path}"
    
    try:
        run_command(drop_command)
    except subprocess.CalledProcessError:
        print("Warning: Could not drop database (may not exist)")
    
    run_command(create_command)
    run_command(restore_command)
    
    print("Database restored successfully!")

def reset_database():
    """Reset the database by dropping and recreating all tables."""
    print("Resetting database...")
    
    mcp_server_dir = os.path.join(os.path.dirname(__file__), '..', 'mcp-server')
    
    # Import Flask app and database
    sys.path.insert(0, mcp_server_dir)
    from app import create_app, db
    
    app = create_app()
    with app.app_context():
        # Drop all tables
        db.drop_all()
        
        # Recreate all tables
        db.create_all()
    
    print("Database reset successfully!")

def show_status():
    """Show database status and migration information."""
    print("Database Status")
    print("=" * 50)
    
    mcp_server_dir = os.path.join(os.path.dirname(__file__), '..', 'mcp-server')
    
    try:
        # Show migration status
        print("Migration Status:")
        output = run_command("flask db current", cwd=mcp_server_dir)
        print(f"Current revision: {output.strip()}")
        
        # Show migration history
        print("\nMigration History:")
        output = run_command("flask db history", cwd=mcp_server_dir)
        print(output)
        
    except subprocess.CalledProcessError:
        print("Error getting migration status")
    
    # Show table information
    sys.path.insert(0, mcp_server_dir)
    from app import create_app, db
    
    app = create_app()
    with app.app_context():
        # Get table information
        from app.models import AttackLog, Signature, SignatureExecution, BaselineResponse
        
        print("\nTable Counts:")
        print(f"Attack Logs: {AttackLog.query.count()}")
        print(f"Signatures: {Signature.query.count()}")
        print(f"Signature Executions: {SignatureExecution.query.count()}")
        print(f"Baseline Responses: {BaselineResponse.query.count()}")

def create_sample_data():
    """Create sample data for testing."""
    print("Creating sample data...")
    
    # Run the sample data creation script
    sample_script = os.path.join(os.path.dirname(__file__), 'create_sample_data.py')
    run_command(f"python {sample_script}")
    
    print("Sample data created successfully!")

def main():
    """Main function with command line interface."""
    parser = argparse.ArgumentParser(description='Database management for vulnerability scanner')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Initialize database
    subparsers.add_parser('init', help='Initialize database with tables')
    
    # Migration commands
    migrate_parser = subparsers.add_parser('migrate', help='Create new migration')
    migrate_parser.add_argument('message', help='Migration message')
    
    subparsers.add_parser('upgrade', help='Apply pending migrations')
    subparsers.add_parser('downgrade', help='Rollback last migration')
    
    # Backup and restore
    backup_parser = subparsers.add_parser('backup', help='Create database backup')
    backup_parser.add_argument('--path', help='Backup file path')
    
    restore_parser = subparsers.add_parser('restore', help='Restore database from backup')
    restore_parser.add_argument('path', help='Backup file path')
    
    # Other commands
    subparsers.add_parser('reset', help='Reset database (drop and recreate tables)')
    subparsers.add_parser('status', help='Show database status')
    subparsers.add_parser('sample-data', help='Create sample data for testing')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        if args.command == 'init':
            init_database()
        elif args.command == 'migrate':
            create_migration(args.message)
        elif args.command == 'upgrade':
            apply_migrations()
        elif args.command == 'downgrade':
            rollback_migration()
        elif args.command == 'backup':
            backup_database(args.path)
        elif args.command == 'restore':
            restore_database(args.path)
        elif args.command == 'reset':
            reset_database()
        elif args.command == 'status':
            show_status()
        elif args.command == 'sample-data':
            create_sample_data()
        else:
            print(f"Unknown command: {args.command}")
            return 1
            
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main())