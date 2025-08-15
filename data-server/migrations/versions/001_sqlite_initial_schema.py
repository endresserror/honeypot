"""SQLite compatible initial database schema

Revision ID: 001_sqlite
Revises: 
Create Date: 2024-08-15 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '001_sqlite'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Create attack_logs table
    op.create_table('attack_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('source_ip', sa.String(length=45), nullable=False),
        sa.Column('request_method', sa.String(length=10), nullable=False),
        sa.Column('request_uri', sa.Text(), nullable=False),
        sa.Column('request_headers', sa.Text(), nullable=False),  # JSON as TEXT for SQLite
        sa.Column('request_body', sa.Text(), nullable=True),
        sa.Column('response_status_code', sa.Integer(), nullable=False),
        sa.Column('response_headers', sa.Text(), nullable=False),  # JSON as TEXT for SQLite
        sa.Column('response_body', sa.Text(), nullable=True),
        sa.Column('response_time_ms', sa.Integer(), nullable=True),
        sa.Column('processed', sa.Boolean(), nullable=True),
        sa.Column('signatures_generated', sa.Integer(), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('referer', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_attack_logs_processed'), 'attack_logs', ['processed'], unique=False)
    op.create_index(op.f('ix_attack_logs_source_ip'), 'attack_logs', ['source_ip'], unique=False)
    op.create_index(op.f('ix_attack_logs_timestamp'), 'attack_logs', ['timestamp'], unique=False)
    
    # Create baseline_responses table
    op.create_table('baseline_responses',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('request_pattern', sa.String(length=255), nullable=False),
        sa.Column('parameter_name', sa.String(length=100), nullable=True),
        sa.Column('typical_status_code', sa.Integer(), nullable=False),
        sa.Column('typical_content_length', sa.Integer(), nullable=True),
        sa.Column('typical_response_time_ms', sa.Integer(), nullable=True),
        sa.Column('typical_headers', sa.Text(), nullable=True),  # JSON as TEXT for SQLite
        sa.Column('typical_body_hash', sa.String(length=64), nullable=True),
        sa.Column('typical_body_keywords', sa.Text(), nullable=True),  # JSON as TEXT for SQLite
        sa.Column('sample_count', sa.Integer(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('consistency_score', sa.Float(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_baseline_responses_request_pattern'), 'baseline_responses', ['request_pattern'], unique=False)
    
    # Create signatures table
    op.create_table('signatures',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('signature_id', sa.String(length=20), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=True),  # ENUM as VARCHAR for SQLite
        sa.Column('attack_type', sa.String(length=50), nullable=False),  # ENUM as VARCHAR for SQLite
        sa.Column('risk_level', sa.String(length=20), nullable=False),  # ENUM as VARCHAR for SQLite
        sa.Column('confidence_score', sa.Float(), nullable=True),
        sa.Column('observed_count', sa.Integer(), nullable=True),
        sa.Column('success_count', sa.Integer(), nullable=True),
        sa.Column('false_positive_count', sa.Integer(), nullable=True),
        sa.Column('attack_pattern', sa.Text(), nullable=False),  # JSON as TEXT for SQLite
        sa.Column('verification', sa.Text(), nullable=False),  # JSON as TEXT for SQLite
        sa.Column('source_attack_log_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('approved_at', sa.DateTime(), nullable=True),
        sa.Column('approved_by', sa.String(length=100), nullable=True),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['source_attack_log_id'], ['attack_logs.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_signatures_attack_type'), 'signatures', ['attack_type'], unique=False)
    op.create_index(op.f('ix_signatures_signature_id'), 'signatures', ['signature_id'], unique=True)
    op.create_index(op.f('ix_signatures_status'), 'signatures', ['status'], unique=False)
    
    # Create signature_executions table
    op.create_table('signature_executions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('signature_id', sa.String(length=20), nullable=False),
        sa.Column('target_url', sa.Text(), nullable=False),
        sa.Column('executed_at', sa.DateTime(), nullable=True),
        sa.Column('vulnerability_detected', sa.Boolean(), nullable=False),
        sa.Column('response_status_code', sa.Integer(), nullable=True),
        sa.Column('response_body_snippet', sa.Text(), nullable=True),
        sa.Column('response_time_ms', sa.Integer(), nullable=True),
        sa.Column('scanner_instance_id', sa.String(length=100), nullable=True),
        sa.Column('scanner_version', sa.String(length=50), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('false_positive', sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(['signature_id'], ['signatures.signature_id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_signature_executions_executed_at'), 'signature_executions', ['executed_at'], unique=False)
    op.create_index(op.f('ix_signature_executions_signature_id'), 'signature_executions', ['signature_id'], unique=False)


def downgrade():
    # Drop tables in reverse order
    op.drop_index(op.f('ix_signature_executions_signature_id'), table_name='signature_executions')
    op.drop_index(op.f('ix_signature_executions_executed_at'), table_name='signature_executions')
    op.drop_table('signature_executions')
    
    op.drop_index(op.f('ix_signatures_status'), table_name='signatures')
    op.drop_index(op.f('ix_signatures_signature_id'), table_name='signatures')
    op.drop_index(op.f('ix_signatures_attack_type'), table_name='signatures')
    op.drop_table('signatures')
    
    op.drop_index(op.f('ix_baseline_responses_request_pattern'), table_name='baseline_responses')
    op.drop_table('baseline_responses')
    
    op.drop_index(op.f('ix_attack_logs_timestamp'), table_name='attack_logs')
    op.drop_index(op.f('ix_attack_logs_source_ip'), table_name='attack_logs')
    op.drop_index(op.f('ix_attack_logs_processed'), table_name='attack_logs')
    op.drop_table('attack_logs')