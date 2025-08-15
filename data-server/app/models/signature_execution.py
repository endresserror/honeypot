"""
SignatureExecution model for tracking signature usage and results
"""

from datetime import datetime
from app import db

class SignatureExecution(db.Model):
    """Model for tracking signature execution results and feedback."""
    
    __tablename__ = 'signature_executions'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Signature reference
    signature_id = db.Column(db.String(20), db.ForeignKey('signatures.signature_id'), nullable=False, index=True)
    signature = db.relationship('Signature', backref='executions')
    
    # Execution details
    target_url = db.Column(db.Text, nullable=False)
    executed_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    # Results
    vulnerability_detected = db.Column(db.Boolean, nullable=False)
    response_status_code = db.Column(db.Integer)
    response_body_snippet = db.Column(db.Text)  # First 1000 chars for analysis
    response_time_ms = db.Column(db.Integer)
    
    # Scanner information
    scanner_instance_id = db.Column(db.String(100))  # Unique ID for scanner instance
    scanner_version = db.Column(db.String(50))
    
    # Additional metadata
    notes = db.Column(db.Text)  # Additional observations
    false_positive = db.Column(db.Boolean, default=False)  # Marked by admin if needed
    
    def __repr__(self):
        return f'<SignatureExecution {self.id}: {self.signature_id} -> {self.target_url[:50]}>'
    
    def to_dict(self):
        """Convert model to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'signatureId': self.signature_id,
            'targetUrl': self.target_url,
            'executedAt': self.executed_at.isoformat(),
            'vulnerabilityDetected': self.vulnerability_detected,
            'responseStatusCode': self.response_status_code,
            'responseBodySnippet': self.response_body_snippet,
            'responseTime': self.response_time_ms,
            'scannerInstanceId': self.scanner_instance_id,
            'scannerVersion': self.scanner_version,
            'notes': self.notes,
            'falsePositive': self.false_positive
        }
    
    @classmethod
    def from_feedback(cls, signature_id, target_url, vulnerability_detected, 
                     response_data=None, scanner_info=None):
        """Create execution record from scanner feedback."""
        execution = cls(
            signature_id=signature_id,
            target_url=target_url,
            vulnerability_detected=vulnerability_detected
        )
        
        if response_data:
            execution.response_status_code = response_data.get('status_code')
            execution.response_time_ms = response_data.get('response_time_ms')
            # Store only first 1000 chars to avoid huge database entries
            body = response_data.get('body', '')
            execution.response_body_snippet = body[:1000] if body else None
        
        if scanner_info:
            execution.scanner_instance_id = scanner_info.get('instance_id')
            execution.scanner_version = scanner_info.get('version')
        
        return execution