"""
AttackLog model for storing honeypot attack data
"""

from datetime import datetime
from sqlalchemy.dialects.postgresql import JSON
from app import db

class AttackLog(db.Model):
    """Model for storing attack request-response pairs from honeypot."""
    
    __tablename__ = 'attack_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)  # IPv6 compatible
    
    # Request data
    request_method = db.Column(db.String(10), nullable=False)
    request_uri = db.Column(db.Text, nullable=False)
    request_headers = db.Column(JSON, nullable=False)
    request_body = db.Column(db.Text)
    
    # Response data
    response_status_code = db.Column(db.Integer, nullable=False)
    response_headers = db.Column(JSON, nullable=False)
    response_body = db.Column(db.Text)
    response_time_ms = db.Column(db.Integer)  # Response time in milliseconds
    
    # Analysis flags
    processed = db.Column(db.Boolean, default=False, index=True)
    signatures_generated = db.Column(db.Integer, default=0)
    
    # Attack classification and heuristic detection
    attack_type = db.Column(db.String(50), default='normal')
    attack_severity = db.Column(db.String(20), default='low')
    attack_description = db.Column(db.Text, default='')
    suspicious_payloads = db.Column(JSON, default=list)
    heuristic_anomalies = db.Column(JSON, default=dict)
    
    # Metadata
    user_agent = db.Column(db.Text)
    referer = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<AttackLog {self.id}: {self.request_method} {self.request_uri[:50]}>'
    
    def to_dict(self):
        """Convert model to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'sourceIp': self.source_ip,
            'request': {
                'method': self.request_method,
                'uri': self.request_uri,
                'headers': self.request_headers,
                'body': self.request_body
            },
            'response': {
                'statusCode': self.response_status_code,
                'headers': self.response_headers,
                'body': self.response_body,
                'responseTime': self.response_time_ms
            },
            'processed': self.processed,
            'signaturesGenerated': self.signatures_generated,
            'attackType': self.attack_type,
            'attackSeverity': self.attack_severity,
            'attackDescription': self.attack_description,
            'suspiciousPayloads': self.suspicious_payloads,
            'heuristicAnomalies': self.heuristic_anomalies,
            'userAgent': self.user_agent,
            'referer': self.referer
        }
    
    @classmethod
    def from_dict(cls, data):
        """Create AttackLog instance from dictionary."""
        request = data.get('request', {})
        response = data.get('response', {})
        
        # Helper function to clean NUL characters
        def clean_text(text):
            if text is None:
                return None
            if isinstance(text, str):
                return text.replace('\x00', '')
            return text
        
        # Clean headers recursively
        def clean_headers(headers):
            if isinstance(headers, dict):
                return {k: clean_text(v) for k, v in headers.items()}
            return headers
        
        return cls(
            timestamp=datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00')),
            source_ip=clean_text(data['sourceIp']),
            request_method=clean_text(request['method']),
            request_uri=clean_text(request['uri']),
            request_headers=clean_headers(request['headers']),
            request_body=clean_text(request.get('body')),
            response_status_code=response['statusCode'],
            response_headers=clean_headers(response['headers']),
            response_body=clean_text(response.get('body')),
            response_time_ms=response.get('responseTime'),
            attack_type=data.get('attackType', 'normal'),
            attack_severity=data.get('attackSeverity', 'low'),
            attack_description=data.get('attackDescription', ''),
            suspicious_payloads=data.get('suspiciousPayloads', []),
            heuristic_anomalies=data.get('heuristicAnomalies', {}),
            user_agent=clean_text(request['headers'].get('User-Agent')),
            referer=clean_text(request['headers'].get('Referer'))
        )