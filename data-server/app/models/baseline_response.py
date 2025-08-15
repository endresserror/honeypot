"""
BaselineResponse model for storing normal response patterns
"""

from datetime import datetime
from sqlalchemy.dialects.postgresql import JSON
from app import db

class BaselineResponse(db.Model):
    """Model for storing baseline responses for comparison with attack responses."""
    
    __tablename__ = 'baseline_responses'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Request pattern that generates this baseline
    request_pattern = db.Column(db.String(255), nullable=False, index=True)  # e.g., "GET /product.php?id=:param"
    parameter_name = db.Column(db.String(100))  # Parameter that was tested
    
    # Normal response characteristics
    typical_status_code = db.Column(db.Integer, nullable=False)
    typical_content_length = db.Column(db.Integer)
    typical_response_time_ms = db.Column(db.Integer)
    typical_headers = db.Column(JSON)
    
    # Response body patterns (for comparison)
    typical_body_hash = db.Column(db.String(64))  # SHA256 hash of typical response
    typical_body_keywords = db.Column(JSON)  # Common keywords/phrases in normal responses
    
    # Statistical data
    sample_count = db.Column(db.Integer, default=1)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Quality metrics
    consistency_score = db.Column(db.Float, default=1.0)  # How consistent the responses are
    
    def __repr__(self):
        return f'<BaselineResponse {self.id}: {self.request_pattern}>'
    
    def update_with_response(self, response_data):
        """Update baseline with new normal response data."""
        self.sample_count += 1
        self.last_updated = datetime.utcnow()
        
        # Update averages (simple moving average)
        if self.typical_content_length:
            self.typical_content_length = int(
                (self.typical_content_length * (self.sample_count - 1) + 
                 response_data.get('content_length', 0)) / self.sample_count
            )
        else:
            self.typical_content_length = response_data.get('content_length', 0)
        
        if self.typical_response_time_ms:
            self.typical_response_time_ms = int(
                (self.typical_response_time_ms * (self.sample_count - 1) + 
                 response_data.get('response_time_ms', 0)) / self.sample_count
            )
        else:
            self.typical_response_time_ms = response_data.get('response_time_ms', 0)
    
    def is_anomalous_response(self, response_data, threshold_config):
        """Check if a response deviates significantly from baseline."""
        anomalies = []
        
        # Check status code
        if response_data.get('status_code') != self.typical_status_code:
            anomalies.append('status_code_changed')
        
        # Check content length deviation
        response_length = response_data.get('content_length', 0)
        if self.typical_content_length and response_length:
            length_ratio = abs(response_length - self.typical_content_length) / self.typical_content_length
            if length_ratio > threshold_config.get('content_length_threshold', 0.3):
                anomalies.append('content_length_deviation')
        
        # Check response time
        response_time = response_data.get('response_time_ms', 0)
        if self.typical_response_time_ms and response_time:
            if response_time > self.typical_response_time_ms * 2:  # 2x normal time
                anomalies.append('response_time_anomaly')
        
        return anomalies
    
    def to_dict(self):
        """Convert model to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'requestPattern': self.request_pattern,
            'parameterName': self.parameter_name,
            'typicalStatusCode': self.typical_status_code,
            'typicalContentLength': self.typical_content_length,
            'typicalResponseTime': self.typical_response_time_ms,
            'typicalHeaders': self.typical_headers,
            'sampleCount': self.sample_count,
            'consistencyScore': self.consistency_score,
            'lastUpdated': self.last_updated.isoformat(),
            'createdAt': self.created_at.isoformat()
        }
    
    @classmethod
    def find_or_create_baseline(cls, request_pattern, parameter_name=None):
        """Find existing baseline or create new one."""
        baseline = cls.query.filter_by(
            request_pattern=request_pattern,
            parameter_name=parameter_name
        ).first()
        
        if not baseline:
            baseline = cls(
                request_pattern=request_pattern,
                parameter_name=parameter_name
            )
            db.session.add(baseline)
        
        return baseline