"""
Signature model for storing vulnerability detection signatures
"""

from datetime import datetime
from enum import Enum
from sqlalchemy.dialects.postgresql import JSON
from app import db

class SignatureStatus(Enum):
    """Enumeration for signature approval status."""
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"

class AttackType(Enum):
    """Enumeration for attack types."""
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    LFI = "LFI"  # Local File Inclusion
    RFI = "RFI"  # Remote File Inclusion
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    XXE = "XXE"  # XML External Entity
    SSRF = "SSRF"  # Server-Side Request Forgery
    UNKNOWN = "UNKNOWN"

class RiskLevel(Enum):
    """Enumeration for vulnerability risk levels."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class Signature(db.Model):
    """Model for storing vulnerability detection signatures."""
    
    __tablename__ = 'signatures'
    
    id = db.Column(db.Integer, primary_key=True)
    signature_id = db.Column(db.String(20), unique=True, nullable=False, index=True)
    
    # Signature metadata
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.Enum(SignatureStatus), default=SignatureStatus.PENDING_REVIEW, index=True)
    attack_type = db.Column(db.Enum(AttackType), nullable=False, index=True)
    risk_level = db.Column(db.Enum(RiskLevel), nullable=False)
    
    # Quality metrics
    confidence_score = db.Column(db.Float, default=0.5)  # 0.0 to 1.0
    observed_count = db.Column(db.Integer, default=1)
    success_count = db.Column(db.Integer, default=0)
    false_positive_count = db.Column(db.Integer, default=0)
    
    # Attack pattern data
    attack_pattern = db.Column(JSON, nullable=False)  # {target, targetName, payload}
    verification = db.Column(JSON, nullable=False)     # {type, condition}
    
    # Source information
    source_attack_log_id = db.Column(db.Integer, db.ForeignKey('attack_logs.id'))
    source_attack_log = db.relationship('AttackLog', backref='generated_signatures')
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime)
    approved_by = db.Column(db.String(100))  # Admin username
    last_used_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<Signature {self.signature_id}: {self.name}>'
    
    def generate_signature_id(self):
        """Generate unique signature ID."""
        # Get highest existing ID
        max_id = db.session.query(db.func.max(Signature.id)).scalar() or 0
        self.signature_id = f"SID{max_id + 1:04d}"
    
    def approve(self, admin_username):
        """Approve the signature."""
        self.status = SignatureStatus.APPROVED
        self.approved_at = datetime.utcnow()
        self.approved_by = admin_username
    
    def reject(self, admin_username):
        """Reject the signature."""
        self.status = SignatureStatus.REJECTED
        self.approved_by = admin_username
    
    def update_confidence(self, success=True):
        """Update confidence score based on feedback."""
        if success:
            self.success_count += 1
            # Increase confidence, but cap at 1.0
            self.confidence_score = min(1.0, self.confidence_score + 0.1)
        else:
            self.false_positive_count += 1
            # Decrease confidence, but keep above 0.0
            self.confidence_score = max(0.0, self.confidence_score - 0.05)
        
        self.last_used_at = datetime.utcnow()
    
    def to_dict(self):
        """Convert model to dictionary for JSON serialization."""
        return {
            'signatureId': self.signature_id,
            'status': self.status.value,
            'name': self.name,
            'description': self.description,
            'attackType': self.attack_type.value,
            'riskLevel': self.risk_level.value,
            'confidenceScore': self.confidence_score,
            'observedCount': self.observed_count,
            'successCount': self.success_count,
            'falsePositiveCount': self.false_positive_count,
            'attackPattern': self.attack_pattern,
            'verification': self.verification,
            'createdAt': self.created_at.isoformat(),
            'approvedAt': self.approved_at.isoformat() if self.approved_at else None,
            'approvedBy': self.approved_by,
            'lastUsedAt': self.last_used_at.isoformat() if self.last_used_at else None
        }
    
    @classmethod
    def from_analysis(cls, attack_log, pattern_data, verification_data, attack_type, risk_level):
        """Create signature from attack analysis."""
        signature = cls(
            name=cls._generate_name(pattern_data, attack_type),
            attack_type=attack_type,
            risk_level=risk_level,
            attack_pattern=pattern_data,
            verification=verification_data,
            source_attack_log_id=attack_log.id
        )
        signature.generate_signature_id()
        return signature
    
    @staticmethod
    def _generate_name(pattern_data, attack_type):
        """Generate descriptive name for signature."""
        target = pattern_data.get('target', 'unknown')
        target_name = pattern_data.get('targetName', '')
        
        if target == 'parameter' and target_name:
            return f"{attack_type.value.replace('_', ' ').title()} in '{target_name}' parameter"
        elif target == 'header' and target_name:
            return f"{attack_type.value.replace('_', ' ').title()} in '{target_name}' header"
        else:
            return f"{attack_type.value.replace('_', ' ').title()} in {target}"