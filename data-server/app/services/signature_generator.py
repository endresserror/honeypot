"""
Signature generation service for creating vulnerability detection signatures
"""

import logging
from typing import Dict, List, Optional
from app.models import Signature, AttackLog
from app.models.signature import AttackType, RiskLevel, SignatureStatus
from app.services.response_analyzer import ResponseAnalyzer
from app import db

logger = logging.getLogger(__name__)

class SignatureGenerator:
    """Generates vulnerability detection signatures from analyzed attack patterns."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.response_analyzer = ResponseAnalyzer(config)
        self.min_confidence = config.get('signature_generation', {}).get('min_confidence_threshold', 0.5)
    
    def generate_signatures_from_analysis(self, analysis_results: List[Dict]) -> List[Signature]:
        """Generate signatures from log analysis results."""
        generated_signatures = []
        
        for result in analysis_results:
            try:
                signature = self._create_signature_from_analysis(result)
                if signature and signature.confidence_score >= self.min_confidence:
                    db.session.add(signature)
                    generated_signatures.append(signature)
                    
                    # Update the attack log with signature count
                    attack_log = result['attack_log']
                    attack_log.signatures_generated += 1
                    
                    logger.info(f"Generated signature {signature.signature_id} from log {attack_log.id}")
            
            except Exception as e:
                logger.error(f"Error generating signature from analysis: {e}")
                continue
        
        # Commit all changes
        try:
            db.session.commit()
            logger.info(f"Successfully generated {len(generated_signatures)} signatures")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error committing signatures: {e}")
            return []
        
        return generated_signatures
    
    def _create_signature_from_analysis(self, analysis_result: Dict) -> Optional[Signature]:
        """Create a signature from a single analysis result."""
        attack_log = analysis_result['attack_log']
        request_analysis = analysis_result['request_analysis']
        response_analysis = analysis_result['response_analysis']
        confidence = analysis_result['confidence']
        
        payload_target = request_analysis['payload_target']
        payload_info = payload_target['payload_info']
        
        # Determine attack type and risk level
        attack_type = payload_info['attack_type']
        risk_level = self._determine_risk_level(payload_info, response_analysis)
        
        # Create attack pattern data
        attack_pattern = {
            'target': payload_target['target'],
            'targetName': payload_target['target_name'],
            'payload': self._normalize_payload(payload_info['payload'])
        }
        
        # Generate verification condition
        verification = self.response_analyzer.generate_verification_condition(response_analysis)
        
        # Create signature
        signature = Signature.from_analysis(
            attack_log=attack_log,
            pattern_data=attack_pattern,
            verification_data=verification,
            attack_type=attack_type,
            risk_level=risk_level
        )
        
        signature.confidence_score = confidence
        signature.description = self._generate_description(payload_info, response_analysis)
        
        return signature
    
    def _determine_risk_level(self, payload_info: Dict, response_analysis: Dict) -> RiskLevel:
        """Determine risk level based on attack type and response severity."""
        attack_type = payload_info['attack_type']
        response_severity = response_analysis.get('severity', 'low')
        
        # Base risk levels by attack type
        base_risk = {
            AttackType.SQL_INJECTION: RiskLevel.HIGH,
            AttackType.COMMAND_INJECTION: RiskLevel.CRITICAL,
            AttackType.XSS: RiskLevel.MEDIUM,
            AttackType.LFI: RiskLevel.HIGH,
            AttackType.RFI: RiskLevel.HIGH,
            AttackType.XXE: RiskLevel.HIGH,
            AttackType.PATH_TRAVERSAL: RiskLevel.MEDIUM,
            AttackType.SSRF: RiskLevel.MEDIUM,
            AttackType.UNKNOWN: RiskLevel.LOW
        }.get(attack_type, RiskLevel.LOW)
        
        # Adjust based on response severity
        severity_boost = {
            'critical': 2,
            'high': 1,
            'medium': 0,
            'low': -1
        }.get(response_severity, 0)
        
        # Calculate final risk level
        risk_levels = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        current_index = risk_levels.index(base_risk)
        new_index = max(0, min(len(risk_levels) - 1, current_index + severity_boost))
        
        return risk_levels[new_index]
    
    def _normalize_payload(self, payload: str) -> str:
        """Normalize payload for signature generation."""
        # Remove specific values and make more generic
        normalized = payload.strip()
        
        # Replace specific numbers with placeholders for SQL injection
        import re
        if re.search(r"'\s*or\s*\d+\s*=\s*\d+", normalized, re.IGNORECASE):
            normalized = re.sub(r"\d+", "1", normalized)
        
        # Limit payload length
        if len(normalized) > 200:
            normalized = normalized[:200] + "..."
        
        return normalized
    
    def _generate_description(self, payload_info: Dict, response_analysis: Dict) -> str:
        """Generate human-readable description for the signature."""
        attack_type = payload_info['attack_type'].value.replace('_', ' ').title()
        payload_desc = payload_info.get('description', 'Unknown pattern')
        
        description = f"{attack_type} attack using {payload_desc.lower()}"
        
        # Add response information
        error_indicators = response_analysis.get('error_indicators', [])
        if error_indicators:
            error_desc = error_indicators[0].get('description', '')
            description += f". Detected by {error_desc.lower()}"
        
        return description
    
    def merge_similar_signatures(self, signatures: List[Signature]) -> List[Signature]:
        """Merge similar signatures to reduce duplicates."""
        # Group signatures by attack pattern similarity
        signature_groups = {}
        
        for signature in signatures:
            # Create a key based on attack type, target, and payload similarity
            key = self._create_similarity_key(signature)
            
            if key not in signature_groups:
                signature_groups[key] = []
            signature_groups[key].append(signature)
        
        merged_signatures = []
        for group in signature_groups.values():
            if len(group) == 1:
                merged_signatures.append(group[0])
            else:
                # Merge the group into a single signature
                merged = self._merge_signature_group(group)
                merged_signatures.append(merged)
        
        return merged_signatures
    
    def _create_similarity_key(self, signature: Signature) -> str:
        """Create a key for grouping similar signatures."""
        pattern = signature.attack_pattern
        
        # Normalize payload for similarity comparison
        payload = pattern.get('payload', '').lower()
        payload = re.sub(r'\d+', 'N', payload)  # Replace numbers
        payload = re.sub(r'[\'"]', 'Q', payload)  # Replace quotes
        
        return f"{signature.attack_type.value}:{pattern.get('target')}:{pattern.get('targetName')}:{payload[:50]}"
    
    def _merge_signature_group(self, signatures: List[Signature]) -> Signature:
        """Merge a group of similar signatures."""
        # Use the signature with highest confidence as base
        base_signature = max(signatures, key=lambda s: s.confidence_score)
        
        # Combine observed counts
        total_observed = sum(s.observed_count for s in signatures)
        base_signature.observed_count = total_observed
        
        # Average confidence scores
        avg_confidence = sum(s.confidence_score for s in signatures) / len(signatures)
        base_signature.confidence_score = avg_confidence
        
        # Update description to indicate merged signature
        base_signature.description += f" (merged from {len(signatures)} similar patterns)"
        
        # Remove other signatures from session
        for sig in signatures:
            if sig != base_signature and sig in db.session:
                db.session.delete(sig)
        
        return base_signature
    
    def update_signature_confidence(self, signature_id: str, success: bool, 
                                  response_data: Dict = None) -> bool:
        """Update signature confidence based on usage feedback."""
        try:
            signature = Signature.query.filter_by(signature_id=signature_id).first()
            if not signature:
                logger.warning(f"Signature {signature_id} not found for confidence update")
                return False
            
            signature.update_confidence(success)
            
            # Update signature statistics
            if success:
                # Optionally analyze the successful response to improve the signature
                if response_data:
                    self._analyze_successful_detection(signature, response_data)
            
            db.session.commit()
            logger.info(f"Updated confidence for signature {signature_id}: {signature.confidence_score}")
            return True
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating signature confidence: {e}")
            return False
    
    def _analyze_successful_detection(self, signature: Signature, response_data: Dict):
        """Analyze successful detection to potentially improve signature."""
        # This could be extended to refine verification conditions
        # based on successful detections
        pass
    
    def get_generation_statistics(self) -> Dict:
        """Get statistics about signature generation."""
        try:
            total_signatures = Signature.query.count()
            pending_count = Signature.query.filter_by(status=SignatureStatus.PENDING_REVIEW).count()
            approved_count = Signature.query.filter_by(status=SignatureStatus.APPROVED).count()
            rejected_count = Signature.query.filter_by(status=SignatureStatus.REJECTED).count()
            
            # Attack type distribution
            attack_type_counts = {}
            for attack_type in AttackType:
                count = Signature.query.filter_by(attack_type=attack_type).count()
                if count > 0:
                    attack_type_counts[attack_type.value] = count
            
            return {
                'total_signatures': total_signatures,
                'pending_review': pending_count,
                'approved': approved_count,
                'rejected': rejected_count,
                'attack_type_distribution': attack_type_counts
            }
            
        except Exception as e:
            logger.error(f"Error getting generation statistics: {e}")
            return {}