"""
Signature management API endpoints
"""

from flask import request, jsonify, current_app
from app.api import api_bp
from app.models import Signature, SignatureExecution
from app.models.signature import SignatureStatus
from app.services import SignatureGenerator
from app import db
import logging

logger = logging.getLogger(__name__)

@api_bp.route('/signatures', methods=['GET'])
def get_signatures():
    """Get approved signatures for use by scanner tools."""
    try:
        # Only return approved signatures
        signatures = Signature.query.filter_by(status=SignatureStatus.APPROVED).all()
        
        # Optional filtering by attack type
        attack_type = request.args.get('attack_type')
        if attack_type:
            signatures = [s for s in signatures if s.attack_type.value == attack_type.upper()]
        
        # Optional filtering by minimum confidence
        min_confidence = request.args.get('min_confidence', type=float)
        if min_confidence:
            signatures = [s for s in signatures if s.confidence_score >= min_confidence]
        
        return jsonify({
            'signatures': [sig.to_dict() for sig in signatures],
            'count': len(signatures)
        })
        
    except Exception as e:
        logger.error(f"Error retrieving signatures: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/signatures/pending', methods=['GET'])
def get_pending_signatures():
    """Get signatures awaiting review (admin endpoint)."""
    try:
        pending_signatures = Signature.query.filter_by(status=SignatureStatus.PENDING_REVIEW).all()
        
        # Include source log information for review
        result = []
        for sig in pending_signatures:
            sig_data = sig.to_dict()
            if sig.source_attack_log:
                sig_data['sourceLog'] = {
                    'id': sig.source_attack_log.id,
                    'timestamp': sig.source_attack_log.timestamp.isoformat(),
                    'sourceIp': sig.source_attack_log.source_ip,
                    'requestUri': sig.source_attack_log.request_uri,
                    'responseStatusCode': sig.source_attack_log.response_status_code
                }
            result.append(sig_data)
        
        return jsonify({
            'signatures': result,
            'count': len(result)
        })
        
    except Exception as e:
        logger.error(f"Error retrieving pending signatures: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/signatures/<signature_id>/approve', methods=['PUT'])
def approve_signature(signature_id):
    """Approve a signature for use."""
    try:
        data = request.get_json()
        admin_username = data.get('admin_username', 'unknown')
        
        signature = Signature.query.filter_by(signature_id=signature_id).first()
        if not signature:
            return jsonify({'error': 'Signature not found'}), 404
        
        if signature.status != SignatureStatus.PENDING_REVIEW:
            return jsonify({'error': 'Signature is not pending review'}), 400
        
        signature.approve(admin_username)
        db.session.commit()
        
        logger.info(f"Signature {signature_id} approved by {admin_username}")
        
        return jsonify({
            'message': 'Signature approved successfully',
            'signature': signature.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error approving signature {signature_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/signatures/<signature_id>/reject', methods=['PUT'])
def reject_signature(signature_id):
    """Reject a signature."""
    try:
        data = request.get_json()
        admin_username = data.get('admin_username', 'unknown')
        reason = data.get('reason', '')
        
        signature = Signature.query.filter_by(signature_id=signature_id).first()
        if not signature:
            return jsonify({'error': 'Signature not found'}), 404
        
        if signature.status != SignatureStatus.PENDING_REVIEW:
            return jsonify({'error': 'Signature is not pending review'}), 400
        
        signature.reject(admin_username)
        if reason:
            signature.description += f" (Rejected: {reason})"
        
        db.session.commit()
        
        logger.info(f"Signature {signature_id} rejected by {admin_username}")
        
        return jsonify({
            'message': 'Signature rejected successfully',
            'signature': signature.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error rejecting signature {signature_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/signatures/<signature_id>', methods=['GET'])
def get_signature_detail(signature_id):
    """Get detailed information about a specific signature."""
    try:
        signature = Signature.query.filter_by(signature_id=signature_id).first()
        if not signature:
            return jsonify({'error': 'Signature not found'}), 404
        
        # Include execution history
        executions = SignatureExecution.query.filter_by(signature_id=signature_id).order_by(
            SignatureExecution.executed_at.desc()
        ).limit(50).all()
        
        signature_data = signature.to_dict()
        signature_data['recentExecutions'] = [exec.to_dict() for exec in executions]
        
        return jsonify(signature_data)
        
    except Exception as e:
        logger.error(f"Error retrieving signature detail {signature_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/signatures/statistics', methods=['GET'])
def get_signature_statistics():
    """Get signature generation and usage statistics."""
    try:
        config = current_app.config.get('SCANNER_CONFIG', {})
        generator = SignatureGenerator(config)
        stats = generator.get_generation_statistics()
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error retrieving signature statistics: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/signatures/generate', methods=['POST'])
def trigger_signature_generation():
    """Manually trigger signature generation from unprocessed logs."""
    try:
        config = current_app.config.get('SCANNER_CONFIG', {})
        
        # Import services here to avoid circular imports
        from app.services import LogAnalyzer, SignatureGenerator
        
        analyzer = LogAnalyzer(config)
        generator = SignatureGenerator(config)
        
        # Analyze unprocessed logs
        analysis_results = analyzer.analyze_unprocessed_logs()
        
        if not analysis_results:
            return jsonify({
                'message': 'No new patterns found in unprocessed logs',
                'generated_count': 0
            })
        
        # Generate signatures
        new_signatures = generator.generate_signatures_from_analysis(analysis_results)
        
        # Merge similar signatures to reduce duplicates
        merged_signatures = generator.merge_similar_signatures(new_signatures)
        
        logger.info(f"Generated {len(merged_signatures)} signatures from {len(analysis_results)} analyzed logs")
        
        return jsonify({
            'message': f'Successfully generated {len(merged_signatures)} signatures',
            'generated_count': len(merged_signatures),
            'analyzed_logs': len(analysis_results),
            'signatures': [sig.to_dict() for sig in merged_signatures]
        })
        
    except Exception as e:
        logger.error(f"Error generating signatures: {e}")
        return jsonify({'error': 'Internal server error'}), 500