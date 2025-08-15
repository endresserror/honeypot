"""
Feedback API endpoints for scanner tool results
"""

from flask import request, jsonify, current_app
from app.api import api_bp
from app.models import SignatureExecution, Signature
from app.services import SignatureGenerator
from app import db
import logging

logger = logging.getLogger(__name__)

@api_bp.route('/feedback', methods=['POST'])
def submit_feedback():
    """Submit feedback from vulnerability scanner about signature execution results."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate required fields
        required_fields = ['signature_id', 'target_url', 'vulnerability_detected']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        signature_id = data['signature_id']
        target_url = data['target_url']
        vulnerability_detected = data['vulnerability_detected']
        
        # Validate signature exists
        signature = Signature.query.filter_by(signature_id=signature_id).first()
        if not signature:
            return jsonify({'error': 'Invalid signature ID'}), 400
        
        # Extract response data if provided
        response_data = data.get('response_data')
        scanner_info = data.get('scanner_info')
        
        # Create execution record
        execution = SignatureExecution.from_feedback(
            signature_id=signature_id,
            target_url=target_url,
            vulnerability_detected=vulnerability_detected,
            response_data=response_data,
            scanner_info=scanner_info
        )
        
        db.session.add(execution)
        
        # Update signature confidence based on result
        config = current_app.config.get('SCANNER_CONFIG', {})
        generator = SignatureGenerator(config)
        
        success = generator.update_signature_confidence(
            signature_id, 
            vulnerability_detected, 
            response_data
        )
        
        if not success:
            logger.warning(f"Failed to update confidence for signature {signature_id}")
        
        db.session.commit()
        
        logger.info(f"Feedback received for signature {signature_id}: vulnerability_detected={vulnerability_detected}")
        
        return jsonify({
            'message': 'Feedback submitted successfully',
            'execution_id': execution.id,
            'signature_updated': success
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error submitting feedback: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/feedback/batch', methods=['POST'])
def submit_batch_feedback():
    """Submit multiple feedback entries in batch for better performance."""
    try:
        data = request.get_json()
        
        if not data or 'feedback_items' not in data:
            return jsonify({'error': 'No feedback items provided'}), 400
        
        feedback_items = data['feedback_items']
        if not isinstance(feedback_items, list):
            return jsonify({'error': 'feedback_items must be a list'}), 400
        
        successful_submissions = 0
        failed_submissions = 0
        execution_ids = []
        
        config = current_app.config.get('SCANNER_CONFIG', {})
        generator = SignatureGenerator(config)
        
        for item in feedback_items:
            try:
                # Validate required fields for this item
                required_fields = ['signature_id', 'target_url', 'vulnerability_detected']
                if not all(field in item for field in required_fields):
                    failed_submissions += 1
                    continue
                
                signature_id = item['signature_id']
                
                # Validate signature exists
                signature = Signature.query.filter_by(signature_id=signature_id).first()
                if not signature:
                    failed_submissions += 1
                    continue
                
                # Create execution record
                execution = SignatureExecution.from_feedback(
                    signature_id=item['signature_id'],
                    target_url=item['target_url'],
                    vulnerability_detected=item['vulnerability_detected'],
                    response_data=item.get('response_data'),
                    scanner_info=item.get('scanner_info')
                )
                
                db.session.add(execution)
                execution_ids.append(execution.id)
                
                # Update signature confidence
                generator.update_signature_confidence(
                    signature_id,
                    item['vulnerability_detected'],
                    item.get('response_data')
                )
                
                successful_submissions += 1
                
            except Exception as e:
                logger.warning(f"Error processing feedback item: {e}")
                failed_submissions += 1
                continue
        
        db.session.commit()
        
        logger.info(f"Batch feedback processed: {successful_submissions} successful, {failed_submissions} failed")
        
        return jsonify({
            'message': 'Batch feedback processed',
            'successful_submissions': successful_submissions,
            'failed_submissions': failed_submissions,
            'execution_ids': execution_ids
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error submitting batch feedback: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/feedback/statistics', methods=['GET'])
def get_feedback_statistics():
    """Get statistics about signature execution feedback."""
    try:
        from sqlalchemy import func
        from datetime import datetime, timedelta
        
        # Overall statistics
        total_executions = SignatureExecution.query.count()
        successful_detections = SignatureExecution.query.filter_by(vulnerability_detected=True).count()
        failed_detections = SignatureExecution.query.filter_by(vulnerability_detected=False).count()
        
        success_rate = (successful_detections / total_executions * 100) if total_executions > 0 else 0
        
        # Recent activity (last 7 days)
        week_ago = datetime.utcnow() - timedelta(days=7)
        recent_executions = SignatureExecution.query.filter(
            SignatureExecution.executed_at >= week_ago
        ).count()
        
        # Top performing signatures
        top_signatures = db.session.query(
            SignatureExecution.signature_id,
            func.count(SignatureExecution.id).label('execution_count'),
            func.sum(SignatureExecution.vulnerability_detected.cast(db.Integer)).label('success_count')
        ).group_by(SignatureExecution.signature_id).order_by(
            func.count(SignatureExecution.id).desc()
        ).limit(10).all()
        
        # Format top signatures with additional info
        top_signatures_data = []
        for sig_id, exec_count, success_count in top_signatures:
            signature = Signature.query.filter_by(signature_id=sig_id).first()
            success_rate_sig = (success_count / exec_count * 100) if exec_count > 0 else 0
            
            top_signatures_data.append({
                'signature_id': sig_id,
                'signature_name': signature.name if signature else 'Unknown',
                'execution_count': exec_count,
                'success_count': success_count,
                'success_rate': round(success_rate_sig, 2)
            })
        
        # Scanner instance statistics
        scanner_stats = db.session.query(
            SignatureExecution.scanner_instance_id,
            func.count(SignatureExecution.id).label('execution_count')
        ).group_by(SignatureExecution.scanner_instance_id).all()
        
        return jsonify({
            'total_executions': total_executions,
            'successful_detections': successful_detections,
            'failed_detections': failed_detections,
            'overall_success_rate': round(success_rate, 2),
            'recent_executions': recent_executions,
            'top_signatures': top_signatures_data,
            'scanner_instances': [
                {'instance_id': instance_id, 'execution_count': count}
                for instance_id, count in scanner_stats
            ]
        })
        
    except Exception as e:
        logger.error(f"Error retrieving feedback statistics: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/feedback/<int:execution_id>', methods=['GET'])
def get_execution_detail(execution_id):
    """Get detailed information about a specific execution."""
    try:
        execution = SignatureExecution.query.get(execution_id)
        if not execution:
            return jsonify({'error': 'Execution not found'}), 404
        
        execution_data = execution.to_dict()
        
        # Include signature information
        if execution.signature:
            execution_data['signature'] = execution.signature.to_dict()
        
        return jsonify(execution_data)
        
    except Exception as e:
        logger.error(f"Error retrieving execution detail {execution_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/feedback/<int:execution_id>/mark-false-positive', methods=['PUT'])
def mark_false_positive(execution_id):
    """Mark an execution as a false positive (admin endpoint)."""
    try:
        data = request.get_json()
        admin_username = data.get('admin_username', 'unknown')
        notes = data.get('notes', '')
        
        execution = SignatureExecution.query.get(execution_id)
        if not execution:
            return jsonify({'error': 'Execution not found'}), 404
        
        execution.false_positive = True
        execution.notes = notes
        
        # Update signature confidence negatively
        if execution.signature:
            execution.signature.false_positive_count += 1
            execution.signature.confidence_score = max(0.0, execution.signature.confidence_score - 0.1)
        
        db.session.commit()
        
        logger.info(f"Execution {execution_id} marked as false positive by {admin_username}")
        
        return jsonify({
            'message': 'Execution marked as false positive',
            'execution': execution.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error marking execution {execution_id} as false positive: {e}")
        return jsonify({'error': 'Internal server error'}), 500