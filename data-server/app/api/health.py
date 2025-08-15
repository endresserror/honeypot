"""
ヘルスチェックエンドポイント
"""

from flask import jsonify, current_app
from app.api import api_bp
from app import db

@api_bp.route('/health', methods=['GET'])
def health_check():
    """基本的なヘルスチェックエンドポイント"""
    try:
        # データベース接続をテスト
        from sqlalchemy import text
        db.session.execute(text('SELECT 1'))
        database_status = 'healthy'
    except Exception as e:
        current_app.logger.error(f'Database health check failed: {e}')
        database_status = 'unhealthy'
    
    return jsonify({
        'status': 'healthy' if database_status == 'healthy' else 'unhealthy',
        'database': database_status,
        'service': 'MCP Server',
        'version': '1.0.0'
    }), 200 if database_status == 'healthy' else 503

@api_bp.route('/status', methods=['GET'])
def system_status():
    """詳細なシステム状態情報"""
    from app.models import AttackLog, Signature, SignatureExecution
    
    try:
        # 統計情報を取得
        total_logs = AttackLog.query.count()
        unprocessed_logs = AttackLog.query.filter_by(processed=False).count()
        total_signatures = Signature.query.count()
        pending_signatures = Signature.query.filter_by(status='PENDING_REVIEW').count()
        approved_signatures = Signature.query.filter_by(status='APPROVED').count()
        total_executions = SignatureExecution.query.count()
        
        return jsonify({
            'status': 'operational',
            'statistics': {
                'attackLogs': {
                    'total': total_logs,
                    'unprocessed': unprocessed_logs
                },
                'signatures': {
                    'total': total_signatures,
                    'pendingReview': pending_signatures,
                    'approved': approved_signatures
                },
                'executions': {
                    'total': total_executions
                }
            }
        })
    except Exception as e:
        current_app.logger.error(f'Status check failed: {e}')
        return jsonify({
            'status': 'error',
            'message': 'Unable to retrieve system status'
        }), 500