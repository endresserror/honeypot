"""
攻撃ログ管理APIエンドポイント
"""

from flask import request, jsonify, current_app
from app.api import api_bp
from app.models import AttackLog, BaselineResponse
from app import db
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

@api_bp.route('/logs', methods=['POST'])
def submit_attack_log():
    """ハニーポットから攻撃ログを送信"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # 必須フィールドの検証
        required_fields = ['timestamp', 'sourceIp', 'request', 'response']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # 攻撃ログエントリを作成
        attack_log = AttackLog.from_dict(data)
        
        # ベースライン要求（通常、非悪意）かどうかをチェック
        is_baseline = _is_baseline_request(data)
        
        if is_baseline:
            # 攻撃として扱わずベースラインデータを更新
            _update_baseline_data(data)
            db.session.add(attack_log)
            attack_log.processed = True  # ベースラインなので処理済みとマーク
        else:
            # 潜在的攻撃ログとして追加
            db.session.add(attack_log)
        
        db.session.commit()
        
        response_data = {
            'message': 'Log submitted successfully',
            'log_id': attack_log.id,
            'type': 'baseline' if is_baseline else 'attack'
        }
        
        if not is_baseline:
            # Optionally trigger immediate analysis for high-priority attacks
            if _is_high_priority_attack(data):
                response_data['priority'] = 'high'
                # Could trigger immediate processing here
        
        return jsonify(response_data), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error submitting attack log: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/logs', methods=['GET'])
def get_attack_logs():
    """Get attack logs (admin endpoint)."""
    try:
        # Pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 100)
        
        # Filtering parameters
        processed = request.args.get('processed', type=bool)
        source_ip = request.args.get('source_ip')
        method = request.args.get('method')
        since = request.args.get('since')  # ISO format timestamp
        
        # Build query
        query = AttackLog.query
        
        if processed is not None:
            query = query.filter_by(processed=processed)
        
        if source_ip:
            query = query.filter_by(source_ip=source_ip)
        
        if method:
            query = query.filter_by(request_method=method.upper())
        
        if since:
            try:
                since_date = datetime.fromisoformat(since.replace('Z', '+00:00'))
                query = query.filter(AttackLog.timestamp >= since_date)
            except ValueError:
                return jsonify({'error': 'Invalid since timestamp format'}), 400
        
        # Order by timestamp descending
        query = query.order_by(AttackLog.timestamp.desc())
        
        # Execute paginated query
        pagination = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        logs = pagination.items
        
        return jsonify({
            'logs': [log.to_dict() for log in logs],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        })
        
    except Exception as e:
        logger.error(f"Error retrieving attack logs: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/logs/<int:log_id>', methods=['GET'])
def get_attack_log_detail(log_id):
    """Get detailed information about a specific attack log."""
    try:
        attack_log = AttackLog.query.get(log_id)
        if not attack_log:
            return jsonify({'error': 'Log not found'}), 404
        
        log_data = attack_log.to_dict()
        
        # Include generated signatures if any
        if attack_log.generated_signatures:
            log_data['generatedSignatures'] = [
                sig.to_dict() for sig in attack_log.generated_signatures
            ]
        
        return jsonify(log_data)
        
    except Exception as e:
        logger.error(f"Error retrieving attack log {log_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/logs/<int:log_id>/analyze', methods=['POST'])
def analyze_single_log(log_id):
    """Manually trigger analysis of a specific log."""
    try:
        attack_log = AttackLog.query.get(log_id)
        if not attack_log:
            return jsonify({'error': 'Log not found'}), 404
        
        if attack_log.processed:
            return jsonify({'error': 'Log already processed'}), 400
        
        config = current_app.config.get('SCANNER_CONFIG', {})
        
        # Import services here to avoid circular imports
        from app.services import LogAnalyzer, SignatureGenerator
        
        analyzer = LogAnalyzer(config)
        generator = SignatureGenerator(config)
        
        # Analyze the specific log
        result = analyzer.analyze_single_log(attack_log)
        
        if result:
            # Generate signature from analysis
            signatures = generator.generate_signatures_from_analysis([result])
            
            attack_log.processed = True
            db.session.commit()
            
            return jsonify({
                'message': 'Log analyzed successfully',
                'signatures_generated': len(signatures),
                'analysis_confidence': result.get('confidence', 0),
                'signatures': [sig.to_dict() for sig in signatures]
            })
        else:
            attack_log.processed = True
            db.session.commit()
            
            return jsonify({
                'message': 'Log analyzed but no suspicious patterns found',
                'signatures_generated': 0
            })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error analyzing log {log_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/logs/statistics', methods=['GET'])
def get_log_statistics():
    """Get attack log statistics."""
    try:
        # Time-based counts
        now = datetime.utcnow()
        day_ago = now - timedelta(days=1)
        week_ago = now - timedelta(days=7)
        month_ago = now - timedelta(days=30)
        
        total_logs = AttackLog.query.count()
        logs_today = AttackLog.query.filter(AttackLog.timestamp >= day_ago).count()
        logs_week = AttackLog.query.filter(AttackLog.timestamp >= week_ago).count()
        logs_month = AttackLog.query.filter(AttackLog.timestamp >= month_ago).count()
        
        unprocessed_logs = AttackLog.query.filter_by(processed=False).count()
        
        # Top source IPs
        from sqlalchemy import func
        top_ips = db.session.query(
            AttackLog.source_ip,
            func.count(AttackLog.id).label('count')
        ).group_by(AttackLog.source_ip).order_by(
            func.count(AttackLog.id).desc()
        ).limit(10).all()
        
        # Request method distribution
        method_stats = db.session.query(
            AttackLog.request_method,
            func.count(AttackLog.id).label('count')
        ).group_by(AttackLog.request_method).all()
        
        return jsonify({
            'total_logs': total_logs,
            'logs_today': logs_today,
            'logs_this_week': logs_week,
            'logs_this_month': logs_month,
            'unprocessed_logs': unprocessed_logs,
            'top_source_ips': [{'ip': ip, 'count': count} for ip, count in top_ips],
            'method_distribution': [{'method': method, 'count': count} for method, count in method_stats]
        })
        
    except Exception as e:
        logger.error(f"Error retrieving log statistics: {e}")
        return jsonify({'error': 'Internal server error'}), 500

def _is_baseline_request(log_data):
    """Determine if a request appears to be normal/baseline rather than an attack."""
    request_data = log_data.get('request', {})
    response_data = log_data.get('response', {})
    
    # Simple heuristics for baseline detection
    # Successful response codes are often baseline
    status_code = response_data.get('statusCode', 0)
    if status_code in [200, 301, 302, 304]:
        
        # Check for common attack patterns in URI
        uri = request_data.get('uri', '')
        suspicious_patterns = ["'", '"', '<script>', 'union select', '../', '/etc/', 'cmd.exe']
        
        uri_lower = uri.lower()
        if not any(pattern in uri_lower for pattern in suspicious_patterns):
            # Check user agent for common browsers vs scanners
            user_agent = request_data.get('headers', {}).get('User-Agent', '')
            if any(browser in user_agent for browser in ['Mozilla', 'Chrome', 'Safari', 'Firefox']):
                return True
    
    return False

def _update_baseline_data(log_data):
    """Update baseline response data for normal requests."""
    try:
        request_data = log_data.get('request', {})
        response_data = log_data.get('response', {})
        
        # Extract request pattern
        method = request_data.get('method', 'GET')
        uri = request_data.get('uri', '')
        
        # Parse URI to get path and parameters
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(uri)
        path = parsed.path
        params = parse_qs(parsed.query)
        
        # Update baseline for each parameter
        for param_name in params.keys():
            request_pattern = f"{method} {path}?{param_name}=:param"
            baseline = BaselineResponse.find_or_create_baseline(request_pattern, param_name)
            
            response_info = {
                'status_code': response_data.get('statusCode'),
                'content_length': len(response_data.get('body', '')),
                'response_time_ms': response_data.get('responseTime', 0)
            }
            
            if baseline.sample_count == 0:
                # First sample
                baseline.typical_status_code = response_info['status_code']
                baseline.typical_content_length = response_info['content_length']
                baseline.typical_response_time_ms = response_info['response_time_ms']
            else:
                # Update existing baseline
                baseline.update_with_response(response_info)
        
        db.session.commit()
        
    except Exception as e:
        logger.error(f"Error updating baseline data: {e}")

def _is_high_priority_attack(log_data):
    """Determine if an attack should be processed immediately."""
    request_data = log_data.get('request', {})
    response_data = log_data.get('response', {})
    
    # High priority indicators
    uri = request_data.get('uri', '').lower()
    response_body = response_data.get('body', '').lower()
    
    # SQL injection indicators
    sql_indicators = ['union select', 'drop table', 'mysql_fetch_array']
    if any(indicator in uri or indicator in response_body for indicator in sql_indicators):
        return True
    
    # Command injection indicators  
    cmd_indicators = ['/etc/passwd', 'uid=', 'cmd.exe']
    if any(indicator in uri or indicator in response_body for indicator in cmd_indicators):
        return True
    
    # Error status codes
    if response_data.get('statusCode', 0) in [500, 403]:
        return True
    
    return False