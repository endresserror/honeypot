"""
OWASP ZAP統合API
ZAP用のシグネチャとスクリプトを提供するエンドポイント
"""

import os
import zipfile
from io import BytesIO
from flask import Blueprint, request, jsonify, send_file, current_app
from sqlalchemy import func
from app.models.attack_log import AttackLog
from app.services.zap_signature_generator import ZAPSignatureGenerator
from app import db

zap_bp = Blueprint('zap', __name__)
zap_generator = ZAPSignatureGenerator()


@zap_bp.route('/active-scan-rules', methods=['GET'])
def get_active_scan_rules():
    """アクティブスキャンルールを取得"""
    
    # パラメータ取得
    attack_type = request.args.get('attack_type')
    limit = request.args.get('limit', 10, type=int)
    min_confidence = request.args.get('min_confidence', 0.5, type=float)
    
    # 攻撃ログから高品質なものを取得
    query = db.session.query(AttackLog).filter(
        AttackLog.attackType != 'normal',
        AttackLog.responseStatus != 404
    )
    
    if attack_type:
        query = query.filter(AttackLog.attackType == attack_type)
    
    # 重複を除去し、信頼度の高いものを取得
    attack_logs = query.order_by(AttackLog.timestamp.desc()).limit(limit * 2).all()
    
    # ZAP用ルール生成
    rules = []
    seen_payloads = set()
    
    for log in attack_logs:
        if len(rules) >= limit:
            break
            
        log_dict = log.to_dict()
        payload = zap_generator._extract_payload(log_dict)
        
        if payload in seen_payloads:
            continue
            
        seen_payloads.add(payload)
        
        try:
            rule = zap_generator.generate_zap_active_scan_rule(log_dict)
            rules.append(rule)
        except Exception as e:
            current_app.logger.error(f"Failed to generate rule for log {log.id}: {e}")
    
    return jsonify({
        'rules': rules,
        'total': len(rules),
        'generated_at': func.now(),
        'metadata': {
            'source_logs': len(attack_logs),
            'unique_rules': len(rules)
        }
    })


@zap_bp.route('/passive-scan-rules', methods=['GET'])
def get_passive_scan_rules():
    """パッシブスキャンルールを取得"""
    
    attack_type = request.args.get('attack_type')
    limit = request.args.get('limit', 10, type=int)
    
    # レスポンス内容が豊富な攻撃ログを取得
    query = db.session.query(AttackLog).filter(
        AttackLog.responseBody.isnot(None),
        func.length(AttackLog.responseBody) > 100,
        AttackLog.attackType != 'normal'
    )
    
    if attack_type:
        query = query.filter(AttackLog.attackType == attack_type)
    
    attack_logs = query.order_by(AttackLog.timestamp.desc()).limit(limit * 2).all()
    
    rules = []
    seen_responses = set()
    
    for log in attack_logs:
        if len(rules) >= limit:
            break
            
        log_dict = log.to_dict()
        response_hash = hash(log_dict.get('responseBody', '')[:500])
        
        if response_hash in seen_responses:
            continue
            
        seen_responses.add(response_hash)
        
        try:
            rule = zap_generator.generate_zap_passive_scan_rule(log_dict)
            rules.append(rule)
        except Exception as e:
            current_app.logger.error(f"Failed to generate passive rule for log {log.id}: {e}")
    
    return jsonify({
        'rules': rules,
        'total': len(rules),
        'generated_at': func.now()
    })


@zap_bp.route('/fuzzing-payloads/<attack_type>', methods=['GET'])
def get_fuzzing_payloads(attack_type):
    """特定の攻撃タイプのファジング用ペイロードを取得"""
    
    days_back = request.args.get('days', 30, type=int)
    
    # 指定期間内の攻撃ログを取得
    query = db.session.query(AttackLog).filter(
        AttackLog.attackType == attack_type,
        AttackLog.timestamp >= func.date('now', f'-{days_back} days')
    )
    
    attack_logs = query.all()
    attack_logs_dict = [log.to_dict() for log in attack_logs]
    
    try:
        payload_file = zap_generator.generate_zap_fuzzing_payloads(attack_logs_dict, attack_type)
        
        return jsonify({
            'payload_file': payload_file,
            'generated_at': func.now()
        })
    except Exception as e:
        current_app.logger.error(f"Failed to generate fuzzing payloads for {attack_type}: {e}")
        return jsonify({'error': str(e)}), 500


@zap_bp.route('/context-scripts', methods=['GET'])
def get_context_scripts():
    """認証コンテキストスクリプトを取得"""
    
    # 認証関連のログを取得
    auth_logs = db.session.query(AttackLog).filter(
        AttackLog.uri.contains('login')
    ).limit(100).all()
    
    auth_logs_dict = [log.to_dict() for log in auth_logs]
    
    try:
        context_script = zap_generator.generate_zap_context_script(auth_logs_dict)
        
        if context_script:
            return jsonify({
                'context_script': context_script,
                'generated_at': func.now()
            })
        else:
            return jsonify({
                'message': 'No suitable authentication patterns found',
                'context_script': None
            })
    except Exception as e:
        current_app.logger.error(f"Failed to generate context script: {e}")
        return jsonify({'error': str(e)}), 500


@zap_bp.route('/export/zap-scripts', methods=['GET'])
def export_zap_scripts():
    """ZAP用スクリプトファイル一式をZIPでエクスポート"""
    
    attack_types = request.args.getlist('attack_types') or ['sql_injection', 'xss', 'command_injection']
    include_active = request.args.get('include_active', 'true').lower() == 'true'
    include_passive = request.args.get('include_passive', 'true').lower() == 'true'
    include_fuzzing = request.args.get('include_fuzzing', 'true').lower() == 'true'
    
    # メモリ上でZIPファイルを作成
    zip_buffer = BytesIO()
    
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        
        # READMEファイルを追加
        readme_content = f"""# OWASP ZAP Integration Scripts
Generated from honeypot attack data
Generated at: {func.now()}

## Contents:
- active_scan/: Active scanner rules
- passive_scan/: Passive scanner rules  
- fuzzing/: Fuzzing payload files
- context/: Authentication context scripts

## Usage:
1. Place active/passive scan rules in ZAP's scripts/rules directory
2. Import fuzzing payloads via ZAP's fuzzer
3. Configure authentication using context scripts

## Generated Attack Types:
{', '.join(attack_types)}
"""
        zip_file.writestr('README.md', readme_content)
        
        for attack_type in attack_types:
            
            # アクティブスキャンルール
            if include_active:
                logs = db.session.query(AttackLog).filter(
                    AttackLog.attackType == attack_type
                ).limit(5).all()
                
                for i, log in enumerate(logs):
                    try:
                        rule = zap_generator.generate_zap_active_scan_rule(log.to_dict())
                        zip_file.writestr(
                            f"active_scan/{rule['filename']}",
                            rule['script_content']
                        )
                    except Exception as e:
                        current_app.logger.error(f"Failed to generate active rule: {e}")
            
            # パッシブスキャンルール
            if include_passive:
                logs = db.session.query(AttackLog).filter(
                    AttackLog.attackType == attack_type,
                    AttackLog.responseBody.isnot(None)
                ).limit(3).all()
                
                for i, log in enumerate(logs):
                    try:
                        rule = zap_generator.generate_zap_passive_scan_rule(log.to_dict())
                        zip_file.writestr(
                            f"passive_scan/{rule['filename']}",
                            rule['script_content']
                        )
                    except Exception as e:
                        current_app.logger.error(f"Failed to generate passive rule: {e}")
            
            # ファジングペイロード
            if include_fuzzing:
                logs = db.session.query(AttackLog).filter(
                    AttackLog.attackType == attack_type
                ).limit(50).all()
                
                try:
                    payload_file = zap_generator.generate_zap_fuzzing_payloads(
                        [log.to_dict() for log in logs], 
                        attack_type
                    )
                    zip_file.writestr(
                        f"fuzzing/{payload_file['filename']}",
                        payload_file['content']
                    )
                except Exception as e:
                    current_app.logger.error(f"Failed to generate fuzzing payloads: {e}")
        
        # 認証コンテキスト
        try:
            auth_logs = db.session.query(AttackLog).filter(
                AttackLog.uri.contains('login')
            ).limit(20).all()
            
            context_script = zap_generator.generate_zap_context_script(
                [log.to_dict() for log in auth_logs]
            )
            
            if context_script:
                zip_file.writestr(
                    f"context/{context_script['filename']}",
                    context_script['script_content']
                )
        except Exception as e:
            current_app.logger.error(f"Failed to generate context script: {e}")
    
    zip_buffer.seek(0)
    
    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'zap_scripts_{func.now().strftime("%Y%m%d_%H%M%S")}.zip'
    )


@zap_bp.route('/statistics', methods=['GET'])
def get_zap_statistics():
    """ZAP統合用の統計情報を取得"""
    
    # 基本的な統計（攻撃タイプは動的に判定）
    total_logs = db.session.query(AttackLog).count()
    
    # 最新の攻撃情報
    recent_attacks = db.session.query(AttackLog).order_by(AttackLog.timestamp.desc()).limit(10).all()
    
    # 生成可能なルール数の推定
    potential_active_rules = db.session.query(AttackLog).filter(
        AttackLog.response_status_code != 404
    ).count()
    
    potential_passive_rules = db.session.query(AttackLog).filter(
        AttackLog.response_body.isnot(None),
        func.length(AttackLog.response_body) > 100
    ).count()
    
    return jsonify({
        'total_logs': total_logs,
        'recent_attacks': [
            {
                'id': attack.id,
                'timestamp': attack.timestamp.isoformat() if attack.timestamp else None,
                'source_ip': attack.source_ip,
                'method': attack.request_method,
                'uri': attack.request_uri[:100] + '...' if len(attack.request_uri) > 100 else attack.request_uri
            }
            for attack in recent_attacks
        ],
        'potential_rules': {
            'active_scan': potential_active_rules,
            'passive_scan': potential_passive_rules,
            'total': potential_active_rules + potential_passive_rules
        },
        'generated_at': func.now().isoformat() if hasattr(func.now(), 'isoformat') else str(func.now())
    })