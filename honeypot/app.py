#!/usr/bin/env python3
"""
ハニーポットWebアプリケーション

攻撃者を誘引し、活動をログに記録してシグネチャ生成に利用する
脆弱性を持つWebアプリケーションをシミュレートします。
"""

import os
import sys
import time
import json
import sqlite3
import logging
import threading
from datetime import datetime
from typing import Dict, Any, Optional

from flask import Flask, request, render_template_string, redirect, url_for, jsonify, make_response
import requests
import yaml

# モジュールパスを追加
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from logger import HoneypotLogger
from attack_simulator import AttackSimulator

class HoneypotApplication:
    """メインハニーポットWebアプリケーション"""
    
    def __init__(self, config_path: str = 'config/config.yml'):
        self.config = self._load_config(config_path)
        self.logger = HoneypotLogger(self.config.get('logging', {}))
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = self.config.get('flask', {}).get('secret_key', 'honeypot-secret')
        
        # 攻撃シミュレーターを初期化
        self.attack_simulator = AttackSimulator(self.config)
        
        # ルート設定
        self._setup_routes()
        
        # バックグラウンドログ送信
        self._start_log_submission_thread()
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """ハニーポット設定をロード"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            # デフォルト設定
            return {
                'flask': {'host': '0.0.0.0', 'port': 8080, 'debug': False},
                'mcp_server': {'url': 'http://localhost:5001', 'timeout': 10},
                'logging': {'file': 'logs/honeypot.log', 'level': 'INFO'},
                'simulation': {'enable_vulnerabilities': True}
            }
    
    def _setup_routes(self):
        """ハニーポット用のFlaskルートを設定"""
        
        # リクエスト前処理でログ記録
        @self.app.before_request
        def log_request():
            # リクエスト詳細をログに記録
            request_data = {
                'method': request.method,
                'uri': request.full_path.rstrip('?'),
                'headers': dict(request.headers),
                'body': request.get_data(as_text=True) if request.method in ['POST', 'PUT', 'PATCH'] else None
            }
            
            # レスポンスログ用にリクエストデータを保存
            request.honeypot_data = {
                'timestamp': datetime.utcnow(),
                'source_ip': self._get_client_ip(),
                'request': request_data,
                'start_time': time.time()
            }
        
        # レスポンス後処理でログ記録
        @self.app.after_request
        def log_response(response):
            if hasattr(request, 'honeypot_data'):
                response_time = int((time.time() - request.honeypot_data['start_time']) * 1000)
                
                response_data = {
                    'statusCode': response.status_code,
                    'headers': dict(response.headers),
                    'body': response.get_data(as_text=True)[:10000],  # ボディサイズ制限
                    'responseTime': response_time
                }
                
                # 攻撃パターン検出
                attack_info = self._detect_attack_patterns(
                    request.honeypot_data['request'], 
                    response_data
                )
                
                # Create log entry
                log_entry = {
                    'timestamp': request.honeypot_data['timestamp'].isoformat() + 'Z',
                    'sourceIp': request.honeypot_data['source_ip'],
                    'request': request.honeypot_data['request'],
                    'response': response_data,
                    'attackType': attack_info.get('type', 'unknown'),
                    'attackSeverity': attack_info.get('severity', 'low'),
                    'attackDescription': attack_info.get('description', ''),
                    'suspiciousPayloads': attack_info.get('payloads', []),
                    'heuristicAnomalies': attack_info.get('heuristic_anomalies', {})
                }
                
                # Log the interaction
                self.logger.log_interaction(log_entry)
            
            return response
        
        # Main application routes
        @self.app.route('/')
        def index():
            return self._render_index()
        
        @self.app.route('/account.php')
        def account():
            return self._handle_account_page()
        
        @self.app.route('/transfer.php')
        def transfer():
            return self._handle_transfer_page()
        
        @self.app.route('/admin.php')
        def admin():
            return self._handle_admin()
        
        @self.app.route('/login.php', methods=['GET', 'POST'])
        def login():
            return self._handle_login()
        
        @self.app.route('/logout.php')
        def logout():
            return self._handle_logout()
        
        @self.app.route('/password_reset.php')
        def password_reset():
            return self._handle_password_reset()
        
        @self.app.route('/deposit.php')
        def deposit():
            return self._handle_deposit_page()
        
        @self.app.route('/loan.php')
        def loan():
            return self._handle_loan_page()
        
        @self.app.route('/investment.php')
        def investment():
            return self._handle_investment_page()
        
        @self.app.route('/search.php', methods=['GET', 'POST'])
        def search():
            return self._handle_search()
        
        @self.app.route('/contact.php', methods=['GET', 'POST'])
        def contact():
            return self._handle_contact()
        
        @self.app.route('/account_info.php', methods=['GET', 'POST'])
        def account_info():
            return self._handle_account_info()

        @self.app.route('/api/balance')
        def api_balance():
            return self._handle_api_balance()
        
        # コンテナ用ヘルスチェック
        @self.app.route('/health')
        def health():
            return jsonify({'status': 'healthy', 'service': 'honeypot'})
    
    def _get_client_ip(self) -> str:
        """プロキシを考慮してクライアントIPアドレスを取得"""
        return request.environ.get('HTTP_X_REAL_IP', 
                                 request.environ.get('HTTP_X_FORWARDED_FOR', 
                                 request.remote_addr))
    
    def _detect_attack_patterns(self, request_data: Dict[str, Any], response_data: Dict[str, Any]) -> Dict[str, Any]:
        """リクエスト内の攻撃パターンを検出"""
        attack_info = {
            'type': 'normal',
            'severity': 'low',
            'description': '',
            'payloads': []
        }
        
        # 分析対象のテキストデータを結合
        text_to_analyze = []
        if request_data.get('uri'):
            text_to_analyze.append(request_data['uri'])
        if request_data.get('body'):
            text_to_analyze.append(request_data['body'])
        
        combined_text = ' '.join(text_to_analyze).lower()
        
        # SQL Injection Detection
        sql_patterns = [
            "' or '1'='1", "' or 1=1", "union select", "drop table", 
            "insert into", "delete from", "update set", "' or ''='",
            "' and '1'='1", "' union", "' or 1=1--", "'; drop",
            "' or '1'='1'--", "'||", "' or sleep", "' waitfor delay"
        ]
        
        detected_sql = [pattern for pattern in sql_patterns if pattern in combined_text]
        
        if detected_sql:
            attack_info.update({
                'type': 'sql_injection',
                'severity': 'high',
                'description': f'SQL Injection attack detected with patterns: {", ".join(detected_sql)}',
                'payloads': detected_sql
            })
            return attack_info
        
        # XSS Detection
        xss_patterns = [
            '<script>', '</script>', 'javascript:', 'onerror=', 'onload=',
            'alert(', 'prompt(', 'confirm(', '<iframe', '<object',
            'document.cookie', 'document.write', '<img src=x onerror=',
            '<svg onload=', 'eval(', '<body onload='
        ]
        
        detected_xss = [pattern for pattern in xss_patterns if pattern in combined_text]
        
        if detected_xss:
            attack_info.update({
                'type': 'xss',
                'severity': 'medium',
                'description': f'XSS attack detected with patterns: {", ".join(detected_xss)}',
                'payloads': detected_xss
            })
            return attack_info
        
        # Command Injection Detection (Enhanced)
        cmd_patterns = [
            # Basic command separators
            '; cat', '; ls', '; rm', '; wget', '; curl', '; chmod', '; echo',
            '| cat', '| ls', '| rm', '| wget', '| curl', '| id', '| whoami',
            '&& cat', '&& ls', '&& rm', '&& id', '&& whoami', '&& uname',
            '|| cat', '|| ls', '|| id', '|| whoami', '|| echo',
            
            # Command substitution
            '`cat', '`ls', '`id', '`whoami', '`uname', '`pwd',
            '$(cat', '$(ls', '$(id', '$(whoami', '$(uname', '$(pwd',
            
            # File access attempts
            '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/group',
            '/bin/sh', '/bin/bash', '/bin/cat', '/bin/ls',
            '/usr/bin/', '/sbin/', '/var/log/',
            
            # Windows commands
            '& dir', '& type', '& net', '& ipconfig', '& whoami',
            '&& dir', '&& type', '&& net', '&& ipconfig',
            '|| dir', '|| type', '|| net',
            
            # Encoded attempts
            '%3B', '%7C', '%26%26', '%7C%7C',
            
            # System information gathering
            'uname -a', 'cat /proc/version', 'lsb_release',
            'netstat', 'ps aux', 'mount', 'df -h',
            
            # Network commands
            'ping -c', 'wget http', 'curl http', 'nc -l',
            'telnet', 'ssh', 'scp', 'ftp',
            
            # Process control
            'kill ', 'killall', 'pkill', 'nohup',
            
            # File operations
            'cp /etc/', 'mv /etc/', 'rm -rf', 'chmod 777',
            'chown root', 'sudo ', 'su -'
        ]
        
        detected_cmd = [pattern for pattern in cmd_patterns if pattern in combined_text]
        
        # Enhanced command injection detection with response analysis
        if detected_cmd:
            # Check response for command execution evidence
            response_body = response_data.get('body', '').lower()
            command_evidence = []
            
            # Unix/Linux command output patterns
            unix_evidence = [
                'root:', 'bin/bash', '/etc/passwd', 'uid=', 'gid=',
                'total ', 'drwx', '-rw-', 'lrwx', '/home/', '/var/',
                'linux', 'ubuntu', 'debian', 'centos', 'kernel'
            ]
            
            # Windows command output patterns  
            windows_evidence = [
                'directory of', 'volume serial', '<dir>', 'c:\\windows',
                'system32', 'program files', 'documents and'
            ]
            
            # System information patterns
            system_evidence = [
                'processor', 'architecture', 'hostname', 'domain',
                'network adapter', 'ip address', 'subnet mask'
            ]
            
            # Error patterns (also indicate injection)
            error_evidence = [
                'command not found', 'permission denied', 'no such file',
                'access denied', 'syntax error', 'invalid command',
                'is not recognized', 'bad command'
            ]
            
            # Check all evidence patterns
            for evidence_list, category in [
                (unix_evidence, 'unix_output'),
                (windows_evidence, 'windows_output'), 
                (system_evidence, 'system_info'),
                (error_evidence, 'command_error')
            ]:
                found = [e for e in evidence_list if e in response_body]
                if found:
                    command_evidence.extend(found)
            
            # Determine severity based on evidence
            severity = 'high'
            confidence = 'high'
            
            if command_evidence:
                severity = 'critical'  # Command execution confirmed
                confidence = 'high'
            elif any(pattern in ['`', '$', '&&', '||'] for pattern in detected_cmd):
                severity = 'high'      # High-risk injection patterns
                confidence = 'medium'
            else:
                severity = 'medium'    # Basic injection attempt
                confidence = 'low'
            
            attack_info.update({
                'type': 'command_injection',
                'severity': severity,
                'confidence': confidence,
                'description': f'Command injection attack detected. Patterns: {", ".join(detected_cmd[:3])}. Evidence: {", ".join(command_evidence[:3])}',
                'payloads': detected_cmd,
                'evidence': command_evidence
            })
            return attack_info
        
        # Path Traversal Detection
        path_patterns = [
            '../', '..\\', '%2e%2e%2f', '%2e%2e\\', '....//....',
            '/etc/', '/var/', '/proc/', '/sys/', 'c:\\windows\\',
            '%252e%252e%252f'
        ]
        
        detected_path = [pattern for pattern in path_patterns if pattern in combined_text]
        
        if detected_path:
            attack_info.update({
                'type': 'path_traversal',
                'severity': 'medium',
                'description': f'Path traversal attack detected with patterns: {", ".join(detected_path)}',
                'payloads': detected_path
            })
            return attack_info
        
        # Check for suspicious patterns
        suspicious_patterns = [
            'admin', 'test', 'hack', 'exploit', 'vulnerability',
            'payload', 'bypass', 'injection', '%00', '\x00'
        ]
        
        detected_suspicious = [pattern for pattern in suspicious_patterns if pattern in combined_text]
        
        if detected_suspicious and len(detected_suspicious) > 1:
            attack_info.update({
                'type': 'suspicious',
                'severity': 'low',
                'description': f'Suspicious activity detected: {", ".join(detected_suspicious)}',
                'payloads': detected_suspicious
            })
        
        # Add heuristic-based detection for unknown attacks
        if attack_info.get('type') == 'normal':
            heuristic_result = self._detect_heuristic_anomalies(request_data, response_data)
            if heuristic_result:
                attack_info.update(heuristic_result)
        
        return attack_info
    
    def _detect_heuristic_anomalies(self, request_data, response_data=None):
        """Detect unknown attacks using heuristic analysis."""
        combined_text = ' '.join([
            str(request_data.get('uri', '')),
            str(request_data.get('body', '')),
            str(request_data.get('headers', {}))
        ]).lower()
        
        anomaly_scores = []
        
        # 1. Character frequency analysis
        char_score = self._analyze_character_anomalies(combined_text)
        anomaly_scores.append(('char_freq', char_score))
        
        # 2. Entropy analysis for encoded payloads
        entropy_score = self._calculate_entropy_anomaly(combined_text)
        anomaly_scores.append(('entropy', entropy_score))
        
        # 3. Parameter structure analysis
        param_score = self._analyze_parameter_anomalies(request_data)
        anomaly_scores.append(('param_structure', param_score))
        
        # 4. Length-based anomaly detection
        length_score = self._analyze_length_anomalies(request_data)
        anomaly_scores.append(('length', length_score))
        
        # 5. Behavioral pattern analysis
        behavior_score = self._analyze_behavioral_anomalies(request_data)
        anomaly_scores.append(('behavior', behavior_score))
        anomaly_scores.append(('behavior', behavior_score))
        
        # Calculate overall anomaly score
        total_score = sum(score for _, score in anomaly_scores)
        max_score = len(anomaly_scores) * 1.0
        anomaly_ratio = total_score / max_score if max_score > 0 else 0
        
        # Threshold-based detection (lowered thresholds for testing)
        if anomaly_ratio > 0.3:  # High anomaly (lowered from 0.6)
            return {
                'detected': True,
                'type': 'unknown_attack',
                'severity': 'high',
                'confidence': 'medium',
                'description': f'Heuristic anomaly detection: {anomaly_ratio:.2f} anomaly ratio',
                'heuristic_anomalies': {
                    'overall_score': anomaly_ratio,
                    'details': dict(anomaly_scores),
                    'threshold': 'high'
                }
            }
        elif anomaly_ratio > 0.1:  # Medium anomaly (lowered from 0.4)
            return {
                'detected': True,
                'type': 'suspicious_activity',
                'severity': 'medium',
                'confidence': 'low',
                'description': f'Suspicious pattern detected: {anomaly_ratio:.2f} anomaly ratio',
                'heuristic_anomalies': {
                    'overall_score': anomaly_ratio,
                    'details': dict(anomaly_scores),
                    'threshold': 'medium'
                }
            }
        
        return None
    
    def _analyze_character_anomalies(self, text):
        """Analyze character frequency anomalies."""
        if not text:
            return 0.0
            
        # Common attack characters
        attack_chars = ['<', '>', '&', ';', '|', '`', '$', '%', '\\', '"', "'"]
        attack_char_count = sum(text.count(char) for char in attack_chars)
        
        # Calculate anomaly score based on attack character density
        char_density = attack_char_count / len(text) if len(text) > 0 else 0
        
        # Normalize to 0-1 scale
        if char_density > 0.1:  # > 10% attack characters
            return min(char_density * 5, 1.0)
        return char_density * 2
    
    def _calculate_entropy_anomaly(self, text):
        """Calculate entropy to detect encoded/obfuscated payloads."""
        if not text or len(text) < 10:
            return 0.0
            
        import math
        
        # Calculate character frequency
        char_freq = {}
        for char in text:
            char_freq[char] = char_freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_length = len(text)
        for count in char_freq.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        # High entropy indicates possible encoding/obfuscation
        # Normal text entropy: 3-4, encoded data: 5-8
        if entropy > 5.0:
            return min((entropy - 3.0) / 5.0, 1.0)
        return 0.0
    
    def _analyze_parameter_anomalies(self, request_data):
        """Analyze parameter structure for anomalies."""
        anomaly_score = 0.0
        
        # Check for unusual parameter names
        uri = str(request_data.get('uri', ''))
        body = str(request_data.get('body', '') or '')
        
        # Extract parameters
        import re
        param_pattern = r'([^&=?]+)=([^&]*)'
        params = re.findall(param_pattern, uri + '&' + body)
        
        if params:
            for name, value in params:
                # Check for suspicious parameter names
                suspicious_names = ['cmd', 'exec', 'eval', 'system', 'shell', 'debug']
                if any(sus in name.lower() for sus in suspicious_names):
                    anomaly_score += 0.3
                
                # Check for unusually long parameter values
                if len(value) > 200:
                    anomaly_score += 0.2
                
                # Check for multiple special characters in value
                special_chars = ['<', '>', '&', ';', '|', '`', '$', '%']
                special_count = sum(value.count(char) for char in special_chars)
                if special_count > 5:
                    anomaly_score += 0.2
        
        return min(anomaly_score, 1.0)
    
    def _analyze_length_anomalies(self, request_data):
        """Detect unusual request lengths."""
        uri = str(request_data.get('uri', ''))
        body = str(request_data.get('body', '') or '')
        
        # Calculate total request size
        total_length = len(uri) + len(body)
        
        # Very long requests are suspicious
        if total_length > 2000:
            return min(total_length / 5000.0, 1.0)
        elif total_length > 1000:
            return total_length / 10000.0
        
        return 0.0
    
    def _analyze_behavioral_anomalies(self, request_data):
        """Analyze behavioral patterns."""
        anomaly_score = 0.0
        
        uri = str(request_data.get('uri', '')).lower()
        body = str(request_data.get('body', '') or '').lower()
        combined = uri + ' ' + body
        
        # Check for rapid sequential special characters
        sequential_patterns = ['--', '||', '&&', ';;', '>>']
        for pattern in sequential_patterns:
            if pattern in combined:
                anomaly_score += 0.2
        
        # Check for encoding patterns
        encoding_patterns = ['%20', '%3d', '%3c', '%3e', '\\x', '\\u']
        encoding_count = sum(combined.count(pattern) for pattern in encoding_patterns)
        if encoding_count > 3:
            anomaly_score += 0.3
        
        # Check for mixed case evasion attempts  
        mixed_case_patterns = ['SeLeCt', 'UnIoN', 'ScRiPt', 'AlErT']
        for pattern in mixed_case_patterns:
            if pattern.lower() in combined:
                anomaly_score += 0.2
        
        return min(anomaly_score, 1.0)
    
    def _is_logged_in(self) -> bool:
        """Check if user is logged in."""
        session_token = request.cookies.get('session_token')
        auth_header = request.headers.get('Authorization')
        demo_mode = request.args.get('demo') == 'true'
        
        return session_token or auth_header or demo_mode
    
    def _get_navigation_html(self) -> str:
        """Get navigation HTML with login/logout links."""
        if self._is_logged_in():
            return """
            <div class="nav">
                <div class="nav-content">
                    <a href="/">ホーム</a>
                    <a href="/account.php">口座照会</a>
                    <a href="/transfer.php">振込・振替</a>
                    <a href="/loan.php">ローン</a>
                    <a href="/investment.php">投資商品</a>
                    <a href="/logout.php" style="float: right; background: #dc3545;">ログアウト</a>
                </div>
            </div>
            """
        else:
            return """
            <div class="nav">
                <div class="nav-content">
                    <a href="/">ホーム</a>
                    <a href="/loan.php">ローン</a>
                    <a href="/investment.php">投資商品</a>
                    <a href="/login.php" style="float: right; background: #28a745;">ログイン</a>
                </div>
            </div>
            """
    
    def _render_index(self) -> str:
        """Render main index page."""
        return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>鳩松Bank - インターネットバンキング</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Hiragino Kaku Gothic ProN', 'Yu Gothic', 'Meiryo', sans-serif; background: #f5f5f5; }
        .header { background: #003f7f; color: white; padding: 15px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header-content { max-width: 1200px; margin: 0 auto; padding: 0 20px; display: flex; align-items: center; justify-content: space-between; }
        .logo { font-size: 24px; font-weight: bold; }
        .nav { background: #004a94; padding: 10px 0; }
        .nav-content { max-width: 1200px; margin: 0 auto; padding: 0 20px; }
        .nav a { color: white; text-decoration: none; margin-right: 30px; padding: 8px 15px; border-radius: 3px; transition: background 0.3s; }
        .nav a:hover { background: rgba(255,255,255,0.1); }
        .main-content { max-width: 1200px; margin: 30px auto; padding: 0 20px; }
        .welcome-box { background: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 30px; }
        .services-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .service-card { background: white; padding: 25px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); text-align: center; }
        .service-card h3 { color: #003f7f; margin-bottom: 15px; font-size: 18px; }
        .service-card p { color: #666; line-height: 1.6; margin-bottom: 15px; }
        .btn { display: inline-block; background: #003f7f; color: white; padding: 12px 25px; text-decoration: none; border-radius: 3px; font-weight: bold; transition: background 0.3s; }
        .btn:hover { background: #002856; }
        .login-form { background: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; margin: 0 auto; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 5px; color: #333; font-weight: bold; }
        .form-group input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 3px; font-size: 14px; }
        .security-notice { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 3px; margin-bottom: 20px; }
        .footer { background: #333; color: white; text-align: center; padding: 20px 0; margin-top: 50px; }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="logo">鳩松Bank</div>
            <div style="font-size: 12px;">インターネットバンキング</div>
        </div>
    </div>
    
    <div class="nav">
        <div class="nav-content">
            <a href="/">ホーム</a>
            <a href="/account.php">口座照会</a>
            <a href="/transfer.php">振込・振替</a>
            <a href="/loan.php">ローン</a>
            <a href="/investment.php">投資信託</a>
            """ + ('<a href="/logout.php" style="float: right; background: #dc3545;">ログアウト</a>' if self._is_logged_in() else '<a href="/login.php" style="float: right; background: #28a745;">ログイン</a>') + """
        </div>
    </div>

    <div class="main-content">
        <div class="welcome-box">
            <h2 style="color: #003f7f; margin-bottom: 20px;">鳩松ダイレクトへようこそ</h2>
            <p style="line-height: 1.6; color: #666;">
                インターネットバンキングサービスをご利用いただき、ありがとうございます。<br>
                24時間365日、残高照会や振込などの銀行取引をご利用いただけます。
            </p>
        </div>

        <div class="services-grid">
            <div class="service-card">
                <h3>口座残高照会</h3>
                <p>普通預金・定期預金の残高をリアルタイムで確認できます。</p>
                <a href="/account.php" class="btn">残高照会</a>
            </div>
            
            <div class="service-card">
                <h3>振込・振替</h3>
                <p>他行あて振込や口座間振替がオンラインで簡単に行えます。</p>
                <a href="/transfer.php" class="btn">振込・振替</a>
            </div>
            
            <div class="service-card">
                <h3>定期預金</h3>
                <p>お得な金利の定期預金の新規作成・解約ができます。</p>
                <a href="/deposit.php" class="btn">定期預金</a>
            </div>
        </div>

        <div class="login-form">
            """ + ("""
            <h3 style="text-align: center; margin-bottom: 25px; color: #28a745;">ログイン済み</h3>
            <p style="text-align: center; color: #666;">現在ログイン中です。上記のサービスをご利用いただけます。</p>
            <div style="text-align: center; margin-top: 20px;">
                <a href="/logout.php" class="btn" style="background: #dc3545;">ログアウト</a>
            </div>
            """ if self._is_logged_in() else """
            <h3 style="text-align: center; margin-bottom: 25px; color: #003f7f;">ログイン</h3>
            
            <div class="security-notice">
                <strong>セキュリティのお知らせ</strong><br>
                ログイン時は必ずアドレスバーのURLをご確認ください。
            </div>
            
            <form action="/login.php" method="POST">
                <div class="form-group">
                    <label for="customer_number">お客様番号</label>
                    <input type="text" id="customer_number" name="customer_number" placeholder="10桁の数字を入力">
                </div>
                
                <div class="form-group">
                    <label for="login_password">ログインパスワード</label>
                    <input type="password" id="login_password" name="login_password" placeholder="ログインパスワードを入力">
                </div>
                
                <div class="form-group">
                    <input type="submit" value="ログイン" class="btn" style="width: 100%; cursor: pointer; border: none;">
                </div>
            </form>
            
            <div style="text-align: center; margin-top: 20px;">
                <a href="/password_reset.php" style="color: #003f7f; text-decoration: none;">パスワードを忘れた方</a> | 
                <a href="/register.php" style="color: #003f7f; text-decoration: none;">初回登録</a>
            </div>
            """) + """
        </div>
    </div>

    <div class="footer">
        <p>&copy; 2024 株式会社鳩松Bank All Rights Reserved.</p>
    </div>
</body>
</html>
        """)
    
    def _handle_account_page(self) -> str:
        """Handle account page - requires login and vulnerable to SQL injection."""
        
        # Check if user is logged in (check for session or basic auth)
        logged_in_user = request.args.get('id')
        auth_header = request.headers.get('Authorization', '')
        session_token = request.cookies.get('session_token')
        
        # Redirect to login if not authenticated
        if not logged_in_user and not auth_header and not session_token:
            return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>認証が必要です - 鳩松Bank</title>
    <style>
        body { font-family: 'Yu Gothic', 'Meiryo', sans-serif; margin: 0; background: #f5f5f5; }
        .header { background: #003f7f; color: white; padding: 15px 0; text-align: center; }
        .container { max-width: 500px; margin: 50px auto; padding: 30px; background: white; border-radius: 5px; text-align: center; }
        .warning { color: #d32f2f; margin-bottom: 20px; font-size: 18px; }
        .btn { background: #003f7f; color: white; padding: 12px 30px; text-decoration: none; border-radius: 3px; display: inline-block; margin: 10px; }
        .security-note { background: #fff3cd; padding: 15px; margin-top: 20px; border-radius: 3px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>鳩松Bank</h1>
    </div>
    <div class="container">
        <div class="warning">
            ⚠️ この機能をご利用いただくには、ログインが必要です
        </div>
        <p>口座照会をご利用いただくためには、お客様番号とパスワードによる認証が必要です。</p>
        
        <a href="/login.php" class="btn">ログインする</a>
        <a href="/" class="btn" style="background: #666;">ホームに戻る</a>
        
        <div class="security-note">
            <strong>セキュリティについて</strong><br>
            お客様の大切な口座情報を保護するため、ログイン認証を行っております。
        </div>
    </div>
</body>
</html>
            """)
        
        account_id = logged_in_user or '1'
        
        # Simulate database lookup with intentional SQL injection vulnerability
        if self.config.get('simulation', {}).get('enable_vulnerabilities', True):
            # Check for common SQL injection patterns and simulate responses
            if "'" in account_id or 'union' in account_id.lower() or 'select' in account_id.lower():
                # Simulate SQL error
                return render_template_string("""
<html><body>
<h1>Database Error</h1>
<pre>
Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /var/www/html/account.php on line 45

SQL Query: SELECT * FROM accounts WHERE customer_id = '{{ account_id }}'
MySQL Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{{ account_id }}' at line 1
</pre>
</body></html>
                """, account_id=account_id), 500
        
        # Normal account page
        return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>口座照会 - 鳩松Bank</title>
    <style>
        body { font-family: 'Yu Gothic', 'Meiryo', sans-serif; margin: 0; background: #f5f5f5; }
        .header { background: #003f7f; color: white; padding: 15px 0; }
        .header h1 { margin: 0; text-align: center; }
        .container { max-width: 800px; margin: 20px auto; padding: 20px; }
        .account-info { background: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .balance { font-size: 18px; font-weight: bold; color: #003f7f; }
    </style>
</head>
<body>
    <div class="header">
        <h1>口座照会</h1>
    </div>
    <div class="container">
        <div class="account-info">
            <h3>普通預金口座</h3>
            <table>
                <tr><th>口座番号</th><td>{{ account_id }}1234567</td></tr>
                <tr><th>口座名義</th><td>ミズホ　タロウ</td></tr>
                <tr><th>残高</th><td class="balance">￥1,234,567</td></tr>
                <tr><th>最終更新</th><td>2024-08-14 18:30</td></tr>
            </table>
        </div>
        <a href="/" style="color: #003f7f;">ホームに戻る</a>
    </div>
</body>
</html>
        """, account_id=account_id)
    
    def _handle_transfer_page(self) -> str:
        """Handle transfer functionality - requires login and vulnerable to XSS."""
        
        # Check if user is logged in
        logged_in_user = request.args.get('user_id')
        auth_header = request.headers.get('Authorization', '')
        session_token = request.cookies.get('session_token')
        
        # Redirect to login if not authenticated
        if not logged_in_user and not auth_header and not session_token:
            return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>認証が必要です - 鳩松Bank</title>
    <style>
        body { font-family: 'Yu Gothic', 'Meiryo', sans-serif; margin: 0; background: #f5f5f5; }
        .header { background: #003f7f; color: white; padding: 15px 0; text-align: center; }
        .container { max-width: 500px; margin: 50px auto; padding: 30px; background: white; border-radius: 5px; text-align: center; }
        .warning { color: #d32f2f; margin-bottom: 20px; font-size: 18px; }
        .btn { background: #003f7f; color: white; padding: 12px 30px; text-decoration: none; border-radius: 3px; display: inline-block; margin: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>鳩松Bank</h1>
    </div>
    <div class="container">
        <div class="warning">
            ⚠️ この機能をご利用いただくには、ログインが必要です
        </div>
        <p>振込・振替機能をご利用いただくためには、お客様番号とパスワードによる認証が必要です。</p>
        
        <a href="/login.php" class="btn">ログインする</a>
        <a href="/" class="btn" style="background: #666;">ホームに戻る</a>
    </div>
</body>
</html>
            """)
        
        query = request.args.get('search', '')
        
        # Intentionally vulnerable to XSS
        return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>振込・振替 - 鳩松Bank</title>
    <style>
        body { font-family: 'Yu Gothic', 'Meiryo', sans-serif; margin: 0; background: #f5f5f5; }
        .header { background: #003f7f; color: white; padding: 15px 0; }
        .header h1 { margin: 0; text-align: center; }
        .container { max-width: 600px; margin: 20px auto; padding: 20px; }
        .form-container { background: white; padding: 30px; border-radius: 5px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input, select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 3px; }
        .btn { background: #003f7f; color: white; padding: 12px 30px; border: none; border-radius: 3px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="header">
        <h1>振込・振替</h1>
    </div>
    <div class="container">
        {% if query %}
        <div style="background: #f8f9fa; padding: 10px; margin-bottom: 20px; border-radius: 3px;">
            検索結果: {{ query|safe }}
        </div>
        {% endif %}
        <div class="form-container">
            <h3>振込先指定</h3>
            <form method="POST">
                <div class="form-group">
                    <label>金融機関コード</label>
                    <input type="text" name="bank_code" placeholder="4桁の数字" maxlength="4">
                </div>
                <div class="form-group">
                    <label>支店コード</label>
                    <input type="text" name="branch_code" placeholder="3桁の数字" maxlength="3">
                </div>
                <div class="form-group">
                    <label>口座番号</label>
                    <input type="text" name="account_number" placeholder="口座番号">
                </div>
                <div class="form-group">
                    <label>振込金額</label>
                    <input type="number" name="amount" placeholder="金額を入力">
                </div>
                <input type="submit" value="振込実行" class="btn">
            </form>
        </div>
        <div style="margin-top: 20px;">
            <a href="/" style="color: #003f7f;">ホームに戻る</a>
        </div>
    </div>
</body>
</html>
        """, query=query)
    
    def _handle_admin(self) -> str:
        """Handle admin page - check for authentication bypass."""
        auth = request.args.get('auth', '')
        
        if auth == 'admin' or 'admin' in request.headers.get('User-Agent', '').lower():
            return render_template_string("""
<html><body>
<h1>Admin Panel</h1>
<p>Welcome, Administrator!</p>
<p>System Status: Online</p>
<p>Users: 1,234</p>
<p>Orders: 5,678</p>
</body></html>
            """)
        else:
            return render_template_string("""
<html><body>
<h1>Access Denied</h1>
<p>Admin access required.</p>
<a href="/login.php">Login</a>
</body></html>
            """), 403
    
    def _handle_login(self) -> str:
        """Handle login functionality."""
        if request.method == 'POST':
            customer_number = request.form.get('customer_number', '')
            password = request.form.get('login_password', '')
            
            # Check for SQL injection attempts
            sql_injection_detected = any(pattern in (customer_number + ' ' + password).lower() for pattern in [
                "' or '1'='1", "' or 1=1", "union select", "-- ", "' or ''='",
                "' and '1'='1", "' union", "' or 1=1--", "'||", "drop table"
            ])
            
            if sql_injection_detected:
                # Return a SQL error response to make the attack look successful
                return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>データベースエラー - 鳩松Bank</title>
    <style>
        body { font-family: monospace; margin: 20px; background: #f0f0f0; }
        .error { background: #ffebee; border: 1px solid #f44336; padding: 15px; margin: 20px 0; }
        .debug { background: #e3f2fd; border: 1px solid #2196f3; padding: 15px; margin: 20px 0; }
        pre { background: #263238; color: #fff; padding: 15px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>💻 システムエラー - 鳩松Bank</h1>
    
    <div class="error">
        <strong>⚠️ データベースエラーが発生しました</strong><br>
        Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /var/www/html/login.php on line 127
    </div>
    
    <div class="debug">
        <strong>🔍 デバッグ情報:</strong><br>
        <pre>SQL Query: SELECT customer_id, customer_name, account_balance FROM customers WHERE customer_number = '{{ customer_number }}' AND password = MD5('{{ password }}')</pre>
        
        <pre>MySQL Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{{ customer_number }}' at line 1</pre>
        
        <p><strong>データベース接続情報:</strong></p>
        <ul>
            <li>Server: db.hatomatu-bank.internal</li>
            <li>Database: customers_prod</li>
            <li>User: webapp_user</li>
            <li>Affected rows: 0</li>
        </ul>
        
        <p><strong>🚨 セキュリティ警告:</strong> 不正なSQL文が検出されました。システム管理者に通知されました。</p>
    </div>
    
    <div style="margin-top: 30px;">
        <a href="/login.php" style="background: #003f7f; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px;">再度ログイン</a>
        <a href="/" style="background: #666; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px; margin-left: 10px;">ホームに戻る</a>
    </div>
</body>
</html>
                """, customer_number=customer_number, password=password), 500
            
            # Simulate authentication
            if customer_number == '1234567890' and password == 'password123':
                # Create response with session cookie
                response = redirect('/account.php?id=' + customer_number)
                response.set_cookie('session_token', f'session_{customer_number}', max_age=3600)  # 1 hour
                return response
            elif customer_number and password:  # Basic credentials for testing
                # Allow basic login for demonstration
                response = redirect('/account.php?id=' + customer_number)
                response.set_cookie('session_token', f'session_{customer_number}', max_age=3600)
                return response
            else:
                return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>ログインエラー - 鳩松Bank</title>
    <style>
        body { font-family: 'Yu Gothic', 'Meiryo', sans-serif; margin: 0; background: #f5f5f5; }
        .container { max-width: 400px; margin: 100px auto; padding: 30px; background: white; border-radius: 5px; text-align: center; }
        .error { color: #d32f2f; margin-bottom: 20px; }
        .btn { background: #003f7f; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>ログインエラー</h2>
        <div class="error">お客様番号またはパスワードが正しくありません。</div>
        <a href="/login.php" class="btn">再度ログイン</a>
    </div>
</body>
</html>
                """)
        
        return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>ログイン - 鳩松Bank</title>
    <style>
        body { font-family: 'Yu Gothic', 'Meiryo', sans-serif; margin: 0; background: #f5f5f5; }
        .header { background: #003f7f; color: white; padding: 15px 0; text-align: center; }
        .container { max-width: 400px; margin: 30px auto; padding: 30px; background: white; border-radius: 5px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"] { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 3px; }
        .btn { width: 100%; padding: 12px; background: #003f7f; color: white; border: none; border-radius: 3px; font-size: 16px; cursor: pointer; }
        .security-notice { background: #fff3cd; padding: 15px; border-radius: 3px; margin-bottom: 20px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>鳩松ダイレクト ログイン</h1>
    </div>
    <div class="container">
        <div class="security-notice">
            <strong>重要:</strong> フィッシングサイトにご注意ください。URLを必ずご確認ください。
        </div>
        <form method="POST">
            <div class="form-group">
                <label for="customer_number">お客様番号（10桁）</label>
                <input type="text" id="customer_number" name="customer_number" maxlength="10" required>
            </div>
            <div class="form-group">
                <label for="login_password">ログインパスワード</label>
                <input type="password" id="login_password" name="login_password" required>
            </div>
            <input type="submit" value="ログイン" class="btn">
        </form>
        <div style="text-align: center; margin-top: 20px;">
            <a href="/" style="color: #003f7f;">トップページに戻る</a>
        </div>
    </div>
</body>
</html>
        """)
    
    def _handle_file_view(self) -> str:
        """Handle file viewing - vulnerable to LFI."""
        filename = request.args.get('file', 'welcome.txt')
        
        # Simulate file inclusion vulnerability
        if '../' in filename or filename.startswith('/'):
            if '/etc/passwd' in filename:
                return render_template_string("""
<pre>
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
</pre>
                """)
            elif 'boot.ini' in filename:
                return render_template_string("""
<pre>
[boot loader]
timeout=30
default=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS
[operating systems]
multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS="Microsoft Windows XP Professional"
</pre>
                """)
        
        # Normal file content
        return render_template_string("""
<html><body>
<h1>File: {{ filename }}</h1>
<pre>
Welcome to SecureShop!
This is a sample text file.
File viewing functionality.
</pre>
</body></html>
        """, filename=filename)
    
    def _handle_upload(self) -> str:
        """Handle file upload functionality."""
        if request.method == 'POST':
            return render_template_string("""
<html><body>
<h1>File Uploaded</h1>
<p>Your file has been uploaded successfully.</p>
</body></html>
            """)
        
        return render_template_string("""
<!DOCTYPE html>
<html>
<head><title>Upload - SecureShop</title></head>
<body>
    <h1>File Upload</h1>
    <form method="POST" enctype="multipart/form-data">
        <p>Choose file: <input type="file" name="file"></p>
        <p><input type="submit" value="Upload"></p>
    </form>
</body>
</html>
        """)
    
    def _handle_debug(self) -> str:
        """Handle debug page - information disclosure."""
        debug_info = request.args.get('debug', '')
        
        if debug_info:
            return render_template_string("""
<html><body>
<h1>Debug Information</h1>
<pre>
PHP Version: 7.4.3
MySQL Version: 8.0.23
Server: Apache/2.4.41
Document Root: /var/www/html
DEBUG: {{ debug_info }}

Environment Variables:
DB_HOST=localhost
DB_USER=root
DB_PASS=password123
SECRET_KEY=supersecret
</pre>
</body></html>
            """, debug_info=debug_info)
        
        return render_template_string("""
<html><body>
<h1>Debug Mode</h1>
<p>Add ?debug=info to see debug information.</p>
</body></html>
        """)
    
    def _handle_password_reset(self) -> str:
        """Handle password reset page."""
        return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>パスワード再設定 - 鳩松Bank</title>
    <style>
        body { font-family: 'Yu Gothic', 'Meiryo', sans-serif; margin: 0; background: #f5f5f5; }
        .header { background: #003f7f; color: white; padding: 15px 0; text-align: center; }
        .container { max-width: 500px; margin: 30px auto; padding: 30px; background: white; border-radius: 5px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 3px; }
        .btn { width: 100%; padding: 12px; background: #003f7f; color: white; border: none; border-radius: 3px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="header">
        <h1>パスワード再設定</h1>
    </div>
    <div class="container">
        <p>お客様番号とご登録の電話番号を入力してください。</p>
        <form method="POST">
            <div class="form-group">
                <label>お客様番号</label>
                <input type="text" name="customer_number" maxlength="10" required>
            </div>
            <div class="form-group">
                <label>電話番号</label>
                <input type="tel" name="phone_number" required>
            </div>
            <input type="submit" value="認証する" class="btn">
        </form>
        <div style="text-align: center; margin-top: 20px;">
            <a href="/login.php" style="color: #003f7f;">ログインに戻る</a>
        </div>
    </div>
</body>
</html>
        """)
    
    def _handle_deposit_page(self) -> str:
        """Handle deposit page."""
        return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>定期預金 - 鳩松Bank</title>
    <style>
        body { font-family: 'Yu Gothic', 'Meiryo', sans-serif; margin: 0; background: #f5f5f5; }
        .header { background: #003f7f; color: white; padding: 15px 0; text-align: center; }
        .container { max-width: 800px; margin: 30px auto; padding: 30px; }
        .product-card { background: white; padding: 25px; margin-bottom: 20px; border-radius: 5px; }
        .rate { font-size: 24px; color: #d32f2f; font-weight: bold; }
        .btn { background: #003f7f; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>定期預金商品</h1>
    </div>
    <div class="container">
        <div class="product-card">
            <h3>スーパー定期300</h3>
            <div class="rate">年0.002%</div>
            <p>預入期間: 1ヶ月〜10年<br>最低預入金額: 300万円以上</p>
            <a href="#" class="btn">詳細・申込</a>
        </div>
        <div class="product-card">
            <h3>大口定期預金</h3>
            <div class="rate">年0.003%</div>
            <p>預入期間: 1ヶ月〜10年<br>最低預入金額: 1,000万円以上</p>
            <a href="#" class="btn">詳細・申込</a>
        </div>
    </div>
</body>
</html>
        """)
    
    def _handle_loan_page(self) -> str:
        """Handle loan page."""
        return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>ローン - 鳩松Bank</title>
    <style>
        body { font-family: 'Yu Gothic', 'Meiryo', sans-serif; margin: 0; background: #f5f5f5; }
        .header { background: #003f7f; color: white; padding: 15px 0; text-align: center; }
        .container { max-width: 800px; margin: 30px auto; padding: 30px; }
        .loan-card { background: white; padding: 25px; margin-bottom: 20px; border-radius: 5px; }
        .rate { font-size: 20px; color: #d32f2f; font-weight: bold; }
        .btn { background: #003f7f; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>各種ローン</h1>
    </div>
    <div class="container">
        <div class="loan-card">
            <h3>住宅ローン</h3>
            <div class="rate">年0.375%〜</div>
            <p>新規お借入れ・お借換えどちらでもご利用いただけます。</p>
            <a href="#" class="btn">詳細・申込</a>
        </div>
        <div class="loan-card">
            <h3>カードローン</h3>
            <div class="rate">年2.0%〜14.0%</div>
            <p>WEBで完結、来店不要でお申し込みいただけます。</p>
            <a href="#" class="btn">詳細・申込</a>
        </div>
    </div>
</body>
</html>
        """)
    
    def _handle_logout(self) -> str:
        """Handle logout page."""
        response = make_response(render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>ログアウト完了 - 鳩松Bank</title>
    <style>
        body { font-family: 'Yu Gothic', 'Meiryo', sans-serif; margin: 0; background: #f5f5f5; }
        .header { background: #003f7f; color: white; padding: 15px 0; }
        .header h1 { margin: 0; text-align: center; }
        .container { max-width: 600px; margin: 50px auto; padding: 20px; }
        .logout-message { background: white; padding: 40px; border-radius: 5px; text-align: center; }
        .success-icon { font-size: 48px; color: #28a745; margin-bottom: 20px; }
        .btn { display: inline-block; background: #003f7f; color: white; padding: 12px 24px; 
               text-decoration: none; border-radius: 5px; margin: 10px; }
        .btn:hover { background: #002f5f; }
    </style>
</head>
<body>
    <div class="header">
        <h1>鳩松Bank インターネットバンキング</h1>
    </div>
    <div class="container">
        <div class="logout-message">
            <div class="success-icon">✓</div>
            <h2>ログアウトしました</h2>
            <p>セキュリティのため、ブラウザを閉じることをお勧めします。</p>
            <p>ご利用ありがとうございました。</p>
            
            <a href="/" class="btn">ホームページに戻る</a>
            <a href="/login.php" class="btn">再ログインする</a>
        </div>
    </div>
</body>
</html>
        """))
        
        # セッションクッキーを削除
        response.set_cookie('session_token', '', expires=0)
        return response
    
    def _handle_investment_page(self) -> str:
        """Handle investment page."""
        return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>投資信託 - 鳩松Bank</title>
    <style>
        body { font-family: 'Yu Gothic', 'Meiryo', sans-serif; margin: 0; background: #f5f5f5; }
        .header { background: #003f7f; color: white; padding: 15px 0; text-align: center; }
        .container { max-width: 800px; margin: 30px auto; padding: 30px; }
        .fund-card { background: white; padding: 25px; margin-bottom: 20px; border-radius: 5px; }
        .performance { color: #27ae60; font-weight: bold; }
        .btn { background: #003f7f; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>投資信託</h1>
    </div>
    <div class="container">
        <div class="fund-card">
            <h3>鳩松日本株ファンド</h3>
            <div class="performance">前年度実績: +12.5%</div>
            <p>日本の優良企業に分散投資するファンドです。</p>
            <a href="#" class="btn">詳細・購入</a>
        </div>
        <div class="fund-card">
            <h3>グローバル債券ファンド</h3>
            <div class="performance">前年度実績: +3.8%</div>
            <p>世界各国の債券に投資し、安定した収益を目指します。</p>
            <a href="#" class="btn">詳細・購入</a>
        </div>
    </div>
</body>
</html>
        """)

    def _handle_api_balance(self) -> str:
        """Handle API balance endpoint."""
        account_id = request.args.get('id', '1')
        
        # Simulate API response
        return jsonify({
            'account_id': account_id,
            'balance': 1234567,
            'currency': 'JPY',
            'last_updated': '2024-08-14T18:30:00Z'
        })
    
    def _start_log_submission_thread(self):
        """Start background thread for submitting logs to MCP Server."""
        def submit_logs():
            while True:
                try:
                    time.sleep(10)  # Submit every 10 seconds
                    self.logger.submit_pending_logs()
                except Exception as e:
                    print(f"Log submission error: {e}")
        
        thread = threading.Thread(target=submit_logs, daemon=True)
        thread.start()
    
    def _handle_search(self) -> str:
        """Handle search functionality - vulnerable to XSS and Command Injection."""
        query = request.args.get('query', '') or request.form.get('query', '')
        
        if query:
            # Enhanced command injection patterns for better detection
            cmd_patterns = [
                # Basic separators
                '; cat', '| ls', '&& whoami', '|| id', '; ls', '| cat', '&& cat', '|| cat',
                '`cat', '$(cat', '`ls', '$(ls)', '`whoami', '$(whoami)', '`id', '$(id)',
                '; uname', '| uname', '&& uname', '|| uname', '`uname', '$(uname)',
                
                # File access commands
                '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/hosts', '/etc/hostname',
                '/proc/version', '/etc/os-release', 'cat /etc/', 'cat /proc/', 'cat /var/',
                
                # Network commands  
                'netstat', 'ifconfig', 'ping -c', 'route -n', 'arp -a', 'ss -', 'ip addr',
                
                # System information
                'uname -a', 'uname -m', 'hostname', 'uptime', 'w', 'ps aux', 'ps -ef',
                'lsb_release', 'systemctl', 'service --status-all',
                
                # Directory operations
                'ls -la', 'ls -l', 'ls /home', 'ls /var', 'ls /etc', 'ls /tmp',
                'find /', 'find /etc', 'find /var', 'find /home',
                
                # Dangerous commands
                'rm -rf', 'chmod 777', 'chown root', 'sudo ', 'su -', 'passwd',
                'useradd', 'userdel', 'usermod', 'groupadd',
                
                # Windows commands
                'dir c:', 'type c:', 'net user', 'ipconfig', 'systeminfo', 'tasklist',
                'wmic', 'powershell', 'cmd.exe', 'rundll32',
                
                # Network/download commands
                'curl http', 'wget http', 'nc -l', 'netcat', 'telnet', 'ssh',
                'scp ', 'rsync', 'ftp'
            ]
            
            cmd_detected = any(pattern in query.lower() for pattern in cmd_patterns)
            
            if cmd_detected:
                # Enhanced command execution output simulation for honeypot
                fake_outputs = {
                    # Basic file commands
                    'cat /etc/passwd': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
                    'cat /etc/shadow': 'cat: /etc/shadow: Permission denied',
                    'cat /etc/group': 'root:x:0:\ndaemon:x:1:\nbin:x:2:\nsys:x:3:\nadm:x:4:\nwww-data:x:33:',
                    'cat /proc/version': 'Linux version 5.4.0-74-generic (buildd@lcy01-amd64-030) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021',
                    'cat /etc/os-release': 'NAME="Ubuntu"\nVERSION="20.04.2 LTS (Focal Fossa)"\nID=ubuntu\nID_LIKE=debian',
                    'cat /etc/hostname': 'webserver',
                    
                    # User and process commands
                    'whoami': 'www-data',
                    'id': 'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
                    'w': ' 10:15:23 up  2:34,  1 user,  load average: 0.08, 0.02, 0.01\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nwww-data pts/0    192.168.1.10     09:45    0.00s  0.04s  0.00s w',
                    'ps aux': 'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1  22092  3396 ?        Ss   07:40   0:01 /sbin/init\nwww-data  1234  0.0  0.5  55416 11284 ?        S    09:45   0:00 python3 app.py',
                    
                    # System information
                    'uname -a': 'Linux webserver 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux',
                    'uname -m': 'x86_64',
                    'hostname': 'webserver',
                    'uptime': ' 10:15:23 up  2:34,  1 user,  load average: 0.08, 0.02, 0.01',
                    'lsb_release -a': 'Distributor ID:\tUbuntu\nDescription:\tUbuntu 20.04.2 LTS\nRelease:\t20.04\nCodename:\tfocal',
                    
                    # Directory listings
                    'ls -la': 'total 48\ndrwxr-xr-x 2 www-data www-data 4096 Aug 15 09:20 .\ndrwxr-xr-x 3 www-data www-data 4096 Aug 15 09:19 ..\n-rw-r--r-- 1 www-data www-data  220 Aug 15 09:15 .bash_logout\n-rw-r--r-- 1 www-data www-data 3771 Aug 15 09:15 .bashrc',
                    'ls /home/': 'ubuntu\nwww-data',
                    'ls /var/': 'backups\ncache\nlib\nlocal\nlock\nlog\nmail\nopt\nrun\nspool\ntmp\nwww',
                    'ls /etc/': 'adduser.conf\nalternatives\napt\nbash.bashrc\nbindresvport.blacklist\ncrontab\ndefault\ngroup\nhosts\npasswd\nshadow',
                    
                    # Network commands  
                    'netstat -an': 'Active Internet connections (servers and established)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\ntcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\ntcp        0      0 192.168.1.100:80        192.168.1.50:45678      ESTABLISHED',
                    'ifconfig': 'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>\n        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)',
                    'route -n': 'Kernel IP routing table\nDestination     Gateway         Genmask         Flags Metric Ref    Use Iface\n0.0.0.0         192.168.1.1     0.0.0.0         UG    100    0        0 eth0\n192.168.1.0     0.0.0.0         255.255.255.0   U     100    0        0 eth0',
                    'arp -a': '? (192.168.1.1) at 52:54:00:12:35:02 [ether] on eth0\n? (192.168.1.50) at 08:00:27:53:69:8a [ether] on eth0',
                    'ping -c 3 127.0.0.1': 'PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.045 ms\n64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.067 ms\n64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.052 ms',
                    
                    # File search commands
                    'find / -name passwd': '/etc/passwd\n/usr/share/base-passwd/passwd.master',
                    'find / -name "*config*"': '/etc/mysql/mysql.conf.d\n/etc/apache2/apache2.conf\n/etc/ssh/sshd_config',
                    
                    # Windows commands (for cross-platform attacks)
                    'dir': 'Volume in drive C has no label.\n Volume Serial Number is 1234-5678\n\n Directory of C:\\\n\n08/15/2021  10:15 AM    <DIR>          Program Files\n08/15/2021  10:15 AM    <DIR>          Windows\n08/15/2021  10:15 AM    <DIR>          Users',
                    'type c:\\windows\\win.ini': '; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1',
                    'net user': 'User accounts for \\\\WEBSERVER\n\n-------------------------------------------------------------------------------\nAdministrator            Guest                    www-data',
                    'ipconfig /all': 'Windows IP Configuration\n\n   Host Name . . . . . . . . . . . . : webserver\n   Primary Dns Suffix  . . . . . . . :\n   Node Type . . . . . . . . . . . . : Hybrid\n   IP Routing Enabled. . . . . . . . : No\n   WINS Proxy Enabled. . . . . . . . : No',
                    'systeminfo': 'Host Name:                 WEBSERVER\nOS Name:                   Microsoft Windows Server 2019\nOS Version:                10.0.17763 N/A Build 17763\nSystem Type:               x64-based PC\nProcessor(s):              1 Processor(s) Installed.'
                }
                
                # Find matching output
                command_output = ""
                for cmd, output in fake_outputs.items():
                    if cmd in query.lower():
                        command_output = output
                        break
                
                if not command_output:
                    # Generic command error
                    if 'rm -rf' in query.lower():
                        command_output = "rm: cannot remove '/': Operation not permitted"
                    elif 'curl http' in query.lower():
                        command_output = "curl: command not found"
                    else:
                        command_output = "bash: command not found"
                
                return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>検索結果 - 鳩松Bank</title>
    <style>
        body { font-family: 'Yu Gothic', 'Meiryo', sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #003f7f; color: white; padding: 15px; margin-bottom: 20px; }
        .results { background: white; padding: 20px; border-radius: 5px; }
        .command-output { background: #f8f8f8; border: 1px solid #ddd; padding: 15px; margin: 10px 0; font-family: monospace; }
        .warning { background: #ffeb3b; padding: 10px; border-radius: 3px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>鳩松Bank - 検索結果</h1>
    </div>
    <div class="results">
        <h2>システム検索結果</h2>
        <p>検索クエリ: {{ query }}</p>
        <div class="command-output">
<pre>{{ command_output }}</pre>
        </div>
        <div class="warning">
            🚨 コマンドインジェクション攻撃が検出され、システムコマンドが実行されました。
        </div>
        <a href="/" style="color: #003f7f;">ホームに戻る</a>
    </div>
</body>
</html>
                """, query=query, command_output=command_output)
            
            # Check for XSS patterns
            xss_detected = any(pattern in query.lower() for pattern in [
                '<script>', 'javascript:', 'onerror=', 'onload=', 'alert('
            ])
            
            if xss_detected:
                # Return reflected XSS vulnerability
                return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>検索結果 - 鳩松Bank</title>
    <style>
        body { font-family: 'Yu Gothic', 'Meiryo', sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #003f7f; color: white; padding: 15px; margin-bottom: 20px; }
        .results { background: white; padding: 20px; border-radius: 5px; }
        .warning { background: #ffeb3b; padding: 10px; border-radius: 3px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>鳩松Bank - 検索結果</h1>
    </div>
    <div class="results">
        <h2>検索結果</h2>
        <p>検索クエリ: {{ query|safe }}</p>
        <div class="warning">
            ⚠️ 検索結果でJavaScriptが実行されました。これはXSS脆弱性の典型例です。
        </div>
        <p>該当する結果は見つかりませんでした。</p>
        <a href="/" style="color: #003f7f;">ホームに戻る</a>
    </div>
</body>
</html>
                """, query=query)
        
        return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>検索 - 鳩松Bank</title>
    <style>
        body { font-family: 'Yu Gothic', 'Meiryo', sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #003f7f; color: white; padding: 15px; margin-bottom: 20px; }
        .search-form { background: white; padding: 20px; border-radius: 5px; }
        .form-group { margin-bottom: 15px; }
        input[type="text"] { width: 70%; padding: 10px; border: 1px solid #ddd; }
        .btn { background: #003f7f; color: white; padding: 10px 20px; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <div class="header">
        <h1>鳩松Bank - サービス検索</h1>
    </div>
    <div class="search-form">
        <form method="GET">
            <div class="form-group">
                <label>検索キーワード:</label><br>
                <input type="text" name="query" placeholder="サービスや商品を検索">
                <input type="submit" value="検索" class="btn">
            </div>
        </form>
    </div>
</body>
</html>
        """)
    
    def _handle_contact(self) -> str:
        """Handle contact form - vulnerable to XSS."""
        if request.method == 'POST':
            message = request.form.get('message', '')
            
            if message:
                # Check for XSS in contact form
                xss_detected = any(pattern in message.lower() for pattern in [
                    '<script>', '</textarea>', 'javascript:', 'onerror=', 'alert('
                ])
                
                if xss_detected:
                    return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>お問い合わせ完了 - 鳩松Bank</title>
    <style>
        body { font-family: 'Yu Gothic', 'Meiryo', sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #003f7f; color: white; padding: 15px; margin-bottom: 20px; }
        .message { background: white; padding: 20px; border-radius: 5px; }
        .alert { background: #f44336; color: white; padding: 10px; border-radius: 3px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>鳩松Bank - お問い合わせ</h1>
    </div>
    <div class="message">
        <h2>お問い合わせを受け付けました</h2>
        <p>以下の内容で承りました：</p>
        <div style="border: 1px solid #ddd; padding: 15px; background: #fafafa;">
            {{ message|safe }}
        </div>
        <div class="alert">
            🚨 XSS攻撃が検出されました！管理者に通知します。
        </div>
        <a href="/" style="color: #003f7f;">ホームに戻る</a>
    </div>
</body>
</html>
                    """, message=message)
            
            return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>お問い合わせ完了 - 鳩松Bank</title>
</head>
<body>
    <h1>お問い合わせありがとうございます</h1>
    <p>お問い合わせを受け付けました。担当者より追ってご連絡いたします。</p>
    <a href="/">ホームに戻る</a>
</body>
</html>
            """)
        
        return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>お問い合わせ - 鳩松Bank</title>
    <style>
        body { font-family: 'Yu Gothic', 'Meiryo', sans-serif; margin: 20px; background: #f5f5f5; }
        .header { background: #003f7f; color: white; padding: 15px; margin-bottom: 20px; }
        .form { background: white; padding: 20px; border-radius: 5px; }
        textarea { width: 100%; height: 100px; padding: 10px; border: 1px solid #ddd; }
        .btn { background: #003f7f; color: white; padding: 10px 20px; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <div class="header">
        <h1>鳩松Bank - お問い合わせ</h1>
    </div>
    <div class="form">
        <form method="POST">
            <div style="margin-bottom: 15px;">
                <label>お問い合わせ内容:</label><br>
                <textarea name="message" placeholder="お問い合わせ内容をご記入ください"></textarea>
            </div>
            <input type="submit" value="送信" class="btn">
        </form>
    </div>
</body>
</html>
        """)
    
    def _handle_account_info(self) -> str:
        """Handle account info - vulnerable to SQL injection."""
        account_id = request.form.get('account_id', request.args.get('id', ''))
        
        if account_id:
            # Check for SQL injection
            sql_detected = any(pattern in account_id.lower() for pattern in [
                "union select", "' or ", "drop table", "insert into", "delete from"
            ])
            
            if sql_detected:
                return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>データベースエラー - 鳩松Bank</title>
    <style>
        body { font-family: monospace; margin: 20px; background: #f0f0f0; }
        .error { background: #ffebee; border: 1px solid #f44336; padding: 15px; margin: 20px 0; }
        pre { background: #263238; color: #fff; padding: 15px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>🔍 口座情報データベースエラー</h1>
    <div class="error">
        <strong>MySQL Error:</strong> You have an error in your SQL syntax near '{{ account_id }}' at line 1
    </div>
    
    <pre>SQL Query: SELECT account_id, customer_name, balance, account_type FROM accounts WHERE account_id = '{{ account_id }}'</pre>
    
    <p><strong>システム情報が漏洩しました:</strong></p>
    <ul>
        <li>Database: accounts_production</li>
        <li>Version: MySQL 8.0.25</li>
        <li>User: webapp@192.168.1.100</li>
        <li>Tables: accounts, customers, transactions, admin_users</li>
    </ul>
    
    <a href="/account.php" style="background: #003f7f; color: white; padding: 10px 20px; text-decoration: none;">戻る</a>
</body>
</html>
                """, account_id=account_id), 500
        
        return """
<html><body>
<h1>口座情報照会</h1>
<p>口座情報を照会するには口座IDを入力してください。</p>
<form method="POST">
    <input type="text" name="account_id" placeholder="口座ID">
    <input type="submit" value="照会">
</form>
</body></html>
        """
    
    def run(self):
        """Run the honeypot application."""
        flask_config = self.config.get('flask', {})
        host = flask_config.get('host', '0.0.0.0')
        port = flask_config.get('port', 8080)
        debug = flask_config.get('debug', False)
        
        print(f"Starting honeypot server on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    app = HoneypotApplication()
    app.run()