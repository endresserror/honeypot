#!/usr/bin/env python3
"""
Dashboard Web Application

Web-based dashboard for monitoring honeypot activities and analyzing attack patterns.
"""

import os
import sys
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Any, List
from collections import Counter

from flask import Flask, render_template_string, jsonify, request
import yaml

# Add modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

class DashboardApplication:
    """Dashboard web application for monitoring honeypot."""
    
    def __init__(self, config_path: str = 'config/config.yml'):
        self.config = self._load_config(config_path)
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'dashboard-secret-key'
        
        # Setup routes
        self._setup_routes()
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                if 'dashboard' not in config:
                    config['dashboard'] = {
                        'enabled': True,
                        'host': '0.0.0.0',
                        'port': 5000,
                        'debug': False
                    }
                return config
        except FileNotFoundError:
            return {
                'dashboard': {'host': '0.0.0.0', 'port': 5000, 'debug': False},
                'database': {'path': 'logs/honeypot.db'}
            }
    
    def _get_database_path(self) -> str:
        """Get database file path."""
        return self.config.get('database', {}).get('path', 'logs/honeypot.db')
    
    def _setup_routes(self):
        """Setup Flask routes for the dashboard."""
        
        @self.app.route('/')
        def index():
            return self._render_dashboard()
        
        @self.app.route('/api/stats')
        def api_stats():
            return jsonify(self._get_stats())
        
        @self.app.route('/api/logs')
        def api_logs():
            limit = request.args.get('limit', 100, type=int)
            return jsonify(self._get_recent_logs(limit))
        
        @self.app.route('/api/attacks')
        def api_attacks():
            return jsonify(self._get_attack_patterns())
        
        @self.app.route('/health')
        def health():
            return jsonify({'status': 'healthy', 'service': 'dashboard'})
    
    def _render_dashboard(self) -> str:
        """Render main dashboard page."""
        return render_template_string("""
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ハニーポット ダッシュボード</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; }
        .header { background: #2d3748; color: white; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .logo { font-size: 1.5rem; font-weight: bold; }
        .status { background: #48bb78; color: white; padding: 0.25rem 0.75rem; border-radius: 1rem; font-size: 0.875rem; }
        .main { max-width: 1200px; margin: 2rem auto; padding: 0 1rem; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
        .stat-card { background: white; padding: 1.5rem; border-radius: 0.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2rem; font-weight: bold; color: #2d3748; }
        .stat-label { color: #718096; font-size: 0.875rem; margin-top: 0.5rem; }
        .content-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 1.5rem; }
        .panel { background: white; border-radius: 0.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .panel-header { padding: 1rem 1.5rem; border-bottom: 1px solid #e2e8f0; font-weight: bold; color: #2d3748; }
        .panel-content { padding: 1.5rem; }
        .log-entry { padding: 0.75rem; border-bottom: 1px solid #e2e8f0; font-family: monospace; font-size: 0.875rem; }
        .log-entry:last-child { border-bottom: none; }
        .log-time { color: #718096; }
        .log-ip { color: #e53e3e; font-weight: bold; }
        .log-method { color: #3182ce; font-weight: bold; }
        .attack-item { padding: 0.75rem; border-bottom: 1px solid #e2e8f0; display: flex; justify-content: space-between; align-items: center; }
        .attack-item:last-child { border-bottom: none; }
        .attack-type { font-weight: bold; color: #2d3748; }
        .attack-count { background: #fed7d7; color: #c53030; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; }
        .refresh-btn { background: #3182ce; color: white; border: none; padding: 0.5rem 1rem; border-radius: 0.25rem; cursor: pointer; font-size: 0.875rem; }
        .refresh-btn:hover { background: #2c5aa0; }
        @media (max-width: 768px) {
            .content-grid { grid-template-columns: 1fr; }
            .header { flex-direction: column; gap: 1rem; text-align: center; }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">🍯 ハニーポット ダッシュボード</div>
        <div>
            <span class="status">● アクティブ</span>
            <button class="refresh-btn" onclick="refreshData()">更新</button>
        </div>
    </div>
    
    <div class="main">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number" id="total-requests">0</div>
                <div class="stat-label">総リクエスト数</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="unique-ips">0</div>
                <div class="stat-label">ユニークIP数</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="attack-attempts">0</div>
                <div class="stat-label">攻撃試行回数</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="uptime">--</div>
                <div class="stat-label">稼働時間</div>
            </div>
        </div>
        
        <div class="content-grid">
            <div class="panel">
                <div class="panel-header">最近のログ</div>
                <div class="panel-content">
                    <div id="recent-logs">ログを読み込み中...</div>
                </div>
            </div>
            
            <div class="panel">
                <div class="panel-header">攻撃パターン</div>
                <div class="panel-content">
                    <div id="attack-patterns">データを読み込み中...</div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function formatTime(timestamp) {
            const date = new Date(timestamp);
            return date.toLocaleString('ja-JP');
        }
        
        function formatUptime(seconds) {
            const days = Math.floor(seconds / 86400);
            const hours = Math.floor((seconds % 86400) / 3600);
            const mins = Math.floor((seconds % 3600) / 60);
            
            if (days > 0) return `${days}日 ${hours}時間`;
            if (hours > 0) return `${hours}時間 ${mins}分`;
            return `${mins}分`;
        }
        
        async function loadStats() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();
                
                document.getElementById('total-requests').textContent = data.total_requests || 0;
                document.getElementById('unique-ips').textContent = data.unique_ips || 0;
                document.getElementById('attack-attempts').textContent = data.attack_attempts || 0;
                document.getElementById('uptime').textContent = formatUptime(data.uptime || 0);
            } catch (error) {
                console.error('統計データの読み込みに失敗:', error);
            }
        }
        
        async function loadLogs() {
            try {
                const response = await fetch('/api/logs?limit=20');
                const logs = await response.json();
                
                const logsContainer = document.getElementById('recent-logs');
                if (logs.length === 0) {
                    logsContainer.innerHTML = '<div style="color: #718096; text-align: center; padding: 2rem;">ログがありません</div>';
                    return;
                }
                
                logsContainer.innerHTML = logs.map(log => `
                    <div class="log-entry">
                        <div class="log-time">${formatTime(log.timestamp)}</div>
                        <div><span class="log-ip">${log.source_ip}</span> - <span class="log-method">${log.method}</span> ${log.uri}</div>
                        <div style="color: #718096; font-size: 0.8rem;">Status: ${log.status_code}</div>
                    </div>
                `).join('');
            } catch (error) {
                console.error('ログの読み込みに失敗:', error);
                document.getElementById('recent-logs').innerHTML = '<div style="color: #e53e3e; text-align: center; padding: 2rem;">ログの読み込みに失敗しました</div>';
            }
        }
        
        async function loadAttackPatterns() {
            try {
                const response = await fetch('/api/attacks');
                const attacks = await response.json();
                
                const attacksContainer = document.getElementById('attack-patterns');
                if (attacks.length === 0) {
                    attacksContainer.innerHTML = '<div style="color: #718096; text-align: center; padding: 2rem;">攻撃パターンなし</div>';
                    return;
                }
                
                attacksContainer.innerHTML = attacks.map(attack => `
                    <div class="attack-item">
                        <div class="attack-type">${attack.type}</div>
                        <div class="attack-count">${attack.count}</div>
                    </div>
                `).join('');
            } catch (error) {
                console.error('攻撃パターンの読み込みに失敗:', error);
                document.getElementById('attack-patterns').innerHTML = '<div style="color: #e53e3e; text-align: center; padding: 2rem;">データの読み込みに失敗しました</div>';
            }
        }
        
        function refreshData() {
            loadStats();
            loadLogs();
            loadAttackPatterns();
        }
        
        // Initial load
        refreshData();
        
        // Auto-refresh every 30 seconds
        setInterval(refreshData, 30000);
    </script>
</body>
</html>
        """)
    
    def _get_stats(self) -> Dict[str, Any]:
        """Get overall statistics."""
        db_path = self._get_database_path()
        
        try:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                
                # Total requests
                cursor.execute("SELECT COUNT(*) FROM requests")
                total_requests = cursor.fetchone()[0]
                
                # Unique IPs
                cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM requests")
                unique_ips = cursor.fetchone()[0]
                
                # Attack attempts (basic heuristics)
                cursor.execute("""
                    SELECT COUNT(*) FROM requests 
                    WHERE uri LIKE '%union%' OR uri LIKE '%select%' OR uri LIKE '%script%' 
                    OR uri LIKE '%admin%' OR body LIKE '%script%' OR body LIKE '%union%'
                """)
                attack_attempts = cursor.fetchone()[0]
                
                return {
                    'total_requests': total_requests,
                    'unique_ips': unique_ips,
                    'attack_attempts': attack_attempts,
                    'uptime': 3600  # Placeholder - 1 hour
                }
                
        except sqlite3.Error:
            return {
                'total_requests': 0,
                'unique_ips': 0,
                'attack_attempts': 0,
                'uptime': 0
            }
    
    def _get_recent_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent log entries."""
        db_path = self._get_database_path()
        
        try:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT timestamp, source_ip, method, uri, status_code, body
                    FROM requests 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (limit,))
                
                results = cursor.fetchall()
                return [
                    {
                        'timestamp': row[0],
                        'source_ip': row[1],
                        'method': row[2],
                        'uri': row[3],
                        'status_code': row[4],
                        'body': row[5][:100] if row[5] else ''  # Truncate body
                    }
                    for row in results
                ]
                
        except sqlite3.Error:
            return []
    
    def _get_attack_patterns(self) -> List[Dict[str, Any]]:
        """Analyze and return attack patterns."""
        db_path = self._get_database_path()
        
        try:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT uri, body FROM requests 
                    WHERE uri LIKE '%union%' OR uri LIKE '%select%' OR uri LIKE '%script%' 
                    OR uri LIKE '%admin%' OR body LIKE '%script%' OR body LIKE '%union%'
                """)
                
                results = cursor.fetchall()
                attack_types = []
                
                for uri, body in results:
                    content = f"{uri} {body or ''}".lower()
                    
                    if 'union' in content or 'select' in content:
                        attack_types.append('SQL Injection')
                    elif 'script' in content:
                        attack_types.append('XSS')
                    elif 'admin' in content:
                        attack_types.append('Admin Access')
                    elif '../' in content:
                        attack_types.append('Directory Traversal')
                    else:
                        attack_types.append('Other')
                
                counter = Counter(attack_types)
                return [
                    {'type': attack_type, 'count': count}
                    for attack_type, count in counter.most_common()
                ]
                
        except sqlite3.Error:
            return []
    
    def run(self):
        """Run the dashboard application."""
        dashboard_config = self.config.get('dashboard', {})
        host = dashboard_config.get('host', '0.0.0.0')
        port = dashboard_config.get('port', 5000)
        debug = dashboard_config.get('debug', False)
        
        print(f"Starting dashboard server on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    dashboard = DashboardApplication()
    dashboard.run()