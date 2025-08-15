"""
Honeypot logging system for capturing and forwarding attack data
"""

import os
import json
import sqlite3
import logging
import requests
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

class HoneypotLogger:
    """Handles logging of honeypot interactions and submission to Data Server."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.db_path = 'logs/honeypot.db'
        self.log_file = config.get('file', 'logs/honeypot.log')
        
        # Setup logging
        self._setup_logging()
        
        # Initialize database
        self._init_database()
        
        # Data Server config
        data_config = config.get('data_server', {})
        self.data_url = os.environ.get('DATA_SERVER_URL', data_config.get('url', 'http://localhost:5001'))
        self.submission_timeout = data_config.get('timeout', 10)
    
    def _setup_logging(self):
        """Setup file logging."""
        log_dir = Path(self.log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        logging.basicConfig(
            level=getattr(logging, self.config.get('level', 'INFO').upper()),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def _init_database(self):
        """Initialize SQLite database for local log storage."""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                method TEXT NOT NULL,
                uri TEXT NOT NULL,
                request_headers TEXT NOT NULL,
                request_body TEXT,
                status_code INTEGER NOT NULL,
                response_headers TEXT NOT NULL,
                response_body TEXT,
                response_time INTEGER,
                attack_type TEXT DEFAULT 'normal',
                attack_severity TEXT DEFAULT 'low',
                attack_description TEXT DEFAULT '',
                suspicious_payloads TEXT DEFAULT '[]',
                heuristic_anomalies TEXT DEFAULT '{}',
                submitted BOOLEAN DEFAULT FALSE,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create requests table for dashboard compatibility
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                method TEXT NOT NULL,
                uri TEXT NOT NULL,
                status_code INTEGER,
                body TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create index for efficient querying
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_submitted ON logs(submitted)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp)
        ''')
        
        conn.commit()
        conn.close()
        
        self.logger.info("Database initialized")
    
    def log_interaction(self, log_entry: Dict[str, Any]):
        """Log an HTTP interaction to database and file."""
        
        try:
            # Extract data from log entry
            timestamp = log_entry['timestamp']
            source_ip = log_entry['sourceIp']
            request = log_entry['request']
            response = log_entry['response']
            
            # Remove NUL characters to prevent PostgreSQL errors
            def clean_text(text):
                if isinstance(text, str):
                    return text.replace('\x00', '')
                return text
            
            # Clean request data
            if request.get('body'):
                request['body'] = clean_text(request['body'])
            if request.get('uri'):
                request['uri'] = clean_text(request['uri'])
            
            # Clean response data
            if response.get('body'):
                response['body'] = clean_text(response['body'])
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO logs (
                    timestamp, source_ip, method, uri, request_headers, request_body,
                    status_code, response_headers, response_body, response_time,
                    attack_type, attack_severity, attack_description, 
                    suspicious_payloads, heuristic_anomalies
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                timestamp,
                source_ip,
                request['method'],
                request['uri'],
                json.dumps(request['headers']),
                request.get('body'),
                response['statusCode'],
                json.dumps(response['headers']),
                response.get('body'),
                response.get('responseTime'),
                log_entry.get('attackType', 'normal'),
                log_entry.get('attackSeverity', 'low'),
                log_entry.get('attackDescription', ''),
                json.dumps(log_entry.get('suspiciousPayloads', [])),
                json.dumps(log_entry.get('heuristicAnomalies', {}))
            ))
            
            # Also insert into requests table for dashboard
            cursor.execute('''
                INSERT INTO requests (
                    timestamp, source_ip, method, uri, status_code, body
                ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                timestamp,
                source_ip,
                request['method'],
                request['uri'],
                response['statusCode'],
                request.get('body')
            ))
            
            conn.commit()
            conn.close()
            
            # Log to file for immediate visibility
            log_line = f"{timestamp} | {source_ip} | {request['method']} {request['uri']} | {response['statusCode']}"
            self.logger.info(log_line)
            
            # Log suspicious patterns
            if self._is_suspicious(log_entry):
                self.logger.warning(f"Suspicious activity detected: {source_ip} -> {request['uri']}")
            
        except Exception as e:
            self.logger.error(f"Failed to log interaction: {e}")
    
    def _is_suspicious(self, log_entry: Dict[str, Any]) -> bool:
        """Check if log entry contains suspicious patterns."""
        
        request = log_entry.get('request', {})
        uri = request.get('uri', '').lower()
        
        # Common attack patterns
        suspicious_patterns = [
            "'", '"', '<script>', 'union select', '../', '/etc/', 'cmd.exe',
            'exec(', 'system(', 'passthru(', 'shell_exec(', 'eval(',
            'drop table', 'insert into', 'update set', 'delete from',
            'waitfor delay', 'benchmark(', 'sleep(',
            'onload=', 'onerror=', 'javascript:', 'vbscript:',
            '%3cscript%3e', '%27', '%22', '0x', 'char(',
            'and 1=1', 'or 1=1', 'admin\'--', 'information_schema'
        ]
        
        return any(pattern in uri for pattern in suspicious_patterns)
    
    def get_pending_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get logs that haven't been submitted to Data Server yet."""
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, timestamp, source_ip, method, uri, request_headers, request_body,
                       status_code, response_headers, response_body, response_time,
                       attack_type, attack_severity, attack_description, 
                       suspicious_payloads, heuristic_anomalies
                FROM logs 
                WHERE submitted = FALSE 
                ORDER BY id ASC 
                LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            # Convert to log entry format
            logs = []
            for row in rows:
                log_entry = {
                    'id': row[0],
                    'timestamp': row[1],
                    'sourceIp': row[2],
                    'request': {
                        'method': row[3],
                        'uri': row[4],
                        'headers': json.loads(row[5]) if row[5] else {},
                        'body': row[6]
                    },
                    'response': {
                        'statusCode': row[7],
                        'headers': json.loads(row[8]) if row[8] else {},
                        'body': row[9],
                        'responseTime': row[10]
                    },
                    'attackType': row[11] if len(row) > 11 else 'normal',
                    'attackSeverity': row[12] if len(row) > 12 else 'low',
                    'attackDescription': row[13] if len(row) > 13 else '',
                    'suspiciousPayloads': json.loads(row[14]) if len(row) > 14 and row[14] else [],
                    'heuristicAnomalies': json.loads(row[15]) if len(row) > 15 and row[15] else {}
                }
                logs.append(log_entry)
            
            return logs
            
        except Exception as e:
            self.logger.error(f"Failed to get pending logs: {e}")
            return []
    
    def mark_logs_submitted(self, log_ids: List[int]):
        """Mark logs as submitted to Data Server."""
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Mark logs as submitted
            placeholders = ','.join('?' * len(log_ids))
            cursor.execute(f'''
                UPDATE logs 
                SET submitted = TRUE 
                WHERE id IN ({placeholders})
            ''', log_ids)
            
            conn.commit()
            conn.close()
            
            self.logger.debug(f"Marked {len(log_ids)} logs as submitted")
            
        except Exception as e:
            self.logger.error(f"Failed to mark logs as submitted: {e}")
    
    def submit_pending_logs(self):
        """Submit pending logs to Data Server."""
        
        pending_logs = self.get_pending_logs()
        
        if not pending_logs:
            return
        
        successful_ids = []
        
        for log_entry in pending_logs:
            try:
                # Remove internal ID before submission
                log_id = log_entry.pop('id')
                
                # Submit to Data Server
                response = requests.post(
                    f"{self.data_url}/api/logs",
                    json=log_entry,
                    timeout=self.submission_timeout,
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code in [200, 201]:
                    successful_ids.append(log_id)
                    self.logger.debug(f"Successfully submitted log {log_id}")
                else:
                    self.logger.warning(f"Failed to submit log {log_id}: HTTP {response.status_code}")
                
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Network error submitting log: {e}")
                break  # Stop trying if network is down
            except Exception as e:
                self.logger.error(f"Error submitting log: {e}")
        
        # Mark successful submissions
        if successful_ids:
            self.mark_logs_submitted(successful_ids)
            self.logger.info(f"Successfully submitted {len(successful_ids)} logs to Data Server")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get logging statistics."""
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total logs
            cursor.execute('SELECT COUNT(*) FROM logs')
            total_logs = cursor.fetchone()[0]
            
            # Submitted logs
            cursor.execute('SELECT COUNT(*) FROM logs WHERE submitted = TRUE')
            submitted_logs = cursor.fetchone()[0]
            
            # Recent logs (last 24 hours)
            cursor.execute('''
                SELECT COUNT(*) FROM logs 
                WHERE datetime(timestamp) > datetime('now', '-1 day')
            ''')
            recent_logs = cursor.fetchone()[0]
            
            # Top source IPs
            cursor.execute('''
                SELECT source_ip, COUNT(*) as count 
                FROM logs 
                GROUP BY source_ip 
                ORDER BY count DESC 
                LIMIT 10
            ''')
            top_ips = [{'ip': row[0], 'count': row[1]} for row in cursor.fetchall()]
            
            conn.close()
            
            return {
                'total_logs': total_logs,
                'submitted_logs': submitted_logs,
                'pending_logs': total_logs - submitted_logs,
                'recent_logs': recent_logs,
                'top_source_ips': top_ips
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {}
    
    def cleanup_old_logs(self, days: int = 30):
        """Clean up logs older than specified days."""
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM logs 
                WHERE submitted = TRUE 
                AND datetime(timestamp) < datetime('now', '-' || ? || ' days')
            ''', (days,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            if deleted_count > 0:
                self.logger.info(f"Cleaned up {deleted_count} old logs")
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old logs: {e}")