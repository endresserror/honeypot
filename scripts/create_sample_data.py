#!/usr/bin/env python3
"""
Create sample data for the vulnerability scanner system

This script creates sample attack logs, baseline responses, and signatures
for demonstration and testing purposes.
"""

import os
import sys
import json
from datetime import datetime, timedelta
import random

# Add the MCP server to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'mcp-server'))

from app import create_app, db
from app.models import AttackLog, BaselineResponse, Signature
from app.models.signature import AttackType, RiskLevel, SignatureStatus

def create_sample_attack_logs():
    """Create sample attack logs."""
    
    print("Creating sample attack logs...")
    
    # Sample attack patterns
    attack_patterns = [
        {
            'method': 'GET',
            'uri': "/product.php?id=1' OR '1'='1",
            'status_code': 500,
            'attack_type': 'SQL_INJECTION'
        },
        {
            'method': 'GET',
            'uri': "/search.php?q=<script>alert('XSS')</script>",
            'status_code': 200,
            'attack_type': 'XSS'
        },
        {
            'method': 'GET',
            'uri': "/file.php?file=../etc/passwd",
            'status_code': 200,
            'attack_type': 'LFI'
        },
        {
            'method': 'GET',
            'uri': "/product.php?id=1; DROP TABLE users--",
            'status_code': 500,
            'attack_type': 'SQL_INJECTION'
        },
        {
            'method': 'GET',
            'uri': "/search.php?q=<img src=x onerror=alert('XSS')>",
            'status_code': 200,
            'attack_type': 'XSS'
        },
        {
            'method': 'GET',
            'uri': "/debug.php?debug=; cat /etc/passwd",
            'status_code': 200,
            'attack_type': 'COMMAND_INJECTION'
        }
    ]
    
    # Source IPs for simulation
    source_ips = [
        '192.168.1.100',
        '10.0.0.50',
        '185.220.100.15',  # Suspicious IP
        '45.129.32.200',   # Suspicious IP
        '172.16.0.25'
    ]
    
    logs_created = 0
    
    for i in range(50):  # Create 50 sample logs
        pattern = random.choice(attack_patterns)
        source_ip = random.choice(source_ips)
        
        # Create realistic timestamps
        timestamp = datetime.utcnow() - timedelta(
            days=random.randint(0, 7),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        
        # Create request headers
        request_headers = {
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'sqlmap/1.7.2#stable (http://sqlmap.org)',
                'python-requests/2.28.1',
                'Nikto/2.1.6'
            ]),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'close'
        }
        
        # Create response based on attack type
        if pattern['attack_type'] == 'SQL_INJECTION' and pattern['status_code'] == 500:
            response_body = """<html><body>
<h1>Database Error</h1>
<pre>
Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given
SQL Error: You have an error in your SQL syntax; check the manual
</pre>
</body></html>"""
        elif pattern['attack_type'] == 'XSS':
            response_body = f"""<html><body>
<h1>Search Results</h1>
<p>You searched for: {pattern['uri'].split('q=')[1] if 'q=' in pattern['uri'] else 'unknown'}</p>
</body></html>"""
        elif pattern['attack_type'] == 'LFI':
            response_body = """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"""
        elif pattern['attack_type'] == 'COMMAND_INJECTION':
            response_body = """uid=33(www-data) gid=33(www-data) groups=33(www-data)"""
        else:
            response_body = "<html><body><h1>Page Not Found</h1></body></html>"
        
        response_headers = {
            'Content-Type': 'text/html',
            'Server': 'Apache/2.4.41',
            'Content-Length': str(len(response_body))
        }
        
        # Create attack log
        attack_log = AttackLog(
            timestamp=timestamp,
            source_ip=source_ip,
            request_method=pattern['method'],
            request_uri=pattern['uri'],
            request_headers=request_headers,
            request_body=None,
            response_status_code=pattern['status_code'],
            response_headers=response_headers,
            response_body=response_body,
            response_time_ms=random.randint(100, 2000),
            processed=random.choice([True, False]),  # Some processed, some not
            signatures_generated=random.randint(0, 2),
            user_agent=request_headers['User-Agent'],
            referer=None
        )
        
        db.session.add(attack_log)
        logs_created += 1
    
    print(f"Created {logs_created} sample attack logs")

def create_sample_baseline_responses():
    """Create sample baseline responses."""
    
    print("Creating sample baseline responses...")
    
    baselines = [
        {
            'request_pattern': 'GET /product.php?id=:param',
            'parameter_name': 'id',
            'typical_status_code': 200,
            'typical_content_length': 1500,
            'typical_response_time_ms': 250
        },
        {
            'request_pattern': 'GET /search.php?q=:param',
            'parameter_name': 'q',
            'typical_status_code': 200,
            'typical_content_length': 800,
            'typical_response_time_ms': 180
        },
        {
            'request_pattern': 'GET /file.php?file=:param',
            'parameter_name': 'file',
            'typical_status_code': 200,
            'typical_content_length': 500,
            'typical_response_time_ms': 120
        },
        {
            'request_pattern': 'GET /',
            'parameter_name': None,
            'typical_status_code': 200,
            'typical_content_length': 2000,
            'typical_response_time_ms': 300
        }
    ]
    
    baselines_created = 0
    
    for baseline_data in baselines:
        baseline = BaselineResponse(
            request_pattern=baseline_data['request_pattern'],
            parameter_name=baseline_data['parameter_name'],
            typical_status_code=baseline_data['typical_status_code'],
            typical_content_length=baseline_data['typical_content_length'],
            typical_response_time_ms=baseline_data['typical_response_time_ms'],
            typical_headers={'Content-Type': 'text/html', 'Server': 'Apache/2.4.41'},
            sample_count=random.randint(10, 50),
            consistency_score=random.uniform(0.8, 1.0)
        )
        
        db.session.add(baseline)
        baselines_created += 1
    
    print(f"Created {baselines_created} sample baseline responses")

def create_sample_signatures():
    """Create sample signatures."""
    
    print("Creating sample signatures...")
    
    signatures_data = [
        {
            'name': "SQL Injection in 'id' parameter",
            'attack_type': AttackType.SQL_INJECTION,
            'risk_level': RiskLevel.HIGH,
            'status': SignatureStatus.APPROVED,
            'confidence_score': 0.85,
            'attack_pattern': {
                'target': 'parameter',
                'targetName': 'id',
                'payload': "' OR '1'='1"
            },
            'verification': {
                'type': 'response-body-contains',
                'condition': 'SQL syntax error'
            }
        },
        {
            'name': "XSS in search query",
            'attack_type': AttackType.XSS,
            'risk_level': RiskLevel.MEDIUM,
            'status': SignatureStatus.APPROVED,
            'confidence_score': 0.75,
            'attack_pattern': {
                'target': 'parameter',
                'targetName': 'q',
                'payload': "<script>alert('XSS')</script>"
            },
            'verification': {
                'type': 'response-body-contains',
                'condition': '<script>'
            }
        },
        {
            'name': "Local File Inclusion via file parameter",
            'attack_type': AttackType.LFI,
            'risk_level': RiskLevel.HIGH,
            'status': SignatureStatus.APPROVED,
            'confidence_score': 0.90,
            'attack_pattern': {
                'target': 'parameter',
                'targetName': 'file',
                'payload': '../etc/passwd'
            },
            'verification': {
                'type': 'response-body-contains',
                'condition': 'root:x:0:0:'
            }
        },
        {
            'name': "Command Injection in debug parameter",
            'attack_type': AttackType.COMMAND_INJECTION,
            'risk_level': RiskLevel.CRITICAL,
            'status': SignatureStatus.PENDING_REVIEW,
            'confidence_score': 0.80,
            'attack_pattern': {
                'target': 'parameter',
                'targetName': 'debug',
                'payload': '; cat /etc/passwd'
            },
            'verification': {
                'type': 'response-body-contains',
                'condition': 'uid='
            }
        },
        {
            'name': "Boolean-based SQL Injection",
            'attack_type': AttackType.SQL_INJECTION,
            'risk_level': RiskLevel.HIGH,
            'status': SignatureStatus.PENDING_REVIEW,
            'confidence_score': 0.70,
            'attack_pattern': {
                'target': 'parameter',
                'targetName': 'id',
                'payload': "1 AND 1=1"
            },
            'verification': {
                'type': 'status-code-not-equals',
                'condition': '200'
            }
        }
    ]
    
    signatures_created = 0
    
    for sig_data in signatures_data:
        signature = Signature(
            name=sig_data['name'],
            attack_type=sig_data['attack_type'],
            risk_level=sig_data['risk_level'],
            status=sig_data['status'],
            confidence_score=sig_data['confidence_score'],
            observed_count=random.randint(5, 30),
            success_count=random.randint(0, 10),
            false_positive_count=random.randint(0, 3),
            attack_pattern=sig_data['attack_pattern'],
            verification=sig_data['verification'],
            description=f"Automatically generated signature for {sig_data['attack_type'].value.replace('_', ' ').lower()} attacks"
        )
        
        # Generate signature ID
        signature.generate_signature_id()
        
        # Set approval info for approved signatures
        if signature.status == SignatureStatus.APPROVED:
            signature.approved_at = datetime.utcnow() - timedelta(days=random.randint(1, 5))
            signature.approved_by = 'admin'
        
        db.session.add(signature)
        signatures_created += 1
    
    print(f"Created {signatures_created} sample signatures")

def main():
    """Main function to create all sample data."""
    
    print("Creating sample data for vulnerability scanner system...")
    
    # Create Flask app and database context
    app = create_app()
    
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Create sample data
        create_sample_attack_logs()
        create_sample_baseline_responses()
        create_sample_signatures()
        
        # Commit all changes
        try:
            db.session.commit()
            print("\nSample data created successfully!")
        except Exception as e:
            db.session.rollback()
            print(f"\nError creating sample data: {e}")
            return 1
    
    return 0

if __name__ == '__main__':
    exit(main())