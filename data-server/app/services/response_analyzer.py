"""
Response analysis service for comparing attack responses with baselines
"""

import hashlib
import logging
import re
from typing import Dict, List, Optional, Set
from app.models import BaselineResponse

logger = logging.getLogger(__name__)

class ResponseAnalyzer:
    """Analyzes HTTP responses to detect anomalies and vulnerabilities."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.error_signatures = self._load_error_signatures()
    
    def _load_error_signatures(self) -> Dict:
        """Load error signature patterns for different vulnerabilities."""
        return {
            'sql_injection': [
                {
                    'pattern': r'mysql_fetch_array\(\)',
                    'severity': 'high',
                    'description': 'MySQL function error exposure'
                },
                {
                    'pattern': r'ORA-\d{5}',
                    'severity': 'high',
                    'description': 'Oracle database error'
                },
                {
                    'pattern': r'Microsoft.*ODBC.*SQL Server',
                    'severity': 'high',
                    'description': 'SQL Server ODBC error'
                },
                {
                    'pattern': r'PostgreSQL.*ERROR',
                    'severity': 'high',
                    'description': 'PostgreSQL error message'
                },
                {
                    'pattern': r'SQL syntax.*error',
                    'severity': 'medium',
                    'description': 'Generic SQL syntax error'
                },
                {
                    'pattern': r'sqlite3\.OperationalError',
                    'severity': 'high',
                    'description': 'SQLite operational error'
                },
                {
                    'pattern': r'mysql_num_rows\(\)',
                    'severity': 'medium',
                    'description': 'MySQL function exposure'
                }
            ],
            
            'xss': [
                {
                    'pattern': r'<script[^>]*>.*?</script>',
                    'severity': 'high',
                    'description': 'Script tag in response'
                },
                {
                    'pattern': r'javascript:',
                    'severity': 'medium',
                    'description': 'JavaScript protocol in response'
                },
                {
                    'pattern': r'alert\s*\(',
                    'severity': 'medium',
                    'description': 'Alert function in response'
                }
            ],
            
            'file_inclusion': [
                {
                    'pattern': r'root:x:0:0:',
                    'severity': 'critical',
                    'description': 'Unix passwd file contents'
                },
                {
                    'pattern': r'\[boot loader\]',
                    'severity': 'high',
                    'description': 'Windows boot.ini file'
                },
                {
                    'pattern': r'<\?php',
                    'severity': 'medium',
                    'description': 'PHP code disclosure'
                }
            ],
            
            'command_injection': [
                {
                    'pattern': r'uid=\d+\(.*?\) gid=\d+\(.*?\)',
                    'severity': 'critical',
                    'description': 'Unix user ID command output'
                },
                {
                    'pattern': r'total \d+',
                    'severity': 'medium',
                    'description': 'Directory listing output'
                }
            ]
        }
    
    def analyze_response(self, response_data: Dict, baseline: BaselineResponse = None) -> Dict:
        """Analyze HTTP response for anomalies and vulnerabilities."""
        analysis_result = {
            'anomalies': [],
            'error_indicators': [],
            'severity': 'low',
            'confidence': 0.0
        }
        
        # Compare with baseline if available
        if baseline:
            baseline_anomalies = self._compare_with_baseline(response_data, baseline)
            analysis_result['anomalies'].extend(baseline_anomalies)
        
        # Check for error indicators
        error_indicators = self._detect_error_indicators(response_data.get('body', ''))
        analysis_result['error_indicators'] = error_indicators
        
        # Calculate overall severity and confidence
        analysis_result['severity'] = self._calculate_severity(
            analysis_result['anomalies'], 
            error_indicators
        )
        analysis_result['confidence'] = self._calculate_confidence(
            analysis_result['anomalies'], 
            error_indicators
        )
        
        return analysis_result
    
    def _compare_with_baseline(self, response_data: Dict, baseline: BaselineResponse) -> List[str]:
        """Compare response with baseline to identify anomalies."""
        anomalies = []
        
        # Status code comparison
        if response_data.get('status_code') != baseline.typical_status_code:
            anomalies.append('status_code_changed')
        
        # Content length comparison
        response_length = response_data.get('content_length', 0)
        if baseline.typical_content_length:
            length_ratio = abs(response_length - baseline.typical_content_length) / baseline.typical_content_length
            threshold = self.config.get('baseline_comparison', {}).get('content_length_threshold', 0.3)
            if length_ratio > threshold:
                anomalies.append('content_length_deviation')
        
        # Response time comparison
        response_time = response_data.get('response_time_ms', 0)
        if baseline.typical_response_time_ms and response_time:
            time_threshold = self.config.get('baseline_comparison', {}).get('response_time_threshold', 2000)
            if response_time > baseline.typical_response_time_ms + time_threshold:
                anomalies.append('response_time_anomaly')
        
        return anomalies
    
    def _detect_error_indicators(self, response_body: str) -> List[Dict]:
        """Detect error indicators in response body."""
        indicators = []
        
        if not response_body:
            return indicators
        
        for category, signatures in self.error_signatures.items():
            for signature in signatures:
                pattern = signature['pattern']
                matches = list(re.finditer(pattern, response_body, re.IGNORECASE))
                
                for match in matches:
                    indicators.append({
                        'category': category,
                        'severity': signature['severity'],
                        'description': signature['description'],
                        'pattern': pattern,
                        'matched_text': match.group(),
                        'position': match.span()
                    })
        
        return indicators
    
    def _calculate_severity(self, anomalies: List[str], error_indicators: List[Dict]) -> str:
        """Calculate overall severity based on anomalies and error indicators."""
        max_severity = 'low'
        
        # Check error indicator severities
        for indicator in error_indicators:
            severity = indicator.get('severity', 'low')
            if severity == 'critical':
                return 'critical'
            elif severity == 'high' and max_severity != 'critical':
                max_severity = 'high'
            elif severity == 'medium' and max_severity in ['low']:
                max_severity = 'medium'
        
        # Boost severity based on anomalies
        critical_anomalies = ['status_code_changed']
        high_anomalies = ['content_length_deviation']
        
        if any(anomaly in critical_anomalies for anomaly in anomalies):
            if max_severity == 'low':
                max_severity = 'medium'
        
        if any(anomaly in high_anomalies for anomaly in anomalies):
            if max_severity == 'low':
                max_severity = 'medium'
        
        return max_severity
    
    def _calculate_confidence(self, anomalies: List[str], error_indicators: List[Dict]) -> float:
        """Calculate confidence score for the analysis."""
        confidence = 0.0
        
        # Base confidence from anomalies
        anomaly_weights = {
            'status_code_changed': 0.3,
            'content_length_deviation': 0.2,
            'response_time_anomaly': 0.1
        }
        
        for anomaly in anomalies:
            confidence += anomaly_weights.get(anomaly, 0.05)
        
        # Boost confidence from error indicators
        severity_weights = {
            'critical': 0.4,
            'high': 0.3,
            'medium': 0.2,
            'low': 0.1
        }
        
        for indicator in error_indicators:
            severity = indicator.get('severity', 'low')
            confidence += severity_weights.get(severity, 0.1)
        
        return min(confidence, 1.0)
    
    def generate_verification_condition(self, response_analysis: Dict) -> Dict:
        """Generate verification condition for signature based on response analysis."""
        error_indicators = response_analysis.get('error_indicators', [])
        anomalies = response_analysis.get('anomalies', [])
        
        # Prefer error indicators for verification
        if error_indicators:
            # Use the most severe error indicator
            best_indicator = max(error_indicators, 
                               key=lambda x: ['low', 'medium', 'high', 'critical'].index(x.get('severity', 'low')))
            
            return {
                'type': 'response-body-contains',
                'condition': best_indicator['matched_text'][:100],  # Limit length
                'description': best_indicator['description']
            }
        
        # Fall back to status code anomalies
        elif 'status_code_changed' in anomalies:
            return {
                'type': 'status-code-not-equals',
                'condition': '200',
                'description': 'Response status code indicates error'
            }
        
        # Default to content length check
        else:
            return {
                'type': 'content-length-deviation',
                'condition': '0.3',  # 30% deviation threshold
                'description': 'Significant change in response size'
            }
    
    def update_baseline(self, baseline: BaselineResponse, response_data: Dict):
        """Update baseline with new normal response data."""
        baseline.update_with_response(response_data)
    
    def calculate_response_hash(self, response_body: str) -> str:
        """Calculate hash of response body for comparison."""
        if not response_body:
            return ''
        return hashlib.sha256(response_body.encode('utf-8')).hexdigest()
    
    def extract_response_keywords(self, response_body: str) -> List[str]:
        """Extract common keywords from response body."""
        if not response_body:
            return []
        
        # Remove HTML tags
        clean_text = re.sub(r'<[^>]+>', ' ', response_body)
        
        # Extract words (letters only, minimum 3 characters)
        words = re.findall(r'\b[a-zA-Z]{3,}\b', clean_text.lower())
        
        # Count word frequency
        word_count = {}
        for word in words:
            word_count[word] = word_count.get(word, 0) + 1
        
        # Return most common words
        sorted_words = sorted(word_count.items(), key=lambda x: x[1], reverse=True)
        return [word for word, count in sorted_words[:20]]