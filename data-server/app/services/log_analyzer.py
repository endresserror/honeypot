"""
Log analysis service for extracting attack patterns from honeypot logs
"""

import logging
import re
import urllib.parse
from typing import List, Dict, Optional, Tuple
from app.models import AttackLog, BaselineResponse
from app.services.payload_extractor import PayloadExtractor
from app.services.response_analyzer import ResponseAnalyzer
from app.core.exceptions import LogAnalysisError, ValidationError
from app.core.constants import AnalysisConstants

logger = logging.getLogger(__name__)

class LogAnalyzer:
    """Analyzes attack logs to identify patterns and generate signatures."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.payload_extractor = PayloadExtractor(config)
        self.response_analyzer = ResponseAnalyzer(config)
        self.min_confidence = config.get('analysis', {}).get(
            'min_confidence_threshold', AnalysisConstants.MIN_CONFIDENCE_THRESHOLD
        )
    
    def analyze_unprocessed_logs(self) -> List[Dict]:
        """Analyze all unprocessed attack logs and extract patterns."""
        unprocessed_logs = AttackLog.query.filter_by(processed=False).all()
        
        analysis_results = []
        for log in unprocessed_logs:
            try:
                result = self.analyze_single_log(log)
                if result:
                    analysis_results.append(result)
                
                # Mark as processed
                log.processed = True
                
            except Exception as e:
                logger.error(f"Error analyzing log {log.id}: {e}")
                continue
        
        return analysis_results
    
    def analyze_single_log(self, attack_log: AttackLog) -> Optional[Dict]:
        """Analyze a single attack log entry."""
        if not attack_log:
            raise ValidationError("Attack log cannot be None")
        
        if not attack_log.request_uri:
            raise ValidationError("Attack log must have a request URI")
        
        logger.info(f"Analyzing attack log {attack_log.id}")
        
        # Extract request components
        request_analysis = self._analyze_request(attack_log)
        if not request_analysis:
            logger.debug(f"No suspicious patterns found in log {attack_log.id}")
            return None
        
        # Analyze response for anomalies
        response_analysis = self._analyze_response(attack_log, request_analysis)
        
        # Only proceed if we have both suspicious request and anomalous response
        if not response_analysis or not response_analysis.get('anomalies'):
            logger.debug(f"No response anomalies found in log {attack_log.id}")
            return None
        
        return {
            'attack_log': attack_log,
            'request_analysis': request_analysis,
            'response_analysis': response_analysis,
            'confidence': self._calculate_confidence(request_analysis, response_analysis)
        }
    
    def _analyze_request(self, attack_log: AttackLog) -> Optional[Dict]:
        """Analyze the request portion of an attack log."""
        parsed_url = urllib.parse.urlparse(attack_log.request_uri)
        payload_results = self._extract_payloads_from_request(attack_log, parsed_url)
        
        if not payload_results:
            return None
        
        best_payload = max(payload_results, key=lambda x: x['payload_info']['confidence'])
        
        return {
            'method': attack_log.request_method,
            'path': parsed_url.path,
            'payload_target': best_payload,
            'all_payloads': payload_results
        }
    
    def _extract_payloads_from_request(self, attack_log: AttackLog, parsed_url) -> List[Dict]:
        """Extract payloads from all request components."""
        payload_results = []
        
        # URL parameters
        params = urllib.parse.parse_qs(parsed_url.query)
        for param_name, param_values in params.items():
            for param_value in param_values:
                payload_info = self.payload_extractor.extract_payload(param_value)
                if payload_info:
                    payload_results.append({
                        'target': 'parameter',
                        'target_name': param_name,
                        'original_value': param_value,
                        'payload_info': payload_info
                    })
        
        # Headers
        headers = attack_log.request_headers or {}
        for header_name, header_value in headers.items():
            if isinstance(header_value, str):
                payload_info = self.payload_extractor.extract_payload(header_value)
                if payload_info:
                    payload_results.append({
                        'target': 'header',
                        'target_name': header_name,
                        'original_value': header_value,
                        'payload_info': payload_info
                    })
        
        # Request body
        if attack_log.request_body:
            payload_info = self.payload_extractor.extract_payload(attack_log.request_body)
            if payload_info:
                payload_results.append({
                    'target': 'body',
                    'target_name': None,
                    'original_value': attack_log.request_body,
                    'payload_info': payload_info
                })
        
        return payload_results
    
    def _analyze_response(self, attack_log: AttackLog, request_analysis: Dict) -> Optional[Dict]:
        """Analyze the response portion for anomalies compared to baseline."""
        payload_target = request_analysis['payload_target']
        
        # Find or create baseline for this request pattern
        request_pattern = self._generate_request_pattern(
            attack_log.request_method,
            request_analysis['path'],
            payload_target.get('target_name')
        )
        
        baseline = BaselineResponse.find_or_create_baseline(
            request_pattern,
            payload_target.get('target_name')
        )
        
        # If baseline is new, we can't compare yet
        if baseline.sample_count == 0:
            logger.debug(f"No baseline data for pattern {request_pattern}")
            return None
        
        # Compare response with baseline
        response_data = {
            'status_code': attack_log.response_status_code,
            'content_length': len(attack_log.response_body or ''),
            'response_time_ms': attack_log.response_time_ms or 0,
            'body': attack_log.response_body or ''
        }
        
        anomalies = baseline.is_anomalous_response(
            response_data,
            self.config.get('baseline_comparison', {})
        )
        
        # Look for error indicators in response body
        error_indicators = self._detect_error_indicators(attack_log.response_body or '')
        
        return {
            'baseline_id': baseline.id,
            'anomalies': anomalies,
            'error_indicators': error_indicators,
            'response_data': response_data
        }
    
    def _generate_request_pattern(self, method: str, path: str, param_name: str = None) -> str:
        """Generate a standardized request pattern for baseline matching."""
        if param_name:
            return f"{method} {path}?{param_name}=:param"
        else:
            return f"{method} {path}"
    
    def _detect_error_indicators(self, response_body: str) -> List[Dict]:
        """Detect error indicators in response body that suggest vulnerabilities."""
        indicators = []
        
        # SQL error patterns
        sql_patterns = [
            (r'mysql_fetch_array\(\)', 'MySQL Error'),
            (r'ORA-\d{5}', 'Oracle Error'),
            (r'Microsoft.*ODBC.*SQL Server', 'SQL Server Error'),
            (r'PostgreSQL.*ERROR', 'PostgreSQL Error'),
            (r'SQL syntax.*error', 'SQL Syntax Error'),
            (r'sqlite3\.OperationalError', 'SQLite Error')
        ]
        
        for pattern, description in sql_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                indicators.append({
                    'type': 'sql_error',
                    'description': description,
                    'pattern': pattern
                })
        
        # XSS indicators (script execution, alert dialogs)
        xss_patterns = [
            (r'<script[^>]*>.*?</script>', 'Script Tag Injection'),
            (r'javascript:', 'JavaScript Protocol'),
            (r'on\w+\s*=', 'Event Handler Injection')
        ]
        
        for pattern, description in xss_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                indicators.append({
                    'type': 'xss_indicator',
                    'description': description,
                    'pattern': pattern
                })
        
        # File inclusion indicators
        file_patterns = [
            (r'root:x:0:0:', 'Unix passwd file'),
            (r'\[boot loader\]', 'Windows boot.ini'),
            (r'<\?php', 'PHP Code Exposure')
        ]
        
        for pattern, description in file_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                indicators.append({
                    'type': 'file_inclusion',
                    'description': description,
                    'pattern': pattern
                })
        
        return indicators
    
    def _calculate_confidence(self, request_analysis: Dict, response_analysis: Dict) -> float:
        """Calculate confidence score for the detected attack pattern."""
        confidence = 0.0
        
        # Base confidence from payload detection
        payload_confidence = request_analysis['payload_target']['payload_info']['confidence']
        confidence += payload_confidence * 0.4
        
        # Boost confidence based on response anomalies
        anomalies = response_analysis.get('anomalies', [])
        if 'status_code_changed' in anomalies:
            confidence += 0.3
        if 'content_length_deviation' in anomalies:
            confidence += 0.2
        if 'response_time_anomaly' in anomalies:
            confidence += 0.1
        
        # Boost confidence based on error indicators
        error_indicators = response_analysis.get('error_indicators', [])
        error_boost = min(len(error_indicators) * 0.2, 0.4)
        confidence += error_boost
        
        return min(confidence, 1.0)