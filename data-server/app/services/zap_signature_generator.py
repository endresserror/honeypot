"""
OWASP ZAP用シグネチャ生成サービス
ハニーポットで観測した攻撃パターンからZAP用のスクリプトを自動生成
"""

import json
import re
import base64
from typing import Dict, List, Any, Optional
from datetime import datetime
import xml.etree.ElementTree as ET


class ZAPSignatureGenerator:
    """OWASP ZAP用のシグネチャ生成クラス"""
    
    def __init__(self):
        self.signature_templates = self._load_zap_templates()
        
    def _load_zap_templates(self) -> Dict[str, str]:
        """ZAP用のテンプレートを読み込み"""
        return {
            'active_scan': """
// Generated ZAP Active Scanner Rule
// Attack Type: {attack_type}
// Generated from honeypot data: {timestamp}

function scanNode(as, msg) {{
    var payload = "{payload}";
    var param = msg.getRequestHeader().getURI().getEscapedQuery();
    
    if (param) {{
        var testMsg = msg.cloneRequest();
        var modifiedParam = param.replace(/([^&=]+)=([^&]*)/g, '$1=' + encodeURIComponent(payload));
        testMsg.getRequestHeader().getURI().setEscapedQuery(modifiedParam);
        
        as.sendAndReceive(testMsg, false, false);
        
        if (isVulnerable(testMsg.getResponseBody().toString())) {{
            as.raiseAlert(
                getRisk(),
                getConfidence(),
                getName(),
                getDescription(),
                testMsg.getRequestHeader().getURI().toString(),
                param,
                "",
                getReference(),
                getSolution(),
                testMsg.getResponseBody().toString(),
                0,
                0,
                testMsg
            );
        }}
    }}
}}

function isVulnerable(responseBody) {{
    var indicators = {vulnerability_indicators};
    for (var i = 0; i < indicators.length; i++) {{
        if (responseBody.indexOf(indicators[i]) !== -1) {{
            return true;
        }}
    }}
    return false;
}}

function getRisk() {{ return {risk_level}; }}
function getConfidence() {{ return {confidence}; }}
function getName() {{ return "{rule_name}"; }}
function getDescription() {{ return "{description}"; }}
function getReference() {{ return "{reference}"; }}
function getSolution() {{ return "{solution}"; }}
""",
            
            'passive_scan': """
// Generated ZAP Passive Scanner Rule
// Attack Type: {attack_type}
// Generated from honeypot data: {timestamp}

function scan(ps, msg, src) {{
    var responseBody = msg.getResponseBody().toString();
    var requestUri = msg.getRequestHeader().getURI().toString();
    
    var indicators = {vulnerability_indicators};
    
    for (var i = 0; i < indicators.length; i++) {{
        if (responseBody.indexOf(indicators[i]) !== -1) {{
            ps.raiseAlert(
                getRisk(),
                getConfidence(),
                getName(),
                getDescription(),
                requestUri,
                "",
                "",
                getReference(),
                getSolution(),
                responseBody,
                0,
                0,
                msg
            );
            break;
        }}
    }}
}}

function getRisk() {{ return {risk_level}; }}
function getConfidence() {{ return {confidence}; }}
function getName() {{ return "{rule_name}"; }}
function getDescription() {{ return "{description}"; }}
function getReference() {{ return "{reference}"; }}
function getSolution() {{ return "{solution}"; }}
""",
            
            'fuzzing_payload': """
# ZAP Fuzzing Payloads
# Generated from honeypot attack patterns
# Attack Type: {attack_type}
# Timestamp: {timestamp}

{payloads}
""",

            'context_script': """
// ZAP Authentication/Context Script
// Generated for: {target_context}
// Based on honeypot observations

function authenticate(helper, paramsValues, credentials) {{
    var loginUrl = "{login_url}";
    var loginParams = "{login_params}";
    
    var msg = helper.prepareMessage();
    msg.getRequestHeader().setURI(new org.apache.commons.httpclient.URI(loginUrl, false));
    msg.getRequestHeader().setMethod("POST");
    msg.getRequestBody().setBody(loginParams);
    
    helper.sendAndReceive(msg);
    
    return msg;
}}

function getRequiredParamsNames() {{
    return {required_params};
}}

function getOptionalParamsNames() {{
    return {optional_params};
}}

function getCredentialsParamsNames() {{
    return {credentials_params};
}}
"""
        }
    
    def generate_zap_active_scan_rule(self, attack_log: Dict[str, Any]) -> Dict[str, str]:
        """アクティブスキャンルールを生成"""
        
        attack_type = attack_log.get('attackType', 'unknown')
        payload = self._extract_payload(attack_log)
        vulnerability_indicators = self._extract_vulnerability_indicators(attack_log)
        
        # 攻撃タイプに基づくリスク・信頼度設定
        risk_confidence = self._get_risk_confidence(attack_type, attack_log)
        
        script_content = self.signature_templates['active_scan'].format(
            attack_type=attack_type,
            timestamp=datetime.now().isoformat(),
            payload=self._escape_javascript_string(payload),
            vulnerability_indicators=json.dumps(vulnerability_indicators),
            risk_level=risk_confidence['risk'],
            confidence=risk_confidence['confidence'],
            rule_name=self._generate_rule_name(attack_type),
            description=self._generate_description(attack_type, attack_log),
            reference=self._generate_reference(attack_type),
            solution=self._generate_solution(attack_type)
        )
        
        return {
            'type': 'active_scan',
            'attack_type': attack_type,
            'script_content': script_content,
            'filename': f"active_scan_{attack_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.js",
            'metadata': {
                'payload': payload,
                'risk_level': risk_confidence['risk'],
                'confidence': risk_confidence['confidence'],
                'source_ip': attack_log.get('sourceIp'),
                'timestamp': attack_log.get('timestamp')
            }
        }
    
    def generate_zap_passive_scan_rule(self, attack_log: Dict[str, Any]) -> Dict[str, str]:
        """パッシブスキャンルールを生成"""
        
        attack_type = attack_log.get('attackType', 'unknown')
        vulnerability_indicators = self._extract_vulnerability_indicators(attack_log)
        
        risk_confidence = self._get_risk_confidence(attack_type, attack_log)
        
        script_content = self.signature_templates['passive_scan'].format(
            attack_type=attack_type,
            timestamp=datetime.now().isoformat(),
            vulnerability_indicators=json.dumps(vulnerability_indicators),
            risk_level=risk_confidence['risk'],
            confidence=risk_confidence['confidence'],
            rule_name=self._generate_rule_name(attack_type),
            description=self._generate_description(attack_type, attack_log),
            reference=self._generate_reference(attack_type),
            solution=self._generate_solution(attack_type)
        )
        
        return {
            'type': 'passive_scan',
            'attack_type': attack_type,
            'script_content': script_content,
            'filename': f"passive_scan_{attack_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.js",
            'metadata': {
                'vulnerability_indicators': vulnerability_indicators,
                'risk_level': risk_confidence['risk'],
                'confidence': risk_confidence['confidence'],
                'source_ip': attack_log.get('sourceIp'),
                'timestamp': attack_log.get('timestamp')
            }
        }
    
    def generate_zap_fuzzing_payloads(self, attack_logs: List[Dict[str, Any]], attack_type: str) -> Dict[str, str]:
        """ファジング用ペイロードファイルを生成"""
        
        payloads = []
        seen_payloads = set()
        
        for log in attack_logs:
            if log.get('attackType') == attack_type:
                payload = self._extract_payload(log)
                if payload and payload not in seen_payloads:
                    payloads.append(payload)
                    seen_payloads.add(payload)
        
        # ペイロードをソートして重複削除
        payloads = sorted(list(set(payloads)))
        
        payload_content = self.signature_templates['fuzzing_payload'].format(
            attack_type=attack_type,
            timestamp=datetime.now().isoformat(),
            payloads='\n'.join(payloads)
        )
        
        return {
            'type': 'fuzzing_payloads',
            'attack_type': attack_type,
            'content': payload_content,
            'filename': f"fuzzing_payloads_{attack_type}_{datetime.now().strftime('%Y%m%d')}.txt",
            'payload_count': len(payloads),
            'metadata': {
                'source_logs': len(attack_logs),
                'unique_payloads': len(payloads)
            }
        }
    
    def generate_zap_context_script(self, auth_logs: List[Dict[str, Any]]) -> Optional[Dict[str, str]]:
        """認証コンテキストスクリプトを生成"""
        
        if not auth_logs:
            return None
            
        # 認証関連のログを分析
        login_attempts = [log for log in auth_logs if 'login' in log.get('uri', '').lower()]
        
        if not login_attempts:
            return None
            
        # 最も一般的な認証パターンを抽出
        login_url = self._extract_common_login_url(login_attempts)
        login_params = self._extract_login_parameters(login_attempts)
        
        script_content = self.signature_templates['context_script'].format(
            target_context="Generated from honeypot",
            login_url=login_url,
            login_params=login_params,
            required_params=json.dumps(["username", "password"]),
            optional_params=json.dumps([]),
            credentials_params=json.dumps(["username", "password"])
        )
        
        return {
            'type': 'context_script',
            'script_content': script_content,
            'filename': f"auth_context_{datetime.now().strftime('%Y%m%d_%H%M%S')}.js",
            'metadata': {
                'login_url': login_url,
                'login_attempts_analyzed': len(login_attempts)
            }
        }
    
    def _extract_payload(self, attack_log: Dict[str, Any]) -> str:
        """攻撃ログからペイロードを抽出"""
        uri = attack_log.get('uri', '')
        request_body = attack_log.get('requestBody', '')
        
        # URIからペイロードを抽出
        if '=' in uri:
            # クエリパラメータから抽出
            import urllib.parse
            parsed = urllib.parse.urlparse(uri)
            params = urllib.parse.parse_qs(parsed.query)
            for param_values in params.values():
                for value in param_values:
                    if self._is_suspicious_payload(value):
                        return value
        
        # リクエストボディからペイロードを抽出
        if request_body and self._is_suspicious_payload(request_body):
            return request_body[:200]  # 長すぎる場合は切り詰め
            
        # デフォルト（URIから抽出）
        return uri.split('=')[-1] if '=' in uri else uri
    
    def _extract_vulnerability_indicators(self, attack_log: Dict[str, Any]) -> List[str]:
        """脆弱性を示すレスポンス内容を抽出"""
        response_body = attack_log.get('responseBody', '')
        attack_type = attack_log.get('attackType', '')
        
        indicators = []
        
        if attack_type == 'sql_injection':
            sql_errors = [
                'SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
                'sqlite_', 'Microsoft OLE DB', 'ODBC SQL Server',
                'You have an error in your SQL syntax'
            ]
            indicators.extend([ind for ind in sql_errors if ind.lower() in response_body.lower()])
        
        elif attack_type == 'xss':
            xss_indicators = [
                'script>', 'javascript:', 'onerror=', 'alert(',
                'document.cookie', 'document.write'
            ]
            indicators.extend([ind for ind in xss_indicators if ind in response_body])
        
        elif attack_type == 'command_injection':
            cmd_indicators = [
                'root:x:0:0', '/bin/bash', 'uid=', 'gid=',
                'Directory of', 'Volume Serial Number'
            ]
            indicators.extend([ind for ind in cmd_indicators if ind in response_body])
        
        # デフォルトエラーインジケータ
        error_indicators = ['error', 'exception', 'stack trace', 'warning']
        indicators.extend([ind for ind in error_indicators if ind.lower() in response_body.lower()])
        
        return list(set(indicators))  # 重複削除
    
    def _get_risk_confidence(self, attack_type: str, attack_log: Dict[str, Any]) -> Dict[str, int]:
        """攻撃タイプに基づくリスクと信頼度を設定"""
        
        # ZAPのリスクレベル: 0=情報, 1=低, 2=中, 3=高
        # ZAPの信頼度: 0=偽陽性, 1=低, 2=中, 3=高, 4=確実
        
        risk_mapping = {
            'sql_injection': {'risk': 3, 'confidence': 3},
            'command_injection': {'risk': 3, 'confidence': 3},
            'xss': {'risk': 2, 'confidence': 2},
            'path_traversal': {'risk': 2, 'confidence': 2},
            'xxe': {'risk': 3, 'confidence': 2},
            'csrf': {'risk': 2, 'confidence': 2},
            'suspicious': {'risk': 1, 'confidence': 1},
            'unknown': {'risk': 1, 'confidence': 1}
        }
        
        base_values = risk_mapping.get(attack_type, {'risk': 1, 'confidence': 1})
        
        # レスポンス内容に基づく信頼度調整
        response_body = attack_log.get('responseBody', '')
        if response_body and len(self._extract_vulnerability_indicators(attack_log)) > 1:
            base_values['confidence'] = min(4, base_values['confidence'] + 1)
        
        return base_values
    
    def _generate_rule_name(self, attack_type: str) -> str:
        """ルール名を生成"""
        name_mapping = {
            'sql_injection': 'SQL Injection (Honeypot Generated)',
            'xss': 'Cross Site Scripting (Honeypot Generated)', 
            'command_injection': 'Remote Command Injection (Honeypot Generated)',
            'path_traversal': 'Path Traversal (Honeypot Generated)',
            'xxe': 'XML External Entity (Honeypot Generated)'
        }
        return name_mapping.get(attack_type, f'{attack_type.title()} (Honeypot Generated)')
    
    def _generate_description(self, attack_type: str, attack_log: Dict[str, Any]) -> str:
        """説明文を生成"""
        base_descriptions = {
            'sql_injection': 'SQL injection vulnerability detected based on real attack patterns observed in honeypot.',
            'xss': 'Cross-site scripting vulnerability detected based on real attack patterns.',
            'command_injection': 'Remote command execution vulnerability detected based on observed attacks.',
            'path_traversal': 'Path traversal vulnerability allowing file access beyond intended directory.'
        }
        
        base_desc = base_descriptions.get(attack_type, f'{attack_type} vulnerability detected from honeypot data.')
        source_ip = attack_log.get('sourceIp', 'unknown')
        
        return f"{base_desc} Original attack observed from IP: {source_ip}"
    
    def _generate_reference(self, attack_type: str) -> str:
        """参考資料URLを生成"""
        references = {
            'sql_injection': 'https://owasp.org/www-community/attacks/SQL_Injection',
            'xss': 'https://owasp.org/www-community/attacks/xss/',
            'command_injection': 'https://owasp.org/www-community/attacks/Command_Injection',
            'path_traversal': 'https://owasp.org/www-community/attacks/Path_Traversal'
        }
        return references.get(attack_type, 'https://owasp.org/')
    
    def _generate_solution(self, attack_type: str) -> str:
        """解決方法を生成"""
        solutions = {
            'sql_injection': 'Use prepared statements and parameterized queries. Validate all input.',
            'xss': 'Encode output and validate input. Use Content Security Policy.',
            'command_injection': 'Avoid system calls with user input. Use safe APIs and validate input.',
            'path_traversal': 'Validate file paths and use whitelist approach for file access.'
        }
        return solutions.get(attack_type, 'Validate and sanitize all user input.')
    
    def _is_suspicious_payload(self, payload: str) -> bool:
        """ペイロードが攻撃的かどうかを判定"""
        suspicious_patterns = [
            r"['\"].*or.*['\"]",  # SQL injection
            r'<script.*?>',       # XSS
            r'javascript:',       # XSS
            r'\.\./',            # Path traversal  
            r';.*\|.*&',         # Command injection
            r'select.*from',     # SQL
            r'drop.*table',      # SQL
            r'<.*onerror.*=',    # XSS
        ]
        
        payload_lower = payload.lower()
        return any(re.search(pattern, payload_lower, re.IGNORECASE) for pattern in suspicious_patterns)
    
    def _escape_javascript_string(self, s: str) -> str:
        """JavaScript文字列をエスケープ"""
        return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
    
    def _extract_common_login_url(self, login_attempts: List[Dict[str, Any]]) -> str:
        """最も一般的なログインURLを抽出"""
        urls = [log.get('uri', '') for log in login_attempts]
        if not urls:
            return '/login'
            
        # 最も頻繁に出現するURLを返す
        from collections import Counter
        most_common = Counter(urls).most_common(1)
        return most_common[0][0] if most_common else '/login'
    
    def _extract_login_parameters(self, login_attempts: List[Dict[str, Any]]) -> str:
        """ログインパラメータを抽出"""
        for attempt in login_attempts:
            body = attempt.get('requestBody', '')
            if body and ('username' in body.lower() or 'password' in body.lower()):
                return body[:200]  # 長すぎる場合は切り詰め
        
        return 'username=test&password=test'  # デフォルト