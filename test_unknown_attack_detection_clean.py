#!/usr/bin/env python3
"""
未知攻撃検知テスト - ヒューリスティックベース異常検知の評価
"""
import requests
import time
import json

class UnknownAttackTester:
    def __init__(self):
        self.honeypot_url = "http://localhost:8080"
        self.data_url = "http://localhost:5001"
        
    def test_attack_detection(self, payload, attack_type):
        """個別攻撃の検知テスト"""
        # 複数のエンドポイントでテスト
        endpoints = ['/search.php', '/debug.php', '/contact.php']
        
        for endpoint in endpoints:
            try:
                # GETパラメータでテスト
                response = requests.get(
                    f"{self.honeypot_url}{endpoint}",
                    params={'q': payload, 'test': payload},
                    timeout=5
                )
                
                # POSTデータでテスト  
                response = requests.post(
                    f"{self.honeypot_url}{endpoint}",
                    data={'search': payload, 'input': payload},
                    timeout=5
                )
                
                time.sleep(0.1)  # サーバー負荷軽減
                
            except Exception as e:
                print(f"Error testing {payload}: {e}")
                continue
        
        # 最新のログを確認して検知結果を取得
        try:
            logs_response = requests.get(f"{self.data_url}/api/logs?limit=1", timeout=5)
            if logs_response.status_code == 200:
                logs_data = logs_response.json()
                logs = logs_data.get('logs', [])
                if logs and len(logs) > 0:
                    latest_log = logs[0]
                    
                    # ヒューリスティック検知結果をチェック
                    heuristic_anomalies = latest_log.get('heuristicAnomalies', {})
                    if heuristic_anomalies and heuristic_anomalies.get('overall_score', 0) > 0:
                        return {
                            'detected': True,
                            'type': latest_log.get('attackType', 'unknown_attack'),
                            'severity': latest_log.get('attackSeverity', 'unknown'),
                            'confidence': heuristic_anomalies.get('threshold', 'unknown'),
                            'anomaly_score': heuristic_anomalies.get('overall_score', 0)
                        }
                    
                    # 従来の攻撃検知もチェック
                    attack_type = latest_log.get('attackType', 'normal')
                    if attack_type != 'normal' and attack_type != 'unknown':
                        return {
                            'detected': True,
                            'type': attack_type,
                            'severity': latest_log.get('attackSeverity', 'unknown'),
                            'confidence': 'high'
                        }
            
            return {'detected': False}
            
        except Exception as e:
            print(f"Error checking logs: {e}")
            return {'detected': False}
    
    def run_unknown_attack_detection_test(self):
        """未知攻撃検知テストの実行"""
        print("未知攻撃検知システム評価開始")
        print("ヒューリスティックベース異常検知の性能測定")
        
        # 1. 新しいコマンドインジェクション技術
        novel_command_injections = [
            # Bash変数展開攻撃
            "; ${IFS}cat${IFS}/etc/passwd",
            "| ${PATH:0:4}cat /etc/passwd",  # /bin/cat
            
            # プロセス置換攻撃
            "; cat <(echo /etc/passwd)",
            "| exec 3< /etc/passwd && cat <&3",
            
            # 算術式展開
            "; $((1+1)) && cat /etc/passwd",
            "| echo $((0x2f)) && ls -la",
            
            # Unicode回避
            "； cat /etc/passwd",  # 全角セミコロン
            "｜ ls -la",           # 全角パイプ
            
            # エンコード回避
            "; %63%61%74 /etc/passwd",  # URL encoded 'cat'
            "| \\143\\141\\164 /etc/passwd",  # Octal encoded
        ]
        
        # 2. 新しいSQLインジェクション技術
        novel_sql_injections = [
            # JSON関数悪用
            "'; INSERT INTO users VALUES (JSON_OBJECT('id',1,'user','admin'))-- ",
            
            # XML関数悪用  
            "'; SELECT EXTRACTVALUE('<user>admin</user>', '/user')-- ",
            
            # 文字列関数悪用
            "'; SELECT CHAR(97,100,109,105,110)-- ",  # 'admin'
            
            # 条件関数悪用
            "'; IF(1=1,SLEEP(5),0)-- ",
            
            # 正規表現悪用
            "' RLIKE 'admin' OR '1'='1",
            
            # ベンチマーク攻撃
            "'; SELECT BENCHMARK(5000000,MD5('test'))-- ",
        ]
        
        # 3. 新しいXSS技術
        novel_xss_attacks = [
            # CSS式攻撃
            "<style>@import'javascript:alert(\"XSS\")';</style>",
            
            # データURI攻撃
            "<iframe src='data:text/html,<script>alert(\"XSS\")</script>'></iframe>",
            
            # VBScript攻撃
            "<img src=x onerror='vbscript:msgbox(\"XSS\")'>",
            
            # ECMAScript 6攻撃
            "<script>(() => alert`XSS`)();</script>",
            
            # テンプレートリテラル攻撃
            "<script>alert`${document.domain}`</script>",
            
            # エンティティ回避
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
        ]
        
        # 4. 高エントロピー/難読化攻撃
        obfuscated_attacks = [
            # Base64エンコード
            "'; exec(base64_decode('Y2F0IC9ldGMvcGFzc3dk'))-- ",
            
            # ROT13エンコード  
            "; $(echo 'png /rgp/cnffjq' | tr 'a-zA-Z' 'n-za-mN-ZA-M')",
            
            # 16進エンコード
            "; \\x63\\x61\\x74 \\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64",
            
            # 長いランダム文字列+ペイロード
            "A" * 500 + "; cat /etc/passwd",
            
            # 大文字小文字混合回避
            "'; UnIoN SeLeCt 1,UsEr(),DaTaBaSe()-- ",
        ]
        
        # 5. プロトコル/パーサー攻撃
        protocol_attacks = [
            # HTTPヘッダインジェクション
            "test\\r\\nX-Injected: malicious",
            
            # パラメータ汚染
            "param=normal&param=; cat /etc/passwd",
            
            # フラグメント識別子悪用
            "#'; DROP TABLE users-- ",
            
            # Unicodeエンコード
            "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",
        ]
        
        all_attacks = [
            ("Novel Command Injection", novel_command_injections),
            ("Novel SQL Injection", novel_sql_injections), 
            ("Novel XSS", novel_xss_attacks),
            ("Obfuscated Attacks", obfuscated_attacks),
            ("Protocol Attacks", protocol_attacks)
        ]
        
        total_detected = 0
        total_tested = 0
        category_results = {}
        
        print("未知攻撃検知テスト開始")
        print("=" * 50)
        
        for category, attacks in all_attacks:
            print(f"\n--- {category} ---")
            detected_count = 0
            
            for i, payload in enumerate(attacks, 1):
                total_tested += 1
                detection_result = self.test_attack_detection(payload, category)
                
                if detection_result['detected']:
                    detected_count += 1
                    total_detected += 1
                    print(f"OK {i:2d}: {payload[:50]}... -> {detection_result['type']} ({detection_result['severity']})")
                else:
                    print(f"NG {i:2d}: {payload[:50]}...")
                    
                time.sleep(0.2)  # サーバー負荷軽減
            
            detection_rate = (detected_count / len(attacks)) * 100
            category_results[category] = {
                'detected': detected_count,
                'total': len(attacks),
                'rate': detection_rate
            }
            
            print(f"{category}: {detected_count}/{len(attacks)} ({detection_rate:.1f}%)")
        
        # 最終結果
        overall_rate = (total_detected / total_tested) * 100
        
        print("\n" + "=" * 50)
        print("未知攻撃検知テスト結果")
        print("=" * 50)
        print(f"総合検知率: {total_detected}/{total_tested} ({overall_rate:.1f}%)")
        print("\nカテゴリ別詳細:")
        
        for category, result in category_results.items():
            print(f"  {category}: {result['detected']}/{result['total']} ({result['rate']:.1f}%)")
        
        # 評価
        if overall_rate >= 70:
            print(f"\n[EXCELLENT] 優秀: {overall_rate:.1f}%の未知攻撃検知率を達成")
        elif overall_rate >= 50:
            print(f"\n[GOOD] 良好: {overall_rate:.1f}%の未知攻撃検知率を達成")  
        elif overall_rate >= 30:
            print(f"\n[WARNING] 改善余地あり: {overall_rate:.1f}%の未知攻撃検知率")
        else:
            print(f"\n[ERROR] 大幅改善必要: {overall_rate:.1f}%の未知攻撃検知率")
        
        return {
            'overall_rate': overall_rate,
            'total_detected': total_detected,
            'total_tested': total_tested,
            'category_results': category_results
        }

def main():
    tester = UnknownAttackTester()
    
    print("待機中... サーバー起動を確認")
    time.sleep(2)
    
    # ヘルスチェック
    try:
        honeypot_response = requests.get(f"{tester.honeypot_url}/", timeout=5)
        mcp_response = requests.get(f"{tester.data_url}/api/health", timeout=5)
        
        if honeypot_response.status_code == 200 and mcp_response.status_code == 200:
            print("[OK] サーバー接続確認完了")
        else:
            print("[ERROR] サーバー接続失敗")
            return
            
    except Exception as e:
        print(f"[ERROR] サーバー接続エラー: {e}")
        return
    
    # テスト実行
    results = tester.run_unknown_attack_detection_test()
    
    # 結果を保存
    with open('unknown_attack_detection_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\n結果をunknown_attack_detection_results.jsonに保存しました")

if __name__ == "__main__":
    main()
