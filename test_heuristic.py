#!/usr/bin/env python3
"""
ヒューリスティック検知システムのテストスクリプト
"""
import requests
import time
import json

def test_normal_request():
    """通常のリクエストをテスト"""
    url = "http://localhost:8080/search.php?query=normal_search_term"
    response = requests.get(url)
    print(f"Normal request: {response.status_code}")
    return response.status_code == 200

def test_high_entropy_attack():
    """高エントロピー攻撃をテスト"""
    # URLエンコードされた悪意のあるペイロード
    malicious_payload = "%3Cscript%3Ealert%28%27XSS%27%29%3B%2F%2F%26%23x27%3B%26%23x22%3B%26%23x3E%3B%26%23x3C%3B%26%23x2F"
    url = f"http://localhost:8080/search.php?query={malicious_payload}"
    response = requests.get(url)
    print(f"High entropy attack: {response.status_code}")
    return response.status_code == 200

def test_long_parameter_attack():
    """長いパラメータ攻撃をテスト"""
    long_payload = "A" * 1000 + "%3Cscript%3E" + "B" * 500
    url = f"http://localhost:8080/search.php?query={long_payload}"
    response = requests.get(url)
    print(f"Long parameter attack: {response.status_code}")
    return response.status_code == 200

def check_detection_logs():
    """検知ログを確認"""
    try:
        response = requests.get("http://localhost:5001/api/logs?limit=5")
        if response.status_code == 200:
            data = response.json()
            logs = data.get('logs', [])
            print(f"\n=== 検知されたログ ({len(logs)}件) ===")
            for i, log in enumerate(logs, 1):
                print(f"{i}. {log.get('timestamp', 'N/A')}")
                
                # リクエストURL/URIを表示
                request = log.get('request', {})
                uri = request.get('uri', 'N/A')
                print(f"   URL: {uri}")
                
                # ヒューリスティック検知結果があるかチェック
                if 'heuristic_anomalies' in log:
                    anomalies = log['heuristic_anomalies']
                    if anomalies:
                        print(f"   ヒューリスティック検知: {anomalies}")
                        
                # 基本的な攻撃検知情報
                if 'attack_type' in log:
                    print(f"   攻撃タイプ: {log['attack_type']}")
                    
                # 生成されたシグネチャ数
                signatures = log.get('signaturesGenerated', 0)
                print(f"   生成シグネチャ数: {signatures}")
                print()
        else:
            print(f"ログ取得エラー: {response.status_code}")
    except Exception as e:
        print(f"ログ確認中にエラー: {e}")

def main():
    print("=== ヒューリスティック検知システム テスト ===\n")
    
    # サーバーの健康チェック
    try:
        honeypot_health = requests.get("http://localhost:8080/").status_code
        mcp_health = requests.get("http://localhost:5001/api/health").status_code
        print(f"ハニーポット: {'OK' if honeypot_health == 200 else 'NG'}")
        print(f"分析サーバー: {'OK' if mcp_health == 200 else 'NG'}")
        print()
    except Exception as e:
        print(f"サーバー接続エラー: {e}")
        return
    
    # テスト実行
    print("1. 通常のリクエストをテスト...")
    test_normal_request()
    time.sleep(2)
    
    print("2. 高エントロピー攻撃をテスト...")
    test_high_entropy_attack()
    time.sleep(2)
    
    print("3. 長いパラメータ攻撃をテスト...")
    test_long_parameter_attack()
    time.sleep(3)
    
    # ログ確認
    print("4. 検知ログを確認...")
    check_detection_logs()

if __name__ == "__main__":
    main()
