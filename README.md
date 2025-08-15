# ハニーポット実攻撃ベースOWASP ZAP自動シグネチャ生成システム

## 概要

実攻撃データからOWASP ZAP用の高精度シグネチャを自動生成するセキュリティシステムです。ハニーポットで観測した実際の攻撃パターンから業界標準のZAPルールを自動生成し、継続的にセキュリティ検査を強化します。

## 最新検証結果

### システム検証結果（構造改善版）
- **データ統合サーバー**: モジュラー構造への改善完了・正常起動確認済み
- **ハニーポット**: 強化された攻撃検知・記録機能（15.0%コマンド注入検出率達成）
- **強化ZAPシグネチャ生成**: 3種類の高品質ルール生成成功
- **包括的攻撃検証**: 102種類の実攻撃ペイロードで検証完了
- **コード品質**: 絵文字削除・モジュラー設計・エラーハンドリング強化

### 検証された攻撃パターン（最新）
- **SQLインジェクション**: 100%検出率（12/12）- Union/Error/Time/Boolean-based全対応
- **XSS攻撃**: 100%反映率（10/10）- フィルター回避技術対応
- **コマンドインジェクション**: 15.0%検出率（12/80）- 実行証拠ベース検証

## システム構成

```
攻撃者 → ハニーポット → データ統合サーバー ← 管理者
                          ↓
                    OWASP ZAP
```

### コンポーネント
1. **鳩松Bankハニーポット** - 銀行風サイトで攻撃を誘引・記録
2. **データ統合サーバー** - ログ分析とZAPルール自動生成
3. **管理ダッシュボード** - ルール承認・管理のWebUI
4. **OWASP ZAP統合** - 業界標準ツールとの連携

## クイックスタート

### 1. システム起動

```bash
# データ統合サーバー起動（ターミナル1）
cd data-server && python3 app.py

# ハニーポット起動（ターミナル2）
cd honeypot && python3 app.py

# ダッシュボード起動（ターミナル3）
cd dashboard && npm install && npm start
```

### 2. 攻撃シミュレーション

```bash
# SQLインジェクション攻撃
curl "http://localhost:8080/login.php" \
  -d "customer_number=admin' OR 1=1--&login_password=test"

# XSS攻撃
curl "http://localhost:8080/search.php" \
  -d "query=<script>alert('XSS')</script>"

# コマンドインジェクション
curl "http://localhost:8080/debug.php?cmd=; cat /etc/passwd"
```

### 3. 強化シグネチャ生成・取得

```bash
# 強化シグネチャ生成
python3 enhanced_signature_generator.py

# 包括的攻撃テスト実行
python3 enhanced_attack_test.py

# ZAPシグネチャをOWASP ZAPにインストール
python3 zap_integration/zap_client.py install \
  --signatures enhanced_zap_signatures/ \
  --zap-scripts ~/.ZAP/scripts/
```

## 確認用URL

- **ハニーポット（鳩松Bank）**: http://localhost:8080
- **データ統合サーバーAPI**: http://localhost:5001/api/health
- **管理ダッシュボード**: http://localhost:3000
- **強化ZAPシグネチャ**: enhanced_zap_signatures/

## 強化OWASP ZAPシグネチャ

### 生成される高品質シグネチャ

1. **enhanced_command_injection.js** - 60+種類の包括的コマンド注入検知
2. **improved_sql_injection.js** - Union/Error/Time/Boolean-based全対応検知
3. **comprehensive_xss.js** - フィルター回避技術対応検知
4. **実攻撃ベース検証** - 理論ではなく実際の攻撃結果に基づく検証

### ZAP統合API

```bash
# アクティブスキャンルール取得
curl "http://localhost:5001/api/zap/active-scan-rules" | jq .

# パッシブスキャンルール取得  
curl "http://localhost:5001/api/zap/passive-scan-rules" | jq .

# ファジングペイロード取得
curl "http://localhost:5001/api/zap/fuzzing-payloads/sql_injection" | jq .

# ZAPルール一式をZIPで取得
curl "http://localhost:5001/api/zap/export/zap-scripts" -o zap_rules.zip
```

## インストール手順

### 前提条件
- Python 3.9以上
- Node.js 16以上  
- PostgreSQL 13以上
- OWASP ZAP（オプション）

### 1. 依存関係インストール

```bash
# PostgreSQL設定
sudo systemctl start postgresql
sudo -u postgres psql -c "CREATE USER scanner_user WITH PASSWORD 'scanner_password';"
sudo -u postgres createdb -O scanner_user vulnerability_scanner

# Python依存関係
cd data-server
pip3 install -r requirements.txt

# Node.js依存関係
cd ../dashboard
npm install
```

### 2. データベース初期化

```bash
cd data-server
python3 -c "
from app import create_app, db
app = create_app()
with app.app_context():
    db.create_all()
    print('Database initialized')
"
```

## 実装された機能詳細

### ハニーポット（鳩松Bank）
- **認証システム**: セッション管理機能
- **意図的脆弱性**: SQLi、XSS、コマンドインジェクション
- **完全ログ記録**: 全HTTP通信の詳細記録
- **攻撃検出**: リアルタイムパターン分析

### データ統合サーバー（改善版）
- **モジュラー設計**: サービスファクトリー・リポジトリパターン適用
- **設定管理**: 中央集約型設定システム
- **ZAPルール生成**: JavaScript形式のスキャンルール作成
- **攻撃分析**: ペイロード抽出・分類機能
- **品質管理**: 信頼度スコアリング
- **API提供**: RESTful ZAP統合API
- **エラーハンドリング**: カスタム例外とバリデーション

### ZAP統合クライアント
- **ルール同期**: ZAP統合サーバーからの自動ダウンロード
- **ZAP連携**: スクリプトの自動インストール
- **統計表示**: 攻撃動向・ルール生成状況の可視化

## 動作検証手順

### 1. システム起動確認

```bash
# サービス稼働状況
curl -I http://localhost:5001/api/health    # データ統合サーバー
curl -I http://localhost:8080/              # ハニーポット  
curl -I http://localhost:3000/              # ダッシュボード
```

### 2. 攻撃ログ収集テスト

```bash
# 攻撃実行
curl "http://localhost:8080/login.php" -d "customer_number=admin' UNION SELECT version(),user(),database()--&login_password=test"

# ログ確認（30秒後）
curl -s "http://localhost:5001/api/logs?limit=3" | python3 -m json.tool
```

### 3. ZAPルール生成テスト

```bash
# ZAP統計確認
python3 zap_integration/zap_client.py stats --server http://localhost:5001

# ルール生成・ダウンロードテスト  
python3 test_zap_generator.py
```

## 生成されるZAPルール例

### アクティブスキャンルール（JavaScript）

```javascript
// Generated ZAP Active Scanner Rule
// Attack Type: sql_injection
// Generated from honeypot data: 2025-08-15T00:44:53

function scanNode(as, msg) {
    var payload = "admin' OR 1=1--";
    var param = msg.getRequestHeader().getURI().getEscapedQuery();
    
    if (param) {
        var testMsg = msg.cloneRequest();
        var modifiedParam = param.replace(/([^&=]+)=([^&]*)/g, '$1=' + encodeURIComponent(payload));
        testMsg.getRequestHeader().getURI().setEscapedQuery(modifiedParam);
        
        as.sendAndReceive(testMsg, false, false);
        
        if (isVulnerable(testMsg.getResponseBody().toString())) {
            as.raiseAlert(getRisk(), getConfidence(), getName(), 
                         getDescription(), /*...*/);
        }
    }
}

function isVulnerable(responseBody) {
    var indicators = ["MySQL Error", "SQL syntax", "mysql_fetch"];
    return indicators.some(ind => responseBody.includes(ind));
}
```

## システム終了

```bash
# 全プロセス終了
pkill -f "python.*app\.py"
pkill -f "npm start"

# PostgreSQL停止（オプション）
sudo systemctl stop postgresql
```

## トラブルシューティング

### よくある問題

#### データ統合サーバー起動エラー
```bash
# 依存関係インストール
pip3 install psycopg2-binary flask flask-sqlalchemy

# PostgreSQL接続確認
PGPASSWORD=scanner_password psql -h localhost -U scanner_user -d vulnerability_scanner -c "SELECT 1;"
```

#### ZAP統合API エラー
```bash
# APIエンドポイント確認
curl -v "http://localhost:5001/api/zap/statistics"

# サンプルデータ追加（テスト用）
python3 add_sample_data.py
```

## 技術仕様

### 対応攻撃タイプ
- **SQLインジェクション**: Union-based、Error-based、Blind
- **XSS**: Reflected、Stored、DOM-based
- **コマンドインジェクション**: OS Command Execution
- **パストラバーサル**: Directory Traversal
- **XXE**: XML External Entity

### アーキテクチャ仕様（改善版）
- **設計パターン**: サービスファクトリー、リポジトリ、ファクトリーメソッド
- **設定管理**: YAML設定ファイル + 環境変数サポート
- **例外処理**: カスタム例外クラス階層
- **データ検証**: 専用バリデーションユーティリティ
- **ログ管理**: 構造化ログとローテーション

### ZAPルール仕様
- **リスクレベル**: 0（情報）～3（高）の4段階
- **信頼度**: 0（偽陽性）～4（確実）の5段階  
- **形式**: JavaScript（ZAP標準）
- **自動分類**: 攻撃タイプと重要度の自動判定

## セキュリティ考慮事項

**重要**: このシステムは防御的セキュリティ研究専用です
- 自身が所有するシステムでのみ使用してください
- 不正アクセスや攻撃に使用しないでください
- 生成されたルールは脆弱性修正のためのみ使用してください

## ライセンス

MITライセンスの下で公開されています。詳細はLICENSEファイルを参照してください。