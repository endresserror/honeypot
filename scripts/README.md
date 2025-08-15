# スクリプトディレクトリ

このディレクトリには、脆弱性スキャナーシステムを管理するためのユーティリティスクリプトが含まれています。

## データベース管理

### `db_manager.py`

データサーバー用の包括的なデータベース管理スクリプトです。

**使用方法:**
```bash
# データベースをテーブルで初期化
python scripts/db_manager.py init

# 新しいマイグレーションを作成
python scripts/db_manager.py migrate "新機能の追加"

# 保留中のマイグレーションを適用
python scripts/db_manager.py upgrade

# 最後のマイグレーションをロールバック
python scripts/db_manager.py downgrade

# データベースのバックアップを作成
python scripts/db_manager.py backup
python scripts/db_manager.py backup --path backup_file.sql

# バックアップから復元
python scripts/db_manager.py restore backup_file.sql

# データベースをリセット（すべてのテーブルを削除して再作成）
python scripts/db_manager.py reset

# データベースのステータスを表示
python scripts/db_manager.py status

# テスト用のサンプルデータを作成
python scripts/db_manager.py sample-data
```

### `create_sample_data.py`

テストおよびデモンストレーション用に、サンプルの攻撃ログ、シグネチャ、およびベースラインレスポンスを作成します。

**使用方法:**
```bash
python scripts/create_sample_data.py
```

## 開発環境

### `setup_dev.sh`

仮想環境、依存関係、設定など、完全な開発環境をセットアップします。

**使用方法:**
```bash
./scripts/setup_dev.sh
```

**機能:**
- Python仮想環境の作成
- すべてのPython依存関係のインストール
- ダッシュボード用のNode.js依存関係のインストール
- 必要なディレクトリの作成
- デフォルトの.envファイルの作成
- セットアップ手順の提供

## データベースの初期化

### `init-db.sql`

データベースユーザー、権限、および拡張機能をセットアップするPostgreSQL初期化スクリプトです。

**使用方法:**
このスクリプトはDocker Composeによって自動的に使用されますが、手動で実行することもできます。
```bash
psql -U postgres -d vulnerability_scanner -f scripts/init-db.sql
```

## スクリプトの依存関係

ほとんどのスクリプトは、データサーバー環境と依存関係を必要とします。以下を確認してください。

1. Python 3.9以降がインストールされていること
2. 仮想環境のセットアップ: `python -m venv venv`
3. 仮想環境のアクティベート: `source venv/bin/activate`
4. 依存関係のインストール: `pip install -r requirements.txt`
5. 環境変数の設定（.env.exampleを参照）

## 環境変数

スクリプトはこれらの環境変数を使用します。

- `DATABASE_URL`: PostgreSQL接続文字列
- `FLASK_APP`: Flaskアプリケーションのエントリポイント
- `FLASK_ENV`: Flask環境（開発/本番）
- `SECRET_KEY`: Flaskシークレットキー
- `DATA_SERVER_URL`: 他のコンポーネント用のデータサーバーURL

## トラブルシューティング

### データベース接続の問題
1. PostgreSQLが動作していることを確認
2. DATABASE_URL形式を確認: `postgresql://user:password@host:port/database`
3. データベースとユーザーが存在することを確認
4. ネットワーク接続を確認

### マイグレーションの問題
1. データベースが初期化されていることを確認: `python scripts/db_manager.py init`
2. 競合するマイグレーションを確認
3. `data-server/migrations/versions/` のマイグレーションファイルを確認

### 権限の問題
1. データベースユーザーが適切な権限を持っていることを確認
2. スクリプトファイルのファイル権限を確認
3. 仮想環境がアクティベートされていることを確認

## ベストプラクティス

1. **大きな変更の前には必ずバックアップを取る:**
   ```bash
   python scripts/db_manager.py backup --path before_upgrade.sql
   ```

2. **開発環境でマイグレーションを最初にテストする:**
   ```bash
   python scripts/db_manager.py migrate "変更の説明"
   python scripts/db_manager.py upgrade
   ```

3. **テスト用にサンプルデータを使用する:**
   ```bash
   python scripts/db_manager.py sample-data
   ```

4. **データベースのステータスを監視する:**
   ```bash
   python scripts/db_manager.py status
   ```