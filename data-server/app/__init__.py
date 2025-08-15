"""
MCPサーバーFlaskアプリケーションファクトリー
"""

import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager
import logging
from logging.handlers import RotatingFileHandler
from app.config import config_manager
from app.core.exceptions import ConfigurationError

# 拡張機能を初期化
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()

def create_app(config_path=None):
    """Flaskアプリケーション作成のファクトリーパターン"""
    app = Flask(__name__)
    
    # 設定をロード
    try:
        if config_path:
            config_manager.config_path = config_path
        config = config_manager.load_config()
    except Exception as e:
        raise ConfigurationError(f"Failed to load configuration: {str(e)}")
    
    # Flask設定
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', config['flask']['secret_key'])
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', config['database']['url'])
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': config['database']['pool_size'],
        'max_overflow': config['database']['max_overflow'],
        'pool_timeout': config['database']['pool_timeout'],
    }
    app.config['JWT_SECRET_KEY'] = config['security']['jwt_secret']
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = config['security']['token_expiry']
    
    # 他のモジュールでアクセス用に完全な設定を保存
    app.config['SCANNER_CONFIG'] = config
    
    # 拡張機能を初期化
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    CORS(app)
    
    # Configure logging
    setup_logging(app, config['logging'])
    
    # Register blueprints
    from app.api import api_bp
    from app.api.zap_integration import zap_bp
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(zap_bp, url_prefix='/api/zap')
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    app.logger.info('MCP Server application started successfully')
    
    return app

def setup_logging(app, logging_config):
    """Configure application logging."""
    log_level = getattr(logging, logging_config['level'].upper())
    
    # Ensure log directory exists
    log_dir = os.path.dirname(logging_config['file'])
    os.makedirs(log_dir, exist_ok=True)
    
    # Set up rotating file handler
    file_handler = RotatingFileHandler(
        logging_config['file'],
        maxBytes=logging_config['max_bytes'],
        backupCount=logging_config['backup_count']
    )
    
    file_handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    ))
    
    file_handler.setLevel(log_level)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(log_level)