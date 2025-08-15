#!/usr/bin/env python3
"""
OWASP ZAP統合クライアント
ZAP統合サーバーから生成されたシグネチャをZAPに自動インポートするツール
"""

import os
import sys
import json
import requests
import zipfile
import click
from pathlib import Path
from datetime import datetime
import time


class ZAPIntegrationClient:
    """ZAP統合クライアント"""
    
    def __init__(self, zap_server_url: str, zap_api_key: str = None, zap_url: str = "http://localhost:8080"):
        self.zap_server_url = zap_server_url.rstrip('/')
        self.zap_url = zap_url.rstrip('/')
        self.zap_api_key = zap_api_key
        self.session = requests.Session()
        
    def get_zap_statistics(self) -> dict:
        """ZAP統合サーバーからZAP統計情報を取得"""
        try:
            response = self.session.get(f"{self.zap_server_url}/api/zap/statistics")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Failed to get statistics: {e}")
    
    def download_zap_scripts(self, output_dir: str, attack_types: list = None) -> str:
        """ZAP用スクリプト一式をダウンロード"""
        
        params = {}
        if attack_types:
            params['attack_types'] = attack_types
        
        try:
            response = self.session.get(
                f"{self.zap_server_url}/api/zap/export/zap-scripts",
                params=params,
                stream=True
            )
            response.raise_for_status()
            
            # ZIPファイルを保存
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            zip_path = os.path.join(output_dir, f"zap_scripts_{timestamp}.zip")
            
            os.makedirs(output_dir, exist_ok=True)
            
            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            return zip_path
            
        except Exception as e:
            raise Exception(f"Failed to download scripts: {e}")
    
    def extract_and_install_scripts(self, zip_path: str, zap_scripts_dir: str) -> dict:
        """スクリプトを展開してZAPディレクトリにインストール"""
        
        if not os.path.exists(zap_scripts_dir):
            os.makedirs(zap_scripts_dir, exist_ok=True)
        
        installed_files = {
            'active_scan': [],
            'passive_scan': [],
            'fuzzing': [],
            'context': []
        }
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_file:
                
                for file_info in zip_file.filelist:
                    if file_info.filename.endswith('/'):
                        continue
                    
                    file_content = zip_file.read(file_info)
                    
                    # インストール先を決定
                    if file_info.filename.startswith('active_scan/'):
                        install_path = os.path.join(zap_scripts_dir, 'rules', 'active', os.path.basename(file_info.filename))
                        installed_files['active_scan'].append(install_path)
                    elif file_info.filename.startswith('passive_scan/'):
                        install_path = os.path.join(zap_scripts_dir, 'rules', 'passive', os.path.basename(file_info.filename))
                        installed_files['passive_scan'].append(install_path)
                    elif file_info.filename.startswith('fuzzing/'):
                        install_path = os.path.join(zap_scripts_dir, 'payloads', os.path.basename(file_info.filename))
                        installed_files['fuzzing'].append(install_path)
                    elif file_info.filename.startswith('context/'):
                        install_path = os.path.join(zap_scripts_dir, 'context', os.path.basename(file_info.filename))
                        installed_files['context'].append(install_path)
                    else:
                        continue  # README等はスキップ
                    
                    # ディレクトリを作成してファイルを保存
                    os.makedirs(os.path.dirname(install_path), exist_ok=True)
                    
                    with open(install_path, 'wb') as f:
                        f.write(file_content)
            
            return installed_files
            
        except Exception as e:
            raise Exception(f"Failed to extract and install scripts: {e}")
    
    def sync_with_zap_api(self, installed_files: dict) -> dict:
        """ZAP APIを使用してスクリプトを同期"""
        
        if not self.zap_api_key:
            return {'message': 'No ZAP API key provided, skipping API sync'}
        
        sync_results = {
            'rules_loaded': 0,
            'payloads_imported': 0,
            'errors': []
        }
        
        try:
            # ZAPの稼働確認
            zap_status = requests.get(f"{self.zap_url}/JSON/core/view/version/", 
                                     params={'apikey': self.zap_api_key}, timeout=5)
            if zap_status.status_code != 200:
                raise Exception("ZAP is not running or API key is invalid")
            
            # アクティブスキャンルールをロード
            for rule_file in installed_files.get('active_scan', []):
                try:
                    response = requests.get(
                        f"{self.zap_url}/JSON/script/action/load/",
                        params={
                            'apikey': self.zap_api_key,
                            'scriptName': os.path.basename(rule_file),
                            'scriptType': 'active',
                            'scriptEngine': 'JavaScript',
                            'fileName': rule_file
                        }
                    )
                    if response.status_code == 200:
                        sync_results['rules_loaded'] += 1
                    else:
                        sync_results['errors'].append(f"Failed to load {rule_file}: {response.text}")
                        
                except Exception as e:
                    sync_results['errors'].append(f"Error loading {rule_file}: {e}")
            
            # パッシブスキャンルールをロード
            for rule_file in installed_files.get('passive_scan', []):
                try:
                    response = requests.get(
                        f"{self.zap_url}/JSON/script/action/load/",
                        params={
                            'apikey': self.zap_api_key,
                            'scriptName': os.path.basename(rule_file),
                            'scriptType': 'passive',
                            'scriptEngine': 'JavaScript', 
                            'fileName': rule_file
                        }
                    )
                    if response.status_code == 200:
                        sync_results['rules_loaded'] += 1
                    else:
                        sync_results['errors'].append(f"Failed to load {rule_file}: {response.text}")
                        
                except Exception as e:
                    sync_results['errors'].append(f"Error loading {rule_file}: {e}")
            
            return sync_results
            
        except Exception as e:
            sync_results['errors'].append(f"ZAP API sync failed: {e}")
            return sync_results


@click.group()
def cli():
    """OWASP ZAP Integration Client"""
    pass


@cli.command()
@click.option('--server', default='http://localhost:5001', help='ZAP Integration Server URL')
def stats(server):
    """Get statistics from ZAP Integration server"""
    
    client = ZAPIntegrationClient(server)
    
    try:
        stats_data = client.get_zap_statistics()
        
        click.echo("=== ZAP Integration Statistics ===")
        click.echo(f"Generated at: {stats_data.get('generated_at', 'N/A')}")
        click.echo()
        
        click.echo("Attack Type Statistics:")
        for stat in stats_data.get('attack_type_statistics', []):
            click.echo(f"  • {stat['attack_type']}: {stat['count']} attacks")
        
        click.echo()
        click.echo("Potential ZAP Rules:")
        potential = stats_data.get('potential_rules', {})
        click.echo(f"  • Active Scan Rules: {potential.get('active_scan', 0)}")
        click.echo(f"  • Passive Scan Rules: {potential.get('passive_scan', 0)}")
        click.echo(f"  • Total: {potential.get('total', 0)}")
        
        click.echo()
        click.echo("Recent Attacks:")
        for attack in stats_data.get('recent_attacks', [])[:5]:
            click.echo(f"  • {attack['attack_type']} from {attack['source_ip']} at {attack['timestamp']}")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--server', default='http://localhost:5001', help='ZAP Integration Server URL')
@click.option('--output-dir', default='./zap_scripts', help='Output directory for downloaded scripts')
@click.option('--attack-types', help='Comma-separated list of attack types')
@click.option('--zap-scripts-dir', help='ZAP scripts directory (for auto-installation)')
@click.option('--zap-api-key', help='ZAP API key (for API integration)')
@click.option('--zap-url', default='http://localhost:8080', help='ZAP API URL')
def sync(server, output_dir, attack_types, zap_scripts_dir, zap_api_key, zap_url):
    """Download and sync ZAP scripts from ZAP Integration server"""
    
    attack_types_list = None
    if attack_types:
        attack_types_list = [t.strip() for t in attack_types.split(',')]
    
    client = ZAPIntegrationClient(server, zap_api_key, zap_url)
    
    try:
        click.echo("[INFO] Downloading ZAP scripts from ZAP Integration server...")
        zip_path = client.download_zap_scripts(output_dir, attack_types_list)
        click.echo(f"[OK] Downloaded: {zip_path}")
        
        if zap_scripts_dir:
            click.echo("[INFO] Installing scripts to ZAP directory...")
            installed_files = client.extract_and_install_scripts(zip_path, zap_scripts_dir)
            
            total_installed = sum(len(files) for files in installed_files.values())
            click.echo(f"[OK] Installed {total_installed} files:")
            
            for category, files in installed_files.items():
                if files:
                    click.echo(f"  • {category}: {len(files)} files")
            
            if zap_api_key:
                click.echo("[INFO] Syncing with ZAP API...")
                sync_results = client.sync_with_zap_api(installed_files)
                
                click.echo(f"[OK] Rules loaded: {sync_results.get('rules_loaded', 0)}")
                
                if sync_results.get('errors'):
                    click.echo("[WARNING] Errors occurred:")
                    for error in sync_results['errors']:
                        click.echo(f"    {error}")
        
        click.echo("[SUCCESS] Sync completed successfully!")
        
    except Exception as e:
        click.echo(f"[ERROR] Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--server', default='http://localhost:5001', help='ZAP Integration Server URL')
@click.option('--output-dir', default='./zap_scripts', help='Output directory')
@click.option('--attack-type', required=True, help='Attack type for payloads')
@click.option('--days', default=30, help='Days to look back for attack data')
def payloads(server, output_dir, attack_type, days):
    """Download fuzzing payloads for specific attack type"""
    
    client = ZAPIntegrationClient(server)
    
    try:
        click.echo(f"[INFO] Downloading fuzzing payloads for {attack_type}...")
        
        response = client.session.get(
            f"{client.zap_server_url}/api/zap/fuzzing-payloads/{attack_type}",
            params={'days': days}
        )
        response.raise_for_status()
        
        data = response.json()
        payload_file = data.get('payload_file')
        
        if not payload_file:
            click.echo("No payloads found for the specified attack type")
            return
        
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, payload_file['filename'])
        
        with open(output_path, 'w') as f:
            f.write(payload_file['content'])
        
        click.echo(f"[OK] Saved {payload_file['payload_count']} payloads to {output_path}")
        
    except Exception as e:
        click.echo(f"[ERROR] Error: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    cli()