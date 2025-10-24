"""
Shodan APIを使用した公開資産スキャナー

機能:
- IPアドレスの公開サービス検索
- ポートとバナー情報の収集
- 脆弱性の検出
"""

import shodan
from typing import Dict, List, Optional
import logging
from app.core.config import settings

logger = logging.getLogger(__name__)


class ShodanScanner:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.SHODAN_API_KEY
        if not self.api_key:
            logger.warning("Shodan API key not configured")
            self.api = None
        else:
            self.api = shodan.Shodan(self.api_key)
    
    async def scan_domain(self, domain: str) -> Dict:
        """ドメインに関連するすべての情報を検索"""
        if not self.api:
            logger.warning("Shodan API not available")
            return {"error": "Shodan API key not configured"}
        
        try:
            results = self.api.search(f"hostname:{domain}")
            
            assets = []
            for result in results['matches']:
                asset = {
                    'ip': result.get('ip_str'),
                    'port': result.get('port'),
                    'transport': result.get('transport', 'tcp'),
                    'product': result.get('product'),
                    'version': result.get('version'),
                    'os': result.get('os'),
                    'banner': result.get('data', '').strip(),
                    'hostnames': result.get('hostnames', []),
                    'location': {
                        'country': result.get('location', {}).get('country_name'),
                        'city': result.get('location', {}).get('city'),
                    },
                    'vulns': result.get('vulns', []),
                    'tags': result.get('tags', []),
                }
                assets.append(asset)
            
            return {
                'total': results.get('total', 0),
                'assets': assets
            }
        
        except shodan.APIError as e:
            logger.error(f"Shodan API error: {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Shodan scan failed: {e}")
            return {"error": str(e)}
    
    async def scan_ip(self, ip: str) -> Dict:
        """特定のIPアドレスの詳細情報を取得"""
        if not self.api:
            return {"error": "Shodan API key not configured"}
        
        try:
            host = self.api.host(ip)
            
            ports_info = []
            for item in host.get('data', []):
                ports_info.append({
                    'port': item.get('port'),
                    'transport': item.get('transport', 'tcp'),
                    'product': item.get('product'),
                    'version': item.get('version'),
                    'banner': item.get('data', '').strip(),
                })
            
            return {
                'ip': host.get('ip_str'),
                'hostnames': host.get('hostnames', []),
                'os': host.get('os'),
                'ports': host.get('ports', []),
                'ports_info': ports_info,
                'vulns': host.get('vulns', []),
                'tags': host.get('tags', []),
                'location': {
                    'country': host.get('country_name'),
                    'city': host.get('city'),
                    'organization': host.get('org'),
                    'isp': host.get('isp'),
                },
                'last_update': host.get('last_update'),
            }
        
        except shodan.APIError as e:
            logger.error(f"Shodan API error for IP {ip}: {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Shodan IP scan failed: {e}")
            return {"error": str(e)}


async def scan_with_shodan(target: str, scan_type: str = "domain") -> Dict:
    """
    Shodanスキャンのエントリーポイント
    
    Args:
        target: ドメインまたはIPアドレス
        scan_type: "domain" または "ip"
    """
    scanner = ShodanScanner()
    
    if scan_type == "domain":
        return await scanner.scan_domain(target)
    elif scan_type == "ip":
        return await scanner.scan_ip(target)
    else:
        return {"error": f"Invalid scan_type: {scan_type}"}
