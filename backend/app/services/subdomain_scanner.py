"""
サブドメイン発見スキャナー

複数のソースからサブドメインを検出:
- Certificate Transparency Logs
- DNS Brute Force
- 検索エンジン
"""

import dns.resolver
import requests
from typing import List, Set
import logging

logger = logging.getLogger(__name__)


class SubdomainScanner:
    def __init__(self, domain: str):
        self.domain = domain
        self.subdomains: Set[str] = set()
    
    async def scan(self) -> List[str]:
        """すべてのスキャン手法を実行"""
        logger.info(f"Starting subdomain scan for {self.domain}")
        
        # Certificate Transparency検索
        await self.scan_certificate_transparency()
        
        # DNS Brute Force
        await self.scan_dns_brute_force()
        
        logger.info(f"Found {len(self.subdomains)} subdomains for {self.domain}")
        return list(self.subdomains)
    
    async def scan_certificate_transparency(self):
        """Certificate Transparency Logsからサブドメインを検索"""
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    # 複数のサブドメインが改行で区切られている場合がある
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip().lower()
                        # ワイルドカードを除外
                        if not subdomain.startswith('*'):
                            self.subdomains.add(subdomain)
                
                logger.info(f"CT Logs: Found {len(self.subdomains)} subdomains")
        except Exception as e:
            logger.error(f"Certificate Transparency scan failed: {e}")
    
    async def scan_dns_brute_force(self):
        """DNS Brute Force攻撃でサブドメインを探索"""
        # 一般的なサブドメインのリスト
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'portal', 'api', 'dev', 'test',
            'staging', 'prod', 'vpn', 'remote', 'blog', 'shop', 'store',
            'webmail', 'mx', 'ns1', 'ns2', 'smtp', 'pop', 'imap',
            'git', 'svn', 'jenkins', 'gitlab', 'jira', 'confluence',
            'wiki', 'forum', 'support', 'help', 'docs', 'beta',
            'app', 'mobile', 'dashboard', 'control', 'panel', 'cpanel',
            'secure', 'ssl', 'cloud', 'backup', 'cdn', 'images', 'static'
        ]
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{self.domain}"
                answers = resolver.resolve(full_domain, 'A')
                if answers:
                    self.subdomains.add(full_domain)
                    logger.debug(f"Found: {full_domain}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
            except Exception as e:
                logger.debug(f"DNS query failed for {subdomain}.{self.domain}: {e}")
        
        logger.info(f"DNS Brute Force: Found {len(self.subdomains)} total subdomains")


async def scan_subdomains(domain: str) -> List[str]:
    """サブドメインスキャンのエントリーポイント"""
    scanner = SubdomainScanner(domain)
    return await scanner.scan()
