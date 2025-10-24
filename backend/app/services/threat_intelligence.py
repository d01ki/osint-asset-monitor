"""
脅威インテリジェンスフィード統合

複数のTIソースから脅威情報を収集:
- AlienVault OTX
- Abuse.ch (URLhaus, Feodo Tracker, ThreatFox)
- CIRCL CVE Search
- VirusTotal
"""

import requests
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from app.core.config import settings

logger = logging.getLogger(__name__)


class ThreatIntelligenceAggregator:
    """脅威インテリジェンス統合クラス"""
    
    def __init__(self):
        self.vt_api_key = settings.VIRUSTOTAL_API_KEY
        self.feeds = {
            'alienvault_otx': 'https://otx.alienvault.com/api/v1',
            'urlhaus': 'https://urlhaus-api.abuse.ch/v1',
            'feodo': 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
            'threatfox': 'https://threatfox-api.abuse.ch/api/v1/',
            'circl_cve': 'https://cve.circl.lu/api',
        }
    
    async def get_threat_intel_for_domain(self, domain: str) -> Dict:
        """ドメインに関する脅威情報を収集"""
        results = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'sources': {}
        }
        
        # AlienVault OTX
        results['sources']['alienvault'] = await self._query_alienvault(domain)
        
        # URLhaus
        results['sources']['urlhaus'] = await self._query_urlhaus(domain)
        
        # VirusTotal
        if self.vt_api_key:
            results['sources']['virustotal'] = await self._query_virustotal_domain(domain)
        
        # 脅威スコアを計算
        results['threat_score'] = self._calculate_threat_score(results['sources'])
        results['risk_level'] = self._determine_risk_level(results['threat_score'])
        
        return results
    
    async def get_threat_intel_for_ip(self, ip: str) -> Dict:
        """IPアドレスに関する脅威情報を収集"""
        results = {
            'ip': ip,
            'timestamp': datetime.utcnow().isoformat(),
            'sources': {}
        }
        
        # AlienVault OTX
        results['sources']['alienvault'] = await self._query_alienvault_ip(ip)
        
        # Feodo Tracker (C2サーバー)
        results['sources']['feodo'] = await self._query_feodo(ip)
        
        # ThreatFox
        results['sources']['threatfox'] = await self._query_threatfox_ip(ip)
        
        # VirusTotal
        if self.vt_api_key:
            results['sources']['virustotal'] = await self._query_virustotal_ip(ip)
        
        # 脅威スコアを計算
        results['threat_score'] = self._calculate_threat_score(results['sources'])
        results['risk_level'] = self._determine_risk_level(results['threat_score'])
        
        return results
    
    async def get_threat_intel_for_hash(self, file_hash: str) -> Dict:
        """ファイルハッシュに関する脅威情報を収集"""
        results = {
            'hash': file_hash,
            'timestamp': datetime.utcnow().isoformat(),
            'sources': {}
        }
        
        # ThreatFox
        results['sources']['threatfox'] = await self._query_threatfox_hash(file_hash)
        
        # VirusTotal
        if self.vt_api_key:
            results['sources']['virustotal'] = await self._query_virustotal_hash(file_hash)
        
        return results
    
    # AlienVault OTX クエリ
    async def _query_alienvault(self, domain: str) -> Dict:
        """AlienVault OTXから脅威情報を取得"""
        try:
            url = f"{self.feeds['alienvault_otx']}/indicators/domain/{domain}/general"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'found': True,
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'pulses': data.get('pulse_info', {}).get('pulses', [])[:5],  # 最新5件
                    'tags': data.get('pulse_info', {}).get('pulses', [{}])[0].get('tags', []) if data.get('pulse_info', {}).get('pulses') else [],
                }
            return {'found': False}
        except Exception as e:
            logger.error(f"AlienVault OTX query failed for {domain}: {e}")
            return {'error': str(e)}
    
    async def _query_alienvault_ip(self, ip: str) -> Dict:
        """AlienVault OTXからIPの脅威情報を取得"""
        try:
            url = f"{self.feeds['alienvault_otx']}/indicators/IPv4/{ip}/general"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'found': True,
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'reputation': data.get('reputation', 0),
                    'country': data.get('country_name'),
                    'asn': data.get('asn'),
                }
            return {'found': False}
        except Exception as e:
            logger.error(f"AlienVault OTX IP query failed for {ip}: {e}")
            return {'error': str(e)}
    
    # URLhaus クエリ
    async def _query_urlhaus(self, domain: str) -> Dict:
        """URLhausから悪意のあるURLを検索"""
        try:
            url = self.feeds['urlhaus']
            data = {'host': domain}
            response = requests.post(url, data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok':
                    return {
                        'found': True,
                        'url_count': len(result.get('urls', [])),
                        'urls': result.get('urls', [])[:5],  # 最新5件
                    }
            return {'found': False}
        except Exception as e:
            logger.error(f"URLhaus query failed for {domain}: {e}")
            return {'error': str(e)}
    
    # Feodo Tracker クエリ
    async def _query_feodo(self, ip: str) -> Dict:
        """Feodo Tracker（C2サーバーリスト）を確認"""
        try:
            response = requests.get(self.feeds['feodo'], timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    if entry.get('ip_address') == ip:
                        return {
                            'found': True,
                            'malware': entry.get('malware'),
                            'first_seen': entry.get('first_seen'),
                            'last_online': entry.get('last_online'),
                        }
            return {'found': False}
        except Exception as e:
            logger.error(f"Feodo Tracker query failed for {ip}: {e}")
            return {'error': str(e)}
    
    # ThreatFox クエリ
    async def _query_threatfox_ip(self, ip: str) -> Dict:
        """ThreatFoxからIOCを検索"""
        try:
            url = self.feeds['threatfox']
            data = {'query': 'search_ioc', 'search_term': ip}
            response = requests.post(url, json=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok':
                    return {
                        'found': True,
                        'iocs': result.get('data', [])[:5],
                    }
            return {'found': False}
        except Exception as e:
            logger.error(f"ThreatFox IP query failed for {ip}: {e}")
            return {'error': str(e)}
    
    async def _query_threatfox_hash(self, file_hash: str) -> Dict:
        """ThreatFoxからハッシュを検索"""
        try:
            url = self.feeds['threatfox']
            data = {'query': 'search_hash', 'hash': file_hash}
            response = requests.post(url, json=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok':
                    return {
                        'found': True,
                        'iocs': result.get('data', [])
                    }
            return {'found': False}
        except Exception as e:
            logger.error(f"ThreatFox hash query failed: {e}")
            return {'error': str(e)}
    
    # VirusTotal クエリ
    async def _query_virustotal_domain(self, domain: str) -> Dict:
        """VirusTotalからドメイン情報を取得"""
        if not self.vt_api_key:
            return {'error': 'API key not configured'}
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {'x-apikey': self.vt_api_key}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'found': True,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'reputation': data.get('data', {}).get('attributes', {}).get('reputation', 0),
                }
            return {'found': False}
        except Exception as e:
            logger.error(f"VirusTotal domain query failed for {domain}: {e}")
            return {'error': str(e)}
    
    async def _query_virustotal_ip(self, ip: str) -> Dict:
        """VirusTotalからIP情報を取得"""
        if not self.vt_api_key:
            return {'error': 'API key not configured'}
        
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {'x-apikey': self.vt_api_key}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'found': True,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                }
            return {'found': False}
        except Exception as e:
            logger.error(f"VirusTotal IP query failed for {ip}: {e}")
            return {'error': str(e)}
    
    async def _query_virustotal_hash(self, file_hash: str) -> Dict:
        """VirusTotalからファイル情報を取得"""
        if not self.vt_api_key:
            return {'error': 'API key not configured'}
        
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {'x-apikey': self.vt_api_key}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'found': True,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'type_description': data.get('data', {}).get('attributes', {}).get('type_description'),
                    'names': data.get('data', {}).get('attributes', {}).get('names', []),
                }
            return {'found': False}
        except Exception as e:
            logger.error(f"VirusTotal hash query failed: {e}")
            return {'error': str(e)}
    
    def _calculate_threat_score(self, sources: Dict) -> int:
        """複数ソースから脅威スコアを計算（0-100）"""
        score = 0
        
        # AlienVault
        if sources.get('alienvault', {}).get('found'):
            pulse_count = sources['alienvault'].get('pulse_count', 0)
            score += min(pulse_count * 5, 30)  # 最大30点
        
        # URLhaus
        if sources.get('urlhaus', {}).get('found'):
            url_count = sources['urlhaus'].get('url_count', 0)
            score += min(url_count * 10, 30)  # 最大30点
        
        # Feodo (C2サーバー)
        if sources.get('feodo', {}).get('found'):
            score += 40  # C2サーバーは高リスク
        
        # ThreatFox
        if sources.get('threatfox', {}).get('found'):
            score += 25
        
        # VirusTotal
        if sources.get('virustotal', {}).get('found'):
            malicious = sources['virustotal'].get('malicious', 0)
            suspicious = sources['virustotal'].get('suspicious', 0)
            if malicious > 0:
                score += min(malicious * 2, 40)
            elif suspicious > 0:
                score += min(suspicious, 20)
        
        return min(score, 100)
    
    def _determine_risk_level(self, score: int) -> str:
        """脅威スコアからリスクレベルを判定"""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'INFO'


# エントリーポイント関数
async def get_threat_intelligence(target: str, target_type: str = 'domain') -> Dict:
    """
    脅威インテリジェンス収集のエントリーポイント
    
    Args:
        target: ドメイン、IP、またはハッシュ
        target_type: 'domain', 'ip', 'hash'
    """
    aggregator = ThreatIntelligenceAggregator()
    
    if target_type == 'domain':
        return await aggregator.get_threat_intel_for_domain(target)
    elif target_type == 'ip':
        return await aggregator.get_threat_intel_for_ip(target)
    elif target_type == 'hash':
        return await aggregator.get_threat_intel_for_hash(target)
    else:
        return {'error': f'Invalid target_type: {target_type}'}
