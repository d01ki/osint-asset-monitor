"""
IoC (Indicator of Compromise) 管理システム

機能:
- IoC の収集・保存・管理
- IoC タイプ別の検証
- IoC の相関分析
- IoC フィードの統合
- 自動エンリッチメント
"""

import re
import hashlib
import ipaddress
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class IoC_Type(str, Enum):
    """IoC の種類"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA1 = "file_hash_sha1"
    FILE_HASH_SHA256 = "file_hash_sha256"
    EMAIL = "email"
    CVE = "cve"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"


class IoC_Severity(str, Enum):
    """IoC の深刻度"""
    CRITICAL = "critical"  # 確実に悪意がある
    HIGH = "high"          # 高い確率で悪意がある
    MEDIUM = "medium"      # 疑わしい
    LOW = "low"            # 潜在的なリスク
    INFO = "info"          # 情報のみ


class IoC_Status(str, Enum):
    """IoC のステータス"""
    ACTIVE = "active"              # 現在活動中
    INACTIVE = "inactive"          # 非活動
    WHITELISTED = "whitelisted"    # ホワイトリスト
    FALSE_POSITIVE = "false_positive"  # 誤検知


class IoC_Manager:
    """IoC 管理クラス"""
    
    def __init__(self):
        self.ioc_patterns = {
            IoC_Type.IP_ADDRESS: self._validate_ip,
            IoC_Type.DOMAIN: self._validate_domain,
            IoC_Type.URL: self._validate_url,
            IoC_Type.FILE_HASH_MD5: lambda x: len(x) == 32 and all(c in '0123456789abcdefABCDEF' for c in x),
            IoC_Type.FILE_HASH_SHA1: lambda x: len(x) == 40 and all(c in '0123456789abcdefABCDEF' for c in x),
            IoC_Type.FILE_HASH_SHA256: lambda x: len(x) == 64 and all(c in '0123456789abcdefABCDEF' for c in x),
            IoC_Type.EMAIL: self._validate_email,
            IoC_Type.CVE: self._validate_cve,
        }
    
    def parse_ioc(self, indicator: str) -> Optional[Tuple[IoC_Type, str]]:
        """
        IoC を自動的に識別・検証
        
        Returns:
            (IoC_Type, normalized_value) または None
        """
        indicator = indicator.strip()
        
        # 各タイプを試す
        for ioc_type, validator in self.ioc_patterns.items():
            try:
                if validator(indicator):
                    normalized = self._normalize_ioc(indicator, ioc_type)
                    return (ioc_type, normalized)
            except:
                continue
        
        return None
    
    def create_ioc(
        self,
        indicator: str,
        ioc_type: Optional[IoC_Type] = None,
        severity: IoC_Severity = IoC_Severity.MEDIUM,
        source: str = "manual",
        description: str = "",
        tags: List[str] = None,
        related_malware: str = None,
        related_threat_actor: str = None,
    ) -> Dict:
        """
        IoC レコードを作成
        
        Args:
            indicator: IoC の値
            ioc_type: IoC のタイプ（Noneの場合は自動検出）
            severity: 深刻度
            source: 情報源
            description: 説明
            tags: タグリスト
            related_malware: 関連マルウェア
            related_threat_actor: 関連脅威アクター
        """
        # 自動検出
        if ioc_type is None:
            result = self.parse_ioc(indicator)
            if result:
                ioc_type, indicator = result
            else:
                raise ValueError(f"Could not determine IoC type for: {indicator}")
        
        # 正規化
        normalized_indicator = self._normalize_ioc(indicator, ioc_type)
        
        # IoC レコード作成
        ioc_record = {
            'indicator': normalized_indicator,
            'type': ioc_type.value,
            'severity': severity.value,
            'status': IoC_Status.ACTIVE.value,
            'source': source,
            'description': description,
            'tags': tags or [],
            'related_malware': related_malware,
            'related_threat_actor': related_threat_actor,
            'first_seen': datetime.utcnow().isoformat(),
            'last_seen': datetime.utcnow().isoformat(),
            'confidence': self._calculate_confidence(source, severity),
            'metadata': {},
        }
        
        return ioc_record
    
    def enrich_ioc(self, ioc_record: Dict, threat_intel: Dict) -> Dict:
        """
        脅威インテリジェンスで IoC をエンリッチ
        
        Args:
            ioc_record: IoC レコード
            threat_intel: 脅威インテリジェンスデータ
        """
        # 脅威スコアを更新
        if threat_intel.get('threat_score'):
            ioc_record['threat_score'] = threat_intel['threat_score']
            ioc_record['risk_level'] = threat_intel['risk_level']
        
        # ソース情報を追加
        ioc_record['enrichment'] = {
            'sources': list(threat_intel.get('sources', {}).keys()),
            'enriched_at': datetime.utcnow().isoformat(),
        }
        
        # AlienVault からタグを抽出
        if threat_intel.get('sources', {}).get('alienvault', {}).get('tags'):
            existing_tags = set(ioc_record.get('tags', []))
            new_tags = set(threat_intel['sources']['alienvault']['tags'])
            ioc_record['tags'] = list(existing_tags.union(new_tags))
        
        # マルウェア情報を更新
        if threat_intel.get('sources', {}).get('feodo', {}).get('malware'):
            ioc_record['related_malware'] = threat_intel['sources']['feodo']['malware']
        
        # 最終確認日時を更新
        ioc_record['last_seen'] = datetime.utcnow().isoformat()
        
        return ioc_record
    
    def correlate_iocs(self, ioc_list: List[Dict]) -> Dict:
        """
        複数の IoC を相関分析
        
        Returns:
            相関関係とクラスター情報
        """
        correlations = {
            'by_malware': {},
            'by_threat_actor': {},
            'by_campaign': {},
            'clusters': [],
        }
        
        # マルウェアごとにグループ化
        for ioc in ioc_list:
            malware = ioc.get('related_malware')
            if malware:
                if malware not in correlations['by_malware']:
                    correlations['by_malware'][malware] = []
                correlations['by_malware'][malware].append(ioc['indicator'])
        
        # 脅威アクターごとにグループ化
        for ioc in ioc_list:
            actor = ioc.get('related_threat_actor')
            if actor:
                if actor not in correlations['by_threat_actor']:
                    correlations['by_threat_actor'][actor] = []
                correlations['by_threat_actor'][actor].append(ioc['indicator'])
        
        # タグの共通性でクラスタリング
        correlations['clusters'] = self._cluster_by_tags(ioc_list)
        
        return correlations
    
    def generate_ioc_report(self, ioc_list: List[Dict], time_range_days: int = 30) -> Dict:
        """
        IoC レポートを生成
        
        Args:
            ioc_list: IoC リスト
            time_range_days: 分析対象期間（日数）
        """
        cutoff_date = datetime.utcnow() - timedelta(days=time_range_days)
        
        # 期間内の IoC をフィルタ
        recent_iocs = [
            ioc for ioc in ioc_list
            if datetime.fromisoformat(ioc['first_seen']) > cutoff_date
        ]
        
        # 統計情報
        stats = {
            'total_iocs': len(ioc_list),
            'recent_iocs': len(recent_iocs),
            'by_type': self._count_by_field(ioc_list, 'type'),
            'by_severity': self._count_by_field(ioc_list, 'severity'),
            'by_status': self._count_by_field(ioc_list, 'status'),
            'top_malware': self._top_n_by_field(ioc_list, 'related_malware', 10),
            'top_threat_actors': self._top_n_by_field(ioc_list, 'related_threat_actor', 10),
            'trend': self._calculate_trend(ioc_list, time_range_days),
        }
        
        # 相関分析
        correlations = self.correlate_iocs(ioc_list)
        
        return {
            'report_generated_at': datetime.utcnow().isoformat(),
            'time_range_days': time_range_days,
            'statistics': stats,
            'correlations': correlations,
            'recommendations': self._generate_recommendations(stats, correlations),
        }
    
    # 内部ヘルパーメソッド
    
    def _validate_ip(self, value: str) -> bool:
        """IP アドレスの検証"""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    def _validate_domain(self, value: str) -> bool:
        """ドメインの検証"""
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, value))
    
    def _validate_url(self, value: str) -> bool:
        """URL の検証"""
        url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(url_pattern, value))
    
    def _validate_email(self, value: str) -> bool:
        """メールアドレスの検証"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, value))
    
    def _validate_cve(self, value: str) -> bool:
        """CVE ID の検証"""
        cve_pattern = r'^CVE-\d{4}-\d{4,}$'
        return bool(re.match(cve_pattern, value.upper()))
    
    def _normalize_ioc(self, indicator: str, ioc_type: IoC_Type) -> str:
        """IoC を正規化"""
        if ioc_type in [IoC_Type.DOMAIN, IoC_Type.EMAIL]:
            return indicator.lower()
        elif ioc_type in [IoC_Type.FILE_HASH_MD5, IoC_Type.FILE_HASH_SHA1, IoC_Type.FILE_HASH_SHA256]:
            return indicator.lower()
        elif ioc_type == IoC_Type.CVE:
            return indicator.upper()
        return indicator
    
    def _calculate_confidence(self, source: str, severity: IoC_Severity) -> int:
        """信頼度スコアを計算（0-100）"""
        base_score = {
            'alienvault': 80,
            'urlhaus': 85,
            'feodo': 90,
            'threatfox': 85,
            'virustotal': 75,
            'manual': 50,
        }.get(source.lower(), 50)
        
        severity_modifier = {
            IoC_Severity.CRITICAL: 10,
            IoC_Severity.HIGH: 5,
            IoC_Severity.MEDIUM: 0,
            IoC_Severity.LOW: -5,
            IoC_Severity.INFO: -10,
        }.get(severity, 0)
        
        return min(max(base_score + severity_modifier, 0), 100)
    
    def _cluster_by_tags(self, ioc_list: List[Dict]) -> List[Dict]:
        """タグの共通性でクラスタリング"""
        clusters = []
        processed = set()
        
        for i, ioc1 in enumerate(ioc_list):
            if i in processed:
                continue
            
            cluster = {
                'iocs': [ioc1['indicator']],
                'common_tags': set(ioc1.get('tags', [])),
            }
            
            for j, ioc2 in enumerate(ioc_list[i+1:], start=i+1):
                if j in processed:
                    continue
                
                tags2 = set(ioc2.get('tags', []))
                common = cluster['common_tags'].intersection(tags2)
                
                if len(common) >= 2:  # 2つ以上の共通タグ
                    cluster['iocs'].append(ioc2['indicator'])
                    cluster['common_tags'] = common
                    processed.add(j)
            
            if len(cluster['iocs']) > 1:
                cluster['common_tags'] = list(cluster['common_tags'])
                clusters.append(cluster)
            
            processed.add(i)
        
        return clusters
    
    def _count_by_field(self, ioc_list: List[Dict], field: str) -> Dict:
        """フィールド別にカウント"""
        counts = {}
        for ioc in ioc_list:
            value = ioc.get(field, 'unknown')
            counts[value] = counts.get(value, 0) + 1
        return counts
    
    def _top_n_by_field(self, ioc_list: List[Dict], field: str, n: int) -> List[Tuple[str, int]]:
        """フィールド別のトップN"""
        counts = self._count_by_field(ioc_list, field)
        return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def _calculate_trend(self, ioc_list: List[Dict], days: int) -> List[Dict]:
        """トレンドを計算"""
        trend = []
        for i in range(days):
            date = datetime.utcnow() - timedelta(days=i)
            count = sum(
                1 for ioc in ioc_list
                if datetime.fromisoformat(ioc['first_seen']).date() == date.date()
            )
            trend.append({
                'date': date.date().isoformat(),
                'count': count,
            })
        return list(reversed(trend))
    
    def _generate_recommendations(self, stats: Dict, correlations: Dict) -> List[str]:
        """推奨アクションを生成"""
        recommendations = []
        
        # Critical IoC がある場合
        critical_count = stats['by_severity'].get('critical', 0)
        if critical_count > 0:
            recommendations.append(
                f"【緊急】{critical_count}件のクリティカルなIoCが検出されています。即座にブロックリストに追加してください。"
            )
        
        # マルウェアキャンペーンの検出
        if correlations['by_malware']:
            top_malware = max(correlations['by_malware'].items(), key=lambda x: len(x[1]))
            recommendations.append(
                f"マルウェア '{top_malware[0]}' に関連する{len(top_malware[1])}件のIoCが検出されました。"
                f"このマルウェアに対する防御策を優先してください。"
            )
        
        # クラスターの検出
        if correlations['clusters']:
            recommendations.append(
                f"{len(correlations['clusters'])}個のIoCクラスターが検出されました。"
                f"これらは組織的な攻撃キャンペーンの可能性があります。"
            )
        
        return recommendations


# エントリーポイント関数

def parse_and_validate_ioc(indicator: str) -> Optional[Dict]:
    """IoC を解析・検証"""
    manager = IoC_Manager()
    result = manager.parse_ioc(indicator)
    
    if result:
        ioc_type, normalized = result
        return {
            'indicator': normalized,
            'type': ioc_type.value,
            'valid': True,
        }
    
    return {'valid': False, 'error': 'Invalid IoC format'}


def create_and_enrich_ioc(
    indicator: str,
    threat_intel: Optional[Dict] = None,
    **kwargs
) -> Dict:
    """IoC を作成し、脅威インテリジェンスでエンリッチ"""
    manager = IoC_Manager()
    
    # IoC 作成
    ioc_record = manager.create_ioc(indicator, **kwargs)
    
    # エンリッチメント
    if threat_intel:
        ioc_record = manager.enrich_ioc(ioc_record, threat_intel)
    
    return ioc_record
