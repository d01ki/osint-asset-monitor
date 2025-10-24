"""
MITRE ATT&CK フレームワーク統合

機能:
- ATT&CKマトリックスの取得
- 攻撃者グループの戦術・技術マッピング
- 検出された脅威とATT&CKの関連付け
- カバレッジ分析
"""

import requests
import logging
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class MITREAttackIntegration:
    """MITRE ATT&CK フレームワーク統合クラス"""
    
    def __init__(self):
        self.base_url = "https://raw.githubusercontent.com/mitre/cti/master"
        self.enterprise_url = f"{self.base_url}/enterprise-attack/enterprise-attack.json"
        self.mobile_url = f"{self.base_url}/mobile-attack/mobile-attack.json"
        self.ics_url = f"{self.base_url}/ics-attack/ics-attack.json"
        
        # キャッシュ
        self._cache = {
            'enterprise': None,
            'groups': None,
            'techniques': None,
            'software': None,
        }
    
    async def get_group_profile(self, group_name: str) -> Optional[Dict]:
        """
        APTグループのプロファイルを取得
        
        例: APT3, APT28, Lazarus Group など
        """
        try:
            groups = await self._get_all_groups()
            
            for group in groups:
                names = [group.get('name', '').lower()]
                aliases = [alias.lower() for alias in group.get('aliases', [])]
                all_names = names + aliases
                
                if group_name.lower() in all_names:
                    return {
                        'id': group.get('id'),
                        'name': group.get('name'),
                        'aliases': group.get('aliases', []),
                        'description': group.get('description', ''),
                        'techniques': await self._get_group_techniques(group.get('id')),
                        'software': await self._get_group_software(group.get('id')),
                        'url': f"https://attack.mitre.org/groups/{group.get('id')}",
                    }
            
            return None
        except Exception as e:
            logger.error(f"Failed to get group profile for {group_name}: {e}")
            return None
    
    async def get_technique_details(self, technique_id: str) -> Optional[Dict]:
        """
        特定のATT&CK技術の詳細を取得
        
        例: T1566 (Phishing), T1190 (Exploit Public-Facing Application)
        """
        try:
            techniques = await self._get_all_techniques()
            
            for technique in techniques:
                if technique.get('external_references'):
                    for ref in technique['external_references']:
                        if ref.get('external_id') == technique_id:
                            return {
                                'id': technique_id,
                                'name': technique.get('name'),
                                'description': technique.get('description', ''),
                                'tactics': [phase['phase_name'] for phase in technique.get('kill_chain_phases', [])],
                                'platforms': technique.get('x_mitre_platforms', []),
                                'data_sources': technique.get('x_mitre_data_sources', []),
                                'detection': technique.get('x_mitre_detection', ''),
                                'url': f"https://attack.mitre.org/techniques/{technique_id}",
                                'mitigations': await self._get_technique_mitigations(technique_id),
                            }
            
            return None
        except Exception as e:
            logger.error(f"Failed to get technique details for {technique_id}: {e}")
            return None
    
    async def map_ioc_to_attack(self, ioc_type: str, threat_info: Dict) -> List[Dict]:
        """
        IoC（侵害指標）をMITRE ATT&CK技術にマッピング
        
        Args:
            ioc_type: 'domain', 'ip', 'hash', 'url'
            threat_info: 脅威インテリジェンスからの情報
        """
        mappings = []
        
        # AlienVault OTXのタグからマッピング
        if threat_info.get('sources', {}).get('alienvault', {}).get('tags'):
            tags = threat_info['sources']['alienvault']['tags']
            mappings.extend(await self._map_tags_to_techniques(tags))
        
        # マルウェアファミリーからマッピング
        if threat_info.get('sources', {}).get('feodo', {}).get('malware'):
            malware = threat_info['sources']['feodo']['malware']
            mappings.extend(await self._map_malware_to_techniques(malware))
        
        # ThreatFoxのIOCからマッピング
        if threat_info.get('sources', {}).get('threatfox', {}).get('iocs'):
            iocs = threat_info['sources']['threatfox']['iocs']
            for ioc in iocs:
                if ioc.get('malware'):
                    mappings.extend(await self._map_malware_to_techniques(ioc['malware']))
        
        return mappings
    
    async def get_defense_coverage(self, detected_techniques: List[str]) -> Dict:
        """
        検出された技術に対する防御カバレッジを分析
        
        Args:
            detected_techniques: 検出されたATT&CK技術IDのリスト
        """
        tactics = {}
        
        for technique_id in detected_techniques:
            technique = await self.get_technique_details(technique_id)
            if technique:
                for tactic in technique.get('tactics', []):
                    if tactic not in tactics:
                        tactics[tactic] = []
                    tactics[tactic].append(technique_id)
        
        return {
            'tactics_covered': list(tactics.keys()),
            'coverage_by_tactic': tactics,
            'total_techniques': len(detected_techniques),
            'recommendations': await self._generate_defense_recommendations(tactics),
        }
    
    # 内部ヘルパーメソッド
    
    async def _get_all_groups(self) -> List[Dict]:
        """すべてのAPTグループを取得（キャッシュ付き）"""
        if self._cache['groups']:
            return self._cache['groups']
        
        try:
            response = requests.get(self.enterprise_url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                groups = [obj for obj in data.get('objects', []) if obj.get('type') == 'intrusion-set']
                self._cache['groups'] = groups
                return groups
        except Exception as e:
            logger.error(f"Failed to fetch ATT&CK groups: {e}")
        
        return []
    
    async def _get_all_techniques(self) -> List[Dict]:
        """すべてのATT&CK技術を取得（キャッシュ付き）"""
        if self._cache['techniques']:
            return self._cache['techniques']
        
        try:
            response = requests.get(self.enterprise_url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                techniques = [obj for obj in data.get('objects', []) if obj.get('type') == 'attack-pattern']
                self._cache['techniques'] = techniques
                return techniques
        except Exception as e:
            logger.error(f"Failed to fetch ATT&CK techniques: {e}")
        
        return []
    
    async def _get_group_techniques(self, group_id: str) -> List[str]:
        """グループが使用する技術を取得"""
        try:
            response = requests.get(self.enterprise_url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                relationships = [obj for obj in data.get('objects', []) 
                               if obj.get('type') == 'relationship' 
                               and obj.get('source_ref') == group_id
                               and obj.get('relationship_type') == 'uses']
                
                technique_ids = []
                for rel in relationships:
                    target = rel.get('target_ref')
                    # 技術IDを抽出
                    for obj in data.get('objects', []):
                        if obj.get('id') == target and obj.get('type') == 'attack-pattern':
                            for ref in obj.get('external_references', []):
                                if ref.get('source_name') == 'mitre-attack':
                                    technique_ids.append(ref.get('external_id'))
                
                return technique_ids
        except Exception as e:
            logger.error(f"Failed to get group techniques: {e}")
        
        return []
    
    async def _get_group_software(self, group_id: str) -> List[str]:
        """グループが使用するソフトウェア/マルウェアを取得"""
        try:
            response = requests.get(self.enterprise_url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                relationships = [obj for obj in data.get('objects', []) 
                               if obj.get('type') == 'relationship' 
                               and obj.get('source_ref') == group_id
                               and obj.get('relationship_type') == 'uses']
                
                software_names = []
                for rel in relationships:
                    target = rel.get('target_ref')
                    # ソフトウェア名を抽出
                    for obj in data.get('objects', []):
                        if obj.get('id') == target and obj.get('type') in ['malware', 'tool']:
                            software_names.append(obj.get('name'))
                
                return software_names
        except Exception as e:
            logger.error(f"Failed to get group software: {e}")
        
        return []
    
    async def _get_technique_mitigations(self, technique_id: str) -> List[Dict]:
        """技術に対する緩和策を取得"""
        # 簡略化版 - 実装を拡張可能
        return []
    
    async def _map_tags_to_techniques(self, tags: List[str]) -> List[Dict]:
        """タグからATT&CK技術にマッピング"""
        mappings = []
        
        # 一般的なマッピング辞書
        tag_technique_map = {
            'phishing': 'T1566',
            'ransomware': 'T1486',
            'credential_dumping': 'T1003',
            'lateral_movement': 'T1021',
            'c2': 'T1071',
            'command_and_control': 'T1071',
            'exfiltration': 'T1041',
            'backdoor': 'T1059',
            'trojan': 'T1204',
        }
        
        for tag in tags:
            tag_lower = tag.lower()
            for key, technique_id in tag_technique_map.items():
                if key in tag_lower:
                    technique = await self.get_technique_details(technique_id)
                    if technique:
                        mappings.append(technique)
        
        return mappings
    
    async def _map_malware_to_techniques(self, malware_name: str) -> List[Dict]:
        """マルウェアファミリーからATT&CK技術にマッピング"""
        mappings = []
        
        # 既知のマルウェアとATT&CK技術のマッピング
        malware_technique_map = {
            'emotet': ['T1566.001', 'T1059.003', 'T1003'],
            'trickbot': ['T1566.001', 'T1021.002', 'T1003.001'],
            'qakbot': ['T1566.001', 'T1055', 'T1003'],
            'cobalt_strike': ['T1071.001', 'T1055', 'T1021.001'],
            'dridex': ['T1566.001', 'T1059.003', 'T1003'],
        }
        
        malware_lower = malware_name.lower()
        for malware_key, technique_ids in malware_technique_map.items():
            if malware_key in malware_lower:
                for technique_id in technique_ids:
                    technique = await self.get_technique_details(technique_id)
                    if technique:
                        mappings.append(technique)
        
        return mappings
    
    async def _generate_defense_recommendations(self, tactics: Dict) -> List[str]:
        """戦術に基づいた防御推奨事項を生成"""
        recommendations = []
        
        if 'initial-access' in tactics:
            recommendations.append("メールフィルタリングとユーザー教育を強化してフィッシング対策を実施")
            recommendations.append("公開サービスの脆弱性スキャンとパッチ適用を優先")
        
        if 'execution' in tactics:
            recommendations.append("アプリケーションホワイトリストを実装")
            recommendations.append("PowerShellとスクリプト実行の監視を強化")
        
        if 'persistence' in tactics:
            recommendations.append("レジストリとスタートアップ項目の定期的な監査")
            recommendations.append("スケジュールタスクの監視を実装")
        
        if 'credential-access' in tactics:
            recommendations.append("多要素認証（MFA）を全社的に展開")
            recommendations.append("特権アカウントの使用を制限・監視")
        
        if 'lateral-movement' in tactics:
            recommendations.append("ネットワークセグメンテーションを実装")
            recommendations.append("SMBおよびRDPの使用を制限・監視")
        
        if 'exfiltration' in tactics:
            recommendations.append("DLP（Data Loss Prevention）ソリューションを導入")
            recommendations.append("異常なデータ転送を検出するネットワーク監視を強化")
        
        return recommendations


# エントリーポイント関数

async def analyze_threat_with_attack(threat_info: Dict, ioc_type: str = 'domain') -> Dict:
    """
    脅威情報をMITRE ATT&CKフレームワークで分析
    
    Args:
        threat_info: 脅威インテリジェンスの結果
        ioc_type: IoC の種類
    
    Returns:
        MITRE ATT&CKマッピングと推奨事項
    """
    mitre = MITREAttackIntegration()
    
    # IoC を ATT&CK技術にマッピング
    mapped_techniques = await mitre.map_ioc_to_attack(ioc_type, threat_info)
    
    # 検出された技術IDを抽出
    technique_ids = [t.get('id') for t in mapped_techniques if t.get('id')]
    
    # 防御カバレッジ分析
    coverage = await mitre.get_defense_coverage(technique_ids)
    
    return {
        'mapped_techniques': mapped_techniques,
        'defense_coverage': coverage,
        'timestamp': datetime.utcnow().isoformat(),
    }


async def get_apt_group_info(group_name: str) -> Optional[Dict]:
    """APTグループの詳細情報を取得"""
    mitre = MITREAttackIntegration()
    return await mitre.get_group_profile(group_name)
