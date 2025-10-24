# 脅威インテリジェンス機能 ドキュメント

## 概要

OSINT Asset Monitorは、組織の外部公開資産を監視するだけでなく、高度な脅威インテリジェンス機能を統合しています。

## 主要機能

### 1. 脅威インテリジェンスフィード統合

複数の脅威インテリジェンスソースから情報を収集・統合します。

#### 対応ソース

- **AlienVault OTX**: 世界最大のオープン脅威インテリジェンスコミュニティ
- **Abuse.ch URLhaus**: 悪意のあるURLデータベース
- **Abuse.ch Feodo Tracker**: C2サーバーIPアドレスリスト（Emotet, Dridex等）
- **Abuse.ch ThreatFox**: IoC（侵害指標）データベース
- **VirusTotal**: ファイル、URL、ドメイン、IPアドレスのスキャン

#### 使用例

```python
from app.services.threat_intelligence import get_threat_intelligence

# ドメインの脅威情報を取得
threat_info = await get_threat_intelligence("example.com", target_type="domain")

print(f"Threat Score: {threat_info['threat_score']}/100")
print(f"Risk Level: {threat_info['risk_level']}")
print(f"Sources: {list(threat_info['sources'].keys())}")
```

#### レスポンス例

```json
{
  "domain": "malicious-site.com",
  "timestamp": "2024-10-24T17:00:00Z",
  "threat_score": 85,
  "risk_level": "HIGH",
  "sources": {
    "alienvault": {
      "found": true,
      "pulse_count": 12,
      "tags": ["malware", "phishing", "trojan"]
    },
    "urlhaus": {
      "found": true,
      "url_count": 5,
      "urls": [...]
    },
    "virustotal": {
      "found": true,
      "malicious": 45,
      "suspicious": 3
    }
  }
}
```

### 2. MITRE ATT&CK フレームワーク統合

攻撃者の戦術・技術・手順（TTP）をMITRE ATT&CKフレームワークにマッピングします。

#### 主要機能

- **APTグループプロファイル**: 脅威アクターの詳細情報
- **技術マッピング**: 検出された脅威をATT&CK技術に関連付け
- **防御カバレッジ分析**: 組織の防御態勢を評価
- **推奨事項生成**: 戦術に基づいた防御策の提案

#### 使用例

```python
from app.services.mitre_attack import get_apt_group_info, analyze_threat_with_attack

# APTグループ情報を取得
apt_info = await get_apt_group_info("APT28")

print(f"Group: {apt_info['name']}")
print(f"Aliases: {apt_info['aliases']}")
print(f"Techniques: {apt_info['techniques']}")
print(f"Software: {apt_info['software']}")

# 脅威をATT&CKにマッピング
attack_mapping = await analyze_threat_with_attack(threat_info, ioc_type="domain")

for technique in attack_mapping['mapped_techniques']:
    print(f"{technique['id']}: {technique['name']}")
    print(f"Tactics: {technique['tactics']}")
```

#### APTグループ例

**APT28 (Fancy Bear)**
- **国**: ロシア
- **動機**: 諜報活動
- **主な技術**: 
  - T1566.001 (Spearphishing Attachment)
  - T1071.001 (Web Protocols for C2)
  - T1003 (Credential Dumping)
- **使用ソフトウェア**: X-Agent, Sofacy, Komplex

### 3. IoC（侵害指標）管理

IoC（Indicator of Compromise）を一元管理し、自動エンリッチメントを実施します。

#### IoC タイプ

- IPアドレス
- ドメイン
- URL
- ファイルハッシュ（MD5, SHA1, SHA256）
- メールアドレス
- CVE ID
- レジストリキー
- ファイルパス

#### 使用例

```python
from app.services.ioc_manager import create_and_enrich_ioc, parse_and_validate_ioc

# IoC を自動検出・検証
result = parse_and_validate_ioc("192.168.1.100")
if result['valid']:
    print(f"Type: {result['type']}")
    print(f"Normalized: {result['indicator']}")

# IoC を作成しエンリッチ
ioc = create_and_enrich_ioc(
    indicator="malicious-domain.com",
    threat_intel=threat_info,
    severity="HIGH",
    source="urlhaus",
    description="C2サーバー",
    tags=["emotet", "c2"],
    related_malware="Emotet"
)

print(f"Confidence: {ioc['confidence']}/100")
print(f"Threat Score: {ioc['threat_score']}/100")
```

#### IoC レポート

```python
from app.services.ioc_manager import IoC_Manager

manager = IoC_Manager()
report = manager.generate_ioc_report(ioc_list, time_range_days=30)

print(report['statistics'])
# {
#   'total_iocs': 1250,
#   'recent_iocs': 89,
#   'by_type': {'ip_address': 450, 'domain': 380, ...},
#   'by_severity': {'critical': 12, 'high': 45, ...},
#   'top_malware': [('Emotet', 45), ('TrickBot', 32), ...],
#   'trend': [...]
# }

print(report['correlations'])
# {
#   'by_malware': {'Emotet': [list of IoCs]},
#   'by_threat_actor': {'APT28': [list of IoCs]},
#   'clusters': [...]
# }
```

### 4. 脅威スコアリング

複数のソースから得られた情報を統合し、0-100の脅威スコアを算出します。

#### スコアリングロジック

```
脅威スコア = AlienVaultスコア + URLhausスコア + Feodoスコア + 
             ThreatFoxスコア + VirusTotalスコア

- AlienVault: pulse数 × 5 (最大30点)
- URLhaus: URL数 × 10 (最大30点)
- Feodo: C2サーバー検出 = 40点
- ThreatFox: IoC検出 = 25点
- VirusTotal: malicious数 × 2 (最大40点)
```

#### リスクレベル

| スコア | リスクレベル | 対応 |
|--------|------------|------|
| 80-100 | CRITICAL | 即座にブロック・隔離 |
| 60-79 | HIGH | 優先的に調査・対処 |
| 40-59 | MEDIUM | 監視強化 |
| 20-39 | LOW | 記録・定期確認 |
| 0-19 | INFO | 情報のみ |

### 5. 自動アラート生成

検出された脅威に基づいて自動的にアラートを生成します。

#### アラートタイプ

- **new_asset**: 新規資産検出
- **new_vulnerability**: 脆弱性検出
- **new_ioc**: IoC検出
- **threat_detected**: 脅威検出（高スコア）
- **certificate_expiry**: 証明書有効期限警告
- **suspicious_activity**: 疑わしいアクティビティ

#### 通知チャネル

- Slack Webhook
- Email（SMTP）
- Webhook（カスタム）

## ワークフロー例

### 新規ドメインスキャン時

1. **資産発見**: サブドメインスキャナーが新しいサブドメインを発見
2. **脅威インテリジェンス収集**: 
   - AlienVault OTX をクエリ
   - URLhaus を確認
   - VirusTotal でスキャン
3. **脅威スコア計算**: 複数ソースから脅威スコアを算出
4. **MITRE ATT&CKマッピング**: 検出された脅威をATT&CK技術に関連付け
5. **IoC登録**: 悪意が確認されればIoCとして登録
6. **アラート生成**: 深刻度に応じてアラートを生成
7. **通知送信**: Slack/Emailで通知

### IoC監視・エンリッチメント

1. **IoC収集**: 複数のフィードからIoCを自動収集
2. **自動検証**: IoC の妥当性を検証
3. **エンリッチメント**: 脅威インテリジェンスで詳細情報を追加
4. **相関分析**: マルウェア、脅威アクター、キャンペーンで関連付け
5. **クラスタリング**: タグの共通性でIoCをグループ化
6. **レポート生成**: 定期的にIoCレポートを作成

## API エンドポイント

### 脅威インテリジェンス

```
GET /api/v1/threat-intelligence/query
  ?target=example.com
  &type=domain

POST /api/v1/threat-intelligence/analyze
  {
    "targets": ["example.com", "192.168.1.1"],
    "deep_scan": true
  }
```

### MITRE ATT&CK

```
GET /api/v1/mitre/group/{group_name}
GET /api/v1/mitre/technique/{technique_id}
POST /api/v1/mitre/map-threat
  {
    "threat_info": {...},
    "ioc_type": "domain"
  }
```

### IoC 管理

```
GET /api/v1/iocs
  ?type=ip_address
  &severity=high
  &status=active

POST /api/v1/iocs
  {
    "indicator": "malicious.com",
    "severity": "high",
    "source": "manual",
    "tags": ["phishing", "emotet"]
  }

GET /api/v1/iocs/report
  ?days=30
  &format=json
```

## ベストプラクティス

### 1. API Keyの取得

無料で以下のAPIキーを取得することを推奨：

- **Shodan**: https://account.shodan.io/
- **VirusTotal**: https://www.virustotal.com/gui/my-apikey
- **AlienVault OTX**: https://otx.alienvault.com/api

### 2. スキャン頻度

- **資産発見**: 毎日1回
- **脅威インテリジェンス**: 6時間ごと
- **IoC更新**: 1時間ごと
- **証明書監視**: 毎日1回

### 3. データ保持

- **IoC**: 1年間保持（非アクティブ化後）
- **脅威インテリジェンス**: 90日間
- **スキャン履歴**: 無期限
- **アラート**: 6ヶ月

### 4. 誤検知対策

- ホワイトリスト機能の活用
- 信頼度スコアの閾値設定
- 複数ソースでの確認
- 定期的なレビュー

## トラブルシューティング

### Q: 脅威スコアが高すぎる/低すぎる

A: 各ソースの重み付けは `threat_intelligence.py` の `_calculate_threat_score` メソッドで調整可能です。

### Q: API Rate Limitに達した

A: 
- 無料APIには制限があります
- 有料プランへのアップグレードを検討
- キャッシュの活用
- スキャン頻度の調整

### Q: MITRE ATT&CKデータが古い

A: キャッシュをクリアして再取得してください。データは定期的に更新されます。

## 参考資料

- [MITRE ATT&CK](https://attack.mitre.org/)
- [AlienVault OTX](https://otx.alienvault.com/)
- [Abuse.ch](https://abuse.ch/)
- [VirusTotal](https://www.virustotal.com/)
- [OASIS STIX/TAXII](https://oasis-open.github.io/cti-documentation/)

---

最終更新: 2024-10-24
