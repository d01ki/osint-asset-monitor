# OSINT Asset Monitor

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)
![Threat Intel](https://img.shields.io/badge/threat_intel-enabled-red.svg)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-integrated-orange.svg)

**組織の外部公開資産を継続的に監視し、高度な脅威インテリジェンスで早期にリスクを検出するOSINTツール**

## 🎯 特徴

### 資産発見・監視
- **自動資産発見**: ドメイン、サブドメイン、IPアドレス、証明書を自動検出
- **継続的監視**: 定期的なスキャンで新規資産や変更を検知
- **統合データソース**: Shodan、Censys、Certificate Transparency、DNS記録を統合

### 🔥 高度な脅威インテリジェンス
- **複数TIフィード統合**: AlienVault OTX、URLhaus、Feodo Tracker、ThreatFox、VirusTotal
- **MITRE ATT&CK マッピング**: 検出された脅威を攻撃者のTTPに関連付け
- **IoC管理**: 侵害指標（IoC）の自動収集・エンリッチメント・相関分析
- **APTグループ追跡**: 脅威アクターのプロファイルと使用技術の把握
- **脅威スコアリング**: 0-100の統合脅威スコアで優先度を判定
- **自動エンリッチメント**: 検出された資産を自動的に脅威情報で拡充

### アラート・通知
- **リアルタイムアラート**: 新規資産・脅威検出時の即座通知
- **多チャネル通知**: Slack、Email対応
- **リスクベースアラート**: CRITICAL/HIGH/MEDIUM/LOW/INFO

### 分析・レポート
- **可視化ダッシュボード**: 資産とリスクの全体像を直感的に把握
- **レポート生成**: コンプライアンス対応やセキュリティ監査用
- **トレンド分析**: IoC発生傾向と相関関係の可視化

## 🏗️ アーキテクチャ

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Dashboard (React)                     │
│                    http://localhost:3000                     │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                  REST API (FastAPI)                          │
│                  http://localhost:8000                       │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│              Task Queue (Celery + Redis)                     │
│  - Asset Discovery Workers                                   │
│  - Threat Intelligence Workers                               │
│  - Vulnerability Scanner Workers                             │
│  - Notification Workers                                      │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                  Database (PostgreSQL)                       │
│  - Assets, IoCs, Threat Intel, MITRE ATT&CK                 │
└──────────────────────────────────────────────────────────────┘

External Threat Intelligence APIs:
├── AlienVault OTX (脅威パルス)
├── URLhaus (悪意のあるURL)
├── Feodo Tracker (C2サーバー)
├── ThreatFox (IoC)
├── VirusTotal (マルウェアスキャン)
├── Shodan (公開資産)
├── Censys (証明書・サービス)
└── MITRE ATT&CK (戦術・技術)
```

## 🚀 クイックスタート

### 前提条件

- Docker & Docker Compose
- API Keys (無料で取得可能):
  - [Shodan API Key](https://account.shodan.io/)
  - [VirusTotal API Key](https://www.virustotal.com/gui/my-apikey)
  - [AlienVault OTX](https://otx.alienvault.com/api) (オプション)

### インストール

```bash
# リポジトリをクローン
git clone https://github.com/d01ki/osint-asset-monitor.git
cd osint-asset-monitor

# 環境変数を設定
cp .env.example .env
# .envファイルを編集してAPI Keyを設定

# Dockerコンテナを起動
docker-compose up -d

# ログを確認
docker-compose logs -f api
```

### アクセス

- **API Documentation**: http://localhost:8000/docs
- **Celery Flower (タスク監視)**: http://localhost:5555

## 📖 使い方

### 基本的なワークフロー

1. **組織を登録**
2. **初回スキャンを実行**
3. **脅威インテリジェンスで資産をエンリッチ**
4. **アラートを確認・対応**
5. **定期スキャンを設定**

詳細は [脅威インテリジェンスドキュメント](docs/THREAT_INTELLIGENCE.md) を参照してください。

## 📦 主要機能

### 1. 資産発見

#### サブドメイン発見
- Certificate Transparency Logs (crt.sh)
- DNS Brute Force
- 検索エンジンからの収集

#### 公開サービス発見
- Shodan統合: 開放ポート、バナー、脆弱性
- Censys統合: 証明書、サービス詳細

### 2. 🛡️ 脅威インテリジェンス

#### 複数ソース統合
```python
# ドメインの脅威情報を取得
threat_info = await get_threat_intelligence("example.com", target_type="domain")

# 結果
# - threat_score: 0-100
# - risk_level: CRITICAL/HIGH/MEDIUM/LOW/INFO
# - sources: AlienVault, URLhaus, Feodo, ThreatFox, VirusTotal
```

#### 脅威スコアリング
- **AlienVault OTX**: Pulseカウント → 最大30点
- **URLhaus**: 悪意のあるURL数 → 最大30点
- **Feodo Tracker**: C2サーバー検出 → 40点
- **ThreatFox**: IoC検出 → 25点
- **VirusTotal**: マルウェア検出数 → 最大40点

### 3. 🎯 MITRE ATT&CK統合

#### APTグループ分析
```python
# APT28の詳細を取得
apt_info = await get_apt_group_info("APT28")

# - 使用技術: T1566.001, T1071.001, T1003
# - 使用ソフトウェア: X-Agent, Sofacy
# - 標的業界: 政府、防衛、メディア
```

#### 攻撃技術マッピング
- 検出された脅威を自動的にATT&CK技術に関連付け
- 防御カバレッジ分析
- 戦術ベースの推奨事項生成

### 4. 📊 IoC管理

#### 対応IoC タイプ
- IPアドレス
- ドメイン
- URL
- ファイルハッシュ (MD5, SHA1, SHA256)
- メールアドレス
- CVE ID
- レジストリキー

#### 自動機能
- IoC の自動検出・検証
- 脅威インテリジェンスでエンリッチ
- マルウェア・脅威アクター・キャンペーンで相関分析
- タグの共通性でクラスタリング
- 定期レポート生成

### 5. アラート＆通知

#### アラートタイプ
- `new_asset`: 新規資産検出
- `threat_detected`: 脅威検出 (高スコア)
- `new_ioc`: IoC検出
- `new_vulnerability`: 脆弱性検出
- `certificate_expiry`: 証明書期限警告

#### 通知チャネル
- Slack Webhook
- Email (SMTP)
- カスタムWebhook

## 🔧 設定

### 環境変数 (.env)

```env
# Threat Intelligence APIs
SHODAN_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here

# 通知設定
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SMTP_HOST=smtp.gmail.com
SMTP_USER=your-email@example.com
ALERT_EMAIL_TO=security-team@example.com

# スキャン設定
SCAN_INTERVAL=86400  # 24時間
MAX_CONCURRENT_SCANS=5
```

## 🗂️ プロジェクト構造

```
osint-asset-monitor/
├── backend/
│   ├── app/
│   │   ├── services/
│   │   │   ├── subdomain_scanner.py      # サブドメインスキャン
│   │   │   ├── shodan_scanner.py         # Shodan統合
│   │   │   ├── threat_intelligence.py    # 🔥 TI統合
│   │   │   ├── mitre_attack.py          # 🔥 MITRE ATT&CK
│   │   │   └── ioc_manager.py           # 🔥 IoC管理
│   │   ├── models/database.py           # データベースモデル
│   │   └── ...
├── docs/
│   └── THREAT_INTELLIGENCE.md           # 🔥 TIドキュメント
├── docker-compose.yml
└── README.md
```

## 🛣️ ロードマップ

### 完了 ✅
- [x] 基本的な資産発見
- [x] Certificate Transparency統合
- [x] Shodan API統合
- [x] サブドメインスキャナー
- [x] **脅威インテリジェンスフィード統合**
- [x] **MITRE ATT&CK フレームワーク統合**
- [x] **IoC管理システム**
- [x] **APTグループ追跡**
- [x] **脅威スコアリング**

### 開発中 🚧
- [ ] Webダッシュボード（React）
- [ ] ユーザー認証・認可（JWT）
- [ ] API エンドポイント実装
- [ ] Celeryタスク実装
- [ ] Slack/Email通知

### 今後の予定 📅
- [ ] Censys API統合
- [ ] 証明書有効期限監視
- [ ] レポート生成（PDF/Excel）
- [ ] AI/MLによる異常検知
- [ ] マルチテナント対応
- [ ] STIX/TAXII サポート

## 🤝 コントリビューション

プルリクエストを歓迎します！

1. Fork
2. Feature ブランチ作成 (`git checkout -b feature/ThreatIntel`)
3. Commit (`git commit -m 'Add threat intelligence'`)
4. Push (`git push origin feature/ThreatIntel`)
5. Pull Request作成

## 📄 ライセンス

MIT License - [LICENSE](LICENSE)

## 🙏 謝辞

### 脅威インテリジェンスソース
- [AlienVault OTX](https://otx.alienvault.com/)
- [Abuse.ch](https://abuse.ch/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [VirusTotal](https://www.virustotal.com/)

### 技術スタック
- [FastAPI](https://fastapi.tiangolo.com/)
- [Celery](https://docs.celeryproject.org/)
- [Shodan](https://shodan.readthedocs.io/)
- [PostgreSQL](https://www.postgresql.org/)
- [Redis](https://redis.io/)

## 📞 サポート

- **Issues**: https://github.com/d01ki/osint-asset-monitor/issues
- **Documentation**: [docs/THREAT_INTELLIGENCE.md](docs/THREAT_INTELLIGENCE.md)

---

**⚠️ 免責事項**: このツールは自組織の資産監視と脅威分析を目的としています。許可なく他組織のネットワークをスキャンすることは違法です。

## 🎓 学習リソース

- [OSINT Framework](https://osintframework.com/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
