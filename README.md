# OSINT Asset Monitor

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)

**組織の外部公開資産を継続的に監視し、セキュリティリスクを早期検出するOSINTツール**

## 🎯 特徴

- **自動資産発見**: ドメイン、サブドメイン、IPアドレス、証明書を自動検出
- **継続的監視**: 定期的なスキャンで新規資産や変更を検知
- **統合データソース**: Shodan、Censys、Certificate Transparency、DNS記録を統合
- **脅威インテリジェンス**: 脆弱性情報との自動マッチング
- **アラート機能**: 新規資産検出時のSlack/Email通知
- **可視化ダッシュボード**: 資産の全体像を直感的に把握
- **レポート生成**: コンプライアンス対応やセキュリティ監査用のレポート

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
│  - Vulnerability Scanner Workers                             │
│  - Notification Workers                                      │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                  Database (PostgreSQL)                       │
│  - Assets, Scans, Vulnerabilities, Alerts                   │
└──────────────────────────────────────────────────────────────┘

External APIs:
├── Shodan API
├── Censys API
├── Certificate Transparency Logs
├── VirusTotal API
└── CVE Database (NVD)
```

## 🚀 クイックスタート

### 前提条件

- Docker & Docker Compose
- API Keys (オプションだが推奨):
  - [Shodan API Key](https://account.shodan.io/)
  - [Censys API Key](https://censys.io/account/api)
  - [VirusTotal API Key](https://www.virustotal.com/gui/my-apikey)

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
docker-compose logs -f
```

### アクセス

- **API Documentation**: http://localhost:8000/docs
- **Celery Flower (タスク監視)**: http://localhost:5555
- **デフォルト認証情報**: 
  - Username: `admin`
  - Password: `changeme`

## 📖 使い方

### APIを使用してスキャンを実行

```bash
# 健全性チェック
curl http://localhost:8000/health

# 組織を追加（APIドキュメントから実行）
# POST /api/v1/organizations
{
  "name": "Example Corp",
  "domain": "example.com",
  "description": "サンプル組織"
}

# スキャンを開始
# POST /api/v1/scans
{
  "organization_id": 1,
  "scan_type": "full"
}
```

## 📦 主要機能

### 1. ドメイン・サブドメイン発見
- **Certificate Transparency Logs**: crt.shからサブドメインを自動収集
- **DNS Brute Force**: 一般的なサブドメイン名で列挙
- **DNS記録**: A、AAAA、CNAME、MX、TXTレコードの取得

### 2. IPアドレス・ポートスキャン
- **Shodan統合**: 公開サービス、バナー、脆弱性情報を取得
- **Censys統合**: 証明書情報とサービス詳細を収集
- **ポート情報**: 開放ポート、サービス名、バージョンを検出

### 3. 証明書監視
- **有効期限監視**: SSL/TLS証明書の有効期限を追跡
- **自己署名証明書検出**: セキュリティリスクのある証明書を特定
- **証明書チェーン検証**: 信頼チェーンの完全性を確認

### 4. 脆弱性マッチング
- **CVEデータベース**: 検出されたサービスバージョンとCVEをマッチング
- **CVSSスコア**: 深刻度による優先度付け
- **エクスプロイト情報**: 既知のエクスプロイトを関連付け

### 5. アラート&通知
- **Slack通知**: 新規資産や脆弱性検出時に即座に通知
- **Email通知**: カスタマイズ可能なメールアラート
- **ダッシュボード**: リアルタイムアラート表示

## 🔧 設定

### スキャンスケジュール

`.env`ファイルでスキャン頻度を設定:

```env
# 24時間ごとにスキャン (秒単位)
SCAN_INTERVAL=86400

# 同時実行スキャン数
MAX_CONCURRENT_SCANS=5
```

### 通知設定

```env
# Slack通知
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Email通知
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@example.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL_TO=security-team@example.com
```

### API Keys

```env
# Shodan (推奨)
SHODAN_API_KEY=your_shodan_api_key

# Censys (オプション)
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret

# VirusTotal (オプション)
VIRUSTOTAL_API_KEY=your_virustotal_key
```

## 🗂️ プロジェクト構造

```
osint-asset-monitor/
├── backend/                    # FastAPI バックエンド
│   ├── app/
│   │   ├── api/               # APIエンドポイント
│   │   ├── core/              # 設定・セキュリティ
│   │   ├── models/            # データベースモデル
│   │   ├── services/          # ビジネスロジック
│   │   │   ├── subdomain_scanner.py  # サブドメインスキャナー
│   │   │   ├── shodan_scanner.py     # Shodan統合
│   │   │   └── ...
│   │   └── tasks/             # Celeryタスク
│   ├── tests/                 # テストコード
│   └── requirements.txt
├── scripts/                    # ユーティリティスクリプト
├── docs/                       # ドキュメント
├── docker-compose.yml
├── .env.example
└── README.md
```

## 🔐 セキュリティ

- **認証**: JWT トークンベース（実装予定）
- **API Rate Limiting**: Redis を使用したレート制限
- **データ暗号化**: 機密情報はデータベースで暗号化保存
- **監査ログ**: すべての操作を記録

## 🛣️ ロードマップ

- [x] 基本的な資産発見機能
- [x] Certificate Transparency統合
- [x] Shodan API統合
- [x] サブドメインスキャナー
- [x] Docker環境構築
- [ ] Webダッシュボード（React）
- [ ] ユーザー認証・認可
- [ ] Censys API統合
- [ ] VirusTotal統合
- [ ] 証明書有効期限監視
- [ ] 脆弱性データベースマッチング
- [ ] Slack/Email通知
- [ ] レポート生成（PDF/Excel）
- [ ] AI/MLによる異常検知
- [ ] MITRE ATT&CK マッピング

## 🤝 コントリビューション

プルリクエストを歓迎します！大きな変更の場合は、まずissueを開いて変更内容を議論してください。

1. このリポジトリをFork
2. Feature ブランチを作成 (`git checkout -b feature/AmazingFeature`)
3. 変更をCommit (`git commit -m 'Add some AmazingFeature'`)
4. ブランチにPush (`git push origin feature/AmazingFeature`)
5. Pull Requestを作成

## 📄 ライセンス

MIT License - 詳細は [LICENSE](LICENSE) ファイルを参照してください。

## 🙏 謝辞

このプロジェクトは以下のオープンソースプロジェクトを活用しています：

- [FastAPI](https://fastapi.tiangolo.com/)
- [Celery](https://docs.celeryproject.org/)
- [Shodan Python Library](https://shodan.readthedocs.io/)
- [DNSPython](https://www.dnspython.org/)
- [PostgreSQL](https://www.postgresql.org/)
- [Redis](https://redis.io/)

## 📞 サポート

- **Issue Tracker**: https://github.com/d01ki/osint-asset-monitor/issues
- **Documentation**: https://github.com/d01ki/osint-asset-monitor/wiki

---

**⚠️ 免責事項**: このツールは自組織の資産監視を目的としています。許可なく他組織のネットワークをスキャンすることは違法です。適用される法律と規制を遵守してください。

## 🎓 学習リソース

- [OSINT Framework](https://osintframework.com/)
- [Shodan Guides](https://help.shodan.io/)
- [Certificate Transparency](https://certificate.transparency.dev/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
