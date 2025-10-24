from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Text, JSON, Float, Enum as SQLEnum
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import enum

Base = declarative_base()


# Enums
class IoC_TypeEnum(enum.Enum):
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


class IoC_SeverityEnum(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IoC_StatusEnum(enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    WHITELISTED = "whitelisted"
    FALSE_POSITIVE = "false_positive"


# Models
class Organization(Base):
    """組織モデル"""
    __tablename__ = "organizations"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    domain = Column(String, unique=True, index=True)
    description = Column(Text, nullable=True)
    industry = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    assets = relationship("Asset", back_populates="organization", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="organization", cascade="all, delete-orphan")


class Asset(Base):
    """資産モデル（ドメイン、サブドメイン、IP等）"""
    __tablename__ = "assets"
    
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"))
    
    # Asset Type: domain, subdomain, ip, certificate
    asset_type = Column(String, index=True)
    value = Column(String, index=True)
    
    # Threat Intelligence
    threat_score = Column(Integer, default=0)  # 0-100
    risk_level = Column(String, default="INFO")  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    
    # Additional Info
    metadata = Column(JSON, nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="assets")
    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan")
    ports = relationship("Port", back_populates="asset", cascade="all, delete-orphan")
    threat_intel = relationship("ThreatIntelligence", back_populates="asset", cascade="all, delete-orphan")


class Scan(Base):
    """スキャン実行履歴"""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"))
    
    # Scan Info
    scan_type = Column(String)  # full, subdomain, port, certificate, threat_intel
    status = Column(String, default="pending")  # pending, running, completed, failed
    
    # Results
    assets_found = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    iocs_found = Column(Integer, default=0)
    
    # Timing
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    
    # Error handling
    error_message = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="scans")


class Vulnerability(Base):
    """脆弱性情報"""
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"))
    
    # CVE Info
    cve_id = Column(String, nullable=True, index=True)
    title = Column(String)
    description = Column(Text)
    severity = Column(String)  # critical, high, medium, low
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String, nullable=True)
    
    # Status
    status = Column(String, default="open")  # open, acknowledged, mitigated, false_positive
    
    # Additional Info
    affected_service = Column(String, nullable=True)
    affected_version = Column(String, nullable=True)
    remediation = Column(Text, nullable=True)
    exploit_available = Column(Boolean, default=False)
    
    # MITRE ATT&CK
    attack_techniques = Column(JSON, nullable=True)  # List of technique IDs
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    asset = relationship("Asset", back_populates="vulnerabilities")


class Port(Base):
    """開放ポート情報"""
    __tablename__ = "ports"
    
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"))
    
    port_number = Column(Integer, index=True)
    protocol = Column(String, default="tcp")  # tcp, udp
    service_name = Column(String, nullable=True)
    service_version = Column(String, nullable=True)
    banner = Column(Text, nullable=True)
    
    is_open = Column(Boolean, default=True)
    
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    asset = relationship("Asset", back_populates="ports")


class ThreatIntelligence(Base):
    """脅威インテリジェンス情報"""
    __tablename__ = "threat_intelligence"
    
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=True)
    
    # Target Info
    target_type = Column(String)  # domain, ip, hash
    target_value = Column(String, index=True)
    
    # Threat Info
    threat_score = Column(Integer, default=0)  # 0-100
    risk_level = Column(String)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    
    # Sources
    sources = Column(JSON)  # AlienVault, URLhaus, Feodo, ThreatFox, VirusTotal
    
    # Related Entities
    related_malware = Column(String, nullable=True)
    related_threat_actor = Column(String, nullable=True)
    related_campaign = Column(String, nullable=True)
    
    # MITRE ATT&CK
    attack_techniques = Column(JSON, nullable=True)  # List of techniques
    attack_tactics = Column(JSON, nullable=True)  # List of tactics
    
    # Metadata
    metadata = Column(JSON, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    asset = relationship("Asset", back_populates="threat_intel")


class IoC(Base):
    """IoC (Indicator of Compromise) 管理"""
    __tablename__ = "iocs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # IoC Info
    indicator = Column(String, index=True, unique=True)
    ioc_type = Column(SQLEnum(IoC_TypeEnum), index=True)
    severity = Column(SQLEnum(IoC_SeverityEnum), default=IoC_SeverityEnum.MEDIUM)
    status = Column(SQLEnum(IoC_StatusEnum), default=IoC_StatusEnum.ACTIVE)
    
    # Source & Confidence
    source = Column(String)  # alienvault, urlhaus, manual, etc.
    confidence = Column(Integer, default=50)  # 0-100
    
    # Description & Context
    description = Column(Text, nullable=True)
    tags = Column(JSON, nullable=True)  # List of tags
    
    # Related Entities
    related_malware = Column(String, nullable=True, index=True)
    related_threat_actor = Column(String, nullable=True, index=True)
    related_campaign = Column(String, nullable=True)
    
    # MITRE ATT&CK
    attack_techniques = Column(JSON, nullable=True)
    
    # Threat Scoring
    threat_score = Column(Integer, default=0)
    
    # Timestamps
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    
    # Enrichment
    enrichment_data = Column(JSON, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class MITREAttackTechnique(Base):
    """MITRE ATT&CK 技術情報（キャッシュ）"""
    __tablename__ = "mitre_attack_techniques"
    
    id = Column(Integer, primary_key=True, index=True)
    
    technique_id = Column(String, unique=True, index=True)  # T1566
    name = Column(String)
    description = Column(Text)
    
    # Tactics
    tactics = Column(JSON)  # List of tactic names
    
    # Platform & Data Sources
    platforms = Column(JSON, nullable=True)
    data_sources = Column(JSON, nullable=True)
    
    # Detection & Mitigation
    detection = Column(Text, nullable=True)
    mitigations = Column(JSON, nullable=True)
    
    # URLs
    attack_url = Column(String)
    
    # Metadata
    metadata = Column(JSON, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ThreatActor(Base):
    """脅威アクター（APTグループ等）"""
    __tablename__ = "threat_actors"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Basic Info
    name = Column(String, unique=True, index=True)
    aliases = Column(JSON, nullable=True)  # List of aliases
    description = Column(Text)
    
    # Attribution
    country = Column(String, nullable=True)
    motivation = Column(JSON, nullable=True)  # financial, espionage, etc.
    sophistication = Column(String, nullable=True)  # low, medium, high, expert
    
    # MITRE ATT&CK Info
    mitre_group_id = Column(String, nullable=True)
    attack_techniques = Column(JSON, nullable=True)
    attack_software = Column(JSON, nullable=True)
    
    # Target Industries
    target_industries = Column(JSON, nullable=True)
    target_countries = Column(JSON, nullable=True)
    
    # Activity
    first_seen = Column(DateTime, nullable=True)
    last_activity = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    
    # References
    references = Column(JSON, nullable=True)  # URLs, reports
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Alert(Base):
    """アラート通知"""
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Alert Type
    alert_type = Column(String, index=True)  # new_asset, new_vulnerability, new_ioc, certificate_expiry, threat_detected
    severity = Column(String)  # critical, high, medium, low, info
    
    # Message
    title = Column(String)
    message = Column(Text)
    
    # Related Entity
    related_entity_type = Column(String, nullable=True)  # asset, vulnerability, scan, ioc
    related_entity_id = Column(Integer, nullable=True)
    
    # Status
    is_read = Column(Boolean, default=False)
    is_notified = Column(Boolean, default=False)
    is_resolved = Column(Boolean, default=False)
    
    # Actions Taken
    actions = Column(JSON, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)


class User(Base):
    """ユーザー認証"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    
    # Profile
    full_name = Column(String, nullable=True)
    role = Column(String, default="analyst")  # admin, analyst, viewer
    
    # Status
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    
    # API Access
    api_key = Column(String, nullable=True, unique=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
