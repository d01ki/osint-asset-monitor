from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Text, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()


class Organization(Base):
    """組織モデル"""
    __tablename__ = "organizations"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    domain = Column(String, unique=True, index=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    assets = relationship("Asset", back_populates="organization")
    scans = relationship("Scan", back_populates="organization")


class Asset(Base):
    """資産モデル（ドメイン、サブドメイン、IP等）"""
    __tablename__ = "assets"
    
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"))
    
    # Asset Type: domain, subdomain, ip, certificate
    asset_type = Column(String, index=True)
    value = Column(String, index=True)  # actual domain/ip/etc
    
    # Additional Info
    metadata = Column(JSON, nullable=True)  # Store additional data as JSON
    
    # Status
    is_active = Column(Boolean, default=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="assets")
    vulnerabilities = relationship("Vulnerability", back_populates="asset")
    ports = relationship("Port", back_populates="asset")


class Scan(Base):
    """スキャン実行履歴"""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"))
    
    # Scan Info
    scan_type = Column(String)  # full, subdomain, port, certificate
    status = Column(String, default="pending")  # pending, running, completed, failed
    
    # Results
    assets_found = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    
    # Timing
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Error handling
    error_message = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="scans")


class Vulnerability(Base):
    """脆弱性情報"""
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    
    # CVE Info
    cve_id = Column(String, nullable=True, index=True)
    title = Column(String)
    description = Column(Text)
    severity = Column(String)  # critical, high, medium, low
    cvss_score = Column(String, nullable=True)
    
    # Status
    status = Column(String, default="open")  # open, acknowledged, mitigated, false_positive
    
    # Additional Info
    affected_service = Column(String, nullable=True)
    remediation = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    asset = relationship("Asset", back_populates="vulnerabilities")


class Port(Base):
    """開放ポート情報"""
    __tablename__ = "ports"
    
    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    
    port_number = Column(Integer)
    protocol = Column(String, default="tcp")  # tcp, udp
    service_name = Column(String, nullable=True)
    service_version = Column(String, nullable=True)
    banner = Column(Text, nullable=True)
    
    is_open = Column(Boolean, default=True)
    
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    asset = relationship("Asset", back_populates="ports")


class Alert(Base):
    """アラート通知"""
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Alert Type
    alert_type = Column(String)  # new_asset, new_vulnerability, certificate_expiry
    severity = Column(String)  # critical, high, medium, low, info
    
    # Message
    title = Column(String)
    message = Column(Text)
    
    # Related Entity
    related_entity_type = Column(String, nullable=True)  # asset, vulnerability, scan
    related_entity_id = Column(Integer, nullable=True)
    
    # Status
    is_read = Column(Boolean, default=False)
    is_notified = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)


class User(Base):
    """ユーザー認証"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
