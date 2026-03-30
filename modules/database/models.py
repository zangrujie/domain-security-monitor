#!/usr/bin/env python3
"""
Database model definitions - PostgreSQL table structure mapping
"""

from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.dialects.postgresql import ARRAY
import datetime

Base = declarative_base()

class Domain(Base):
    """Domain basic information table"""
    __tablename__ = 'domains'
    
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    original_target = Column(String(255))
    punycode = Column(String(255))
    visual_similarity = Column(Float, default=0.0)
    generation_method = Column(String(50))
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    # Relationships
    dns_scans = relationship("DNSScan", back_populates="domain", cascade="all, delete-orphan")
    http_scans = relationship("HTTPScan", back_populates="domain", cascade="all, delete-orphan")
    whois_records = relationship("WhoisRecord", back_populates="domain", cascade="all, delete-orphan")
    threat_intelligence = relationship("ThreatIntelligence", back_populates="domain", cascade="all, delete-orphan")
    risk_assessments = relationship("RiskAssessment", back_populates="domain", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Domain(id={self.id}, domain='{self.domain}')>"

class DNSScan(Base):
    """DNS scan results table"""
    __tablename__ = 'dns_scans'
    
    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey('domains.id', ondelete='CASCADE'), nullable=False, index=True)
    has_dns_record = Column(Boolean, default=False)
    resolved_ips = Column(MutableList.as_mutable(ARRAY(String)), default=[])
    response_time_ms = Column(Float, default=0.0)
    dns_server = Column(String(50))
    scan_timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    domain = relationship("Domain", back_populates="dns_scans")
    
    def __repr__(self):
        return f"<DNSScan(id={self.id}, domain_id={self.domain_id}, has_record={self.has_dns_record})>"

class HTTPScan(Base):
    """HTTP scan results table"""
    __tablename__ = 'http_scans'
    
    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey('domains.id', ondelete='CASCADE'), nullable=False, index=True)
    http_status = Column(Integer)
    https_status = Column(Integer)
    preferred_protocol = Column(String(10))
    final_url = Column(Text)
    redirect_count = Column(Integer, default=0)
    headers = Column(JSON)  # Store HTTP headers as JSON
    ssl_certificate = Column(JSON)  # Store SSL certificate info as JSON
    page_analysis = Column(JSON)  # Store page analysis results as JSON
    http_risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20))
    scan_timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    domain = relationship("Domain", back_populates="http_scans")
    
    def __repr__(self):
        return f"<HTTPScan(id={self.id}, domain_id={self.domain_id}, risk_score={self.http_risk_score})>"


class WebScreenshot(Base):
    """Active probing screenshot and page metadata table"""
    __tablename__ = "web_screenshots"

    id = Column(Integer, primary_key=True)
    domain = Column(String(255), nullable=False, index=True)
    screenshot_path = Column(Text, nullable=False)
    perceptual_hash = Column(String(64))
    ssim_score = Column(Float)
    page_title = Column(Text)
    status_code = Column(Integer)
    load_ms = Column(Integer)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"<WebScreenshot(id={self.id}, domain='{self.domain}', status={self.status_code})>"

class WhoisRecord(Base):
    """WHOIS information table"""
    __tablename__ = 'whois_records'
    
    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey('domains.id', ondelete='CASCADE'), nullable=False, index=True)
    registrar = Column(String(255))
    creation_date = Column(DateTime)
    expiration_date = Column(DateTime)
    updated_date = Column(DateTime)
    name_servers = Column(MutableList.as_mutable(ARRAY(String)), default=[])
    status = Column(MutableList.as_mutable(ARRAY(String)), default=[])
    emails = Column(MutableList.as_mutable(ARRAY(String)), default=[])
    registrant = Column(JSON)  # Registrant information
    admin = Column(JSON)  # Admin contact information
    tech = Column(JSON)  # Technical contact information
    raw_text = Column(Text)
    whois_risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20))
    query_timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    domain = relationship("Domain", back_populates="whois_records")
    
    def __repr__(self):
        return f"<WhoisRecord(id={self.id}, domain_id={self.domain_id}, registrar='{self.registrar}')>"

class ThreatIntelligence(Base):
    """Threat intelligence table"""
    __tablename__ = 'threat_intelligence'
    
    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey('domains.id', ondelete='CASCADE'), nullable=False, index=True)
    threat_sources_checked = Column(MutableList.as_mutable(ARRAY(String)), default=[])
    threat_results = Column(JSON)  # Store threat intelligence results as JSON
    threat_risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20))
    check_timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    domain = relationship("Domain", back_populates="threat_intelligence")
    
    def __repr__(self):
        return f"<ThreatIntelligence(id={self.id}, domain_id={self.domain_id}, risk_score={self.threat_risk_score})>"

class RiskAssessment(Base):
    """Comprehensive risk assessment table"""
    __tablename__ = 'risk_assessments'
    
    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey('domains.id', ondelete='CASCADE'), nullable=False, index=True)
    visual_similarity_score = Column(Float, default=0.0)
    whois_risk_score = Column(Float, default=0.0)
    http_risk_score = Column(Float, default=0.0)
    threat_risk_score = Column(Float, default=0.0)
    dns_risk_score = Column(Float, default=0.0)
    weighted_total_score = Column(Float, default=0.0)
    risk_level = Column(String(20))
    risk_factors = Column(MutableList.as_mutable(ARRAY(String)), default=[])
    confidence = Column(Float, default=0.0)
    assessment_timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    domain = relationship("Domain", back_populates="risk_assessments")
    
    def __repr__(self):
        return f"<RiskAssessment(id={self.id}, domain_id={self.domain_id}, total_score={self.weighted_total_score})>"

# Utility functions
def create_tables(engine):
    """Create all tables"""
    Base.metadata.create_all(engine)
    print(f"Database tables created: {len(Base.metadata.tables)} tables")

def drop_tables(engine):
    """Drop all tables (for testing and reset)"""
    Base.metadata.drop_all(engine)
    print("Database tables dropped")
