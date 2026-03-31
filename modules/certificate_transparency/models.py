#!/usr/bin/env python3
"""
证书透明度数据模型定义
存储从证书透明度日志（CT logs）收集的SSL/TLS证书信息
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, ForeignKey, Index, Boolean
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import ARRAY
from modules.database.models import Base

# 使用主数据库模块中共享的 Base，避免重复 declarative_base 导致的映射冲突


class CertificateRecord(Base):
    """
    SSL/TLS证书记录表
    存储从证书透明度日志收集的证书信息
    """
    __tablename__ = 'certificate_records'
    
    id = Column(Integer, primary_key=True)
    
    # 证书标识信息
    certificate_id = Column(String(64), unique=True, nullable=False, index=True)  # SHA-256指纹
    serial_number = Column(String(128), index=True)  # 证书序列号
    
    # 证书主体信息
    common_name = Column(String(512), index=True)  # CN（Common Name）
    subject_alternative_names = Column(MutableList.as_mutable(ARRAY(String)), default=[])  # SAN列表
    organization = Column(String(512))  # 组织名
    organizational_unit = Column(String(512))  # 组织单位
    
    # 颁发者信息
    issuer_common_name = Column(String(512), index=True)  # 颁发者CN
    issuer_organization = Column(String(512))  # 颁发者组织
    certificate_authority = Column(String(256), index=True)  # 证书颁发机构
    
    # 时间信息
    not_before = Column(DateTime, nullable=False, index=True)  # 有效期开始
    not_after = Column(DateTime, nullable=False, index=True)  # 有效期结束
    logged_at = Column(DateTime, nullable=False, index=True)  # 记录到CT日志的时间
    
    # 技术信息
    signature_algorithm = Column(String(50))  # 签名算法
    key_algorithm = Column(String(50))  # 公钥算法
    key_size = Column(Integer)  # 密钥长度
    version = Column(Integer)  # X.509版本
    
    # 证书透明度特定信息
    ct_log_id = Column(String(64), index=True)  # CT日志ID
    log_entry_index = Column(Integer, index=True)  # 日志条目索引
    leaf_hash = Column(String(64))  # 叶子哈希
    
    # 数据源信息
    source = Column(String(50), nullable=False, index=True)  # 数据源：crt.sh, certstream等
    source_url = Column(Text)  # 原始数据URL
    raw_data = Column(JSON)  # 原始证书数据
    
    # 关联信息
    domain_id = Column(Integer, ForeignKey('domains.id', ondelete='SET NULL'), nullable=True, index=True)
    
    # 元数据
    is_expired = Column(Boolean, default=False, index=True)  # 是否已过期
    is_self_signed = Column(Boolean, default=False, index=True)  # 是否自签名
    is_wildcard = Column(Boolean, default=False, index=True)  # 是否通配符证书
    has_revoked = Column(Boolean, default=False, index=True)  # 是否已吊销
    
    # 时间戳
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), 
                       onupdate=lambda: datetime.now(timezone.utc))
    
    # 关系
    domain_obj = relationship("Domain", backref="certificate_records")
    
    def __repr__(self):
        return f"<CertificateRecord(id={self.id}, cn='{self.common_name}', issuer='{self.issuer_common_name}')>"
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'id': self.id,
            'certificate_id': self.certificate_id,
            'serial_number': self.serial_number,
            'common_name': self.common_name,
            'subject_alternative_names': self.subject_alternative_names,
            'organization': self.organization,
            'issuer_common_name': self.issuer_common_name,
            'issuer_organization': self.issuer_organization,
            'certificate_authority': self.certificate_authority,
            'not_before': self.not_before.isoformat() if self.not_before else None,
            'not_after': self.not_after.isoformat() if self.not_after else None,
            'logged_at': self.logged_at.isoformat() if self.logged_at else None,
            'signature_algorithm': self.signature_algorithm,
            'key_algorithm': self.key_algorithm,
            'key_size': self.key_size,
            'ct_log_id': self.ct_log_id,
            'source': self.source,
            'is_expired': self.is_expired,
            'is_self_signed': self.is_self_signed,
            'is_wildcard': self.is_wildcard,
            'has_revoked': self.has_revoked,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'domain_id': self.domain_id
        }


class CertificateDomainMapping(Base):
    """
    证书与域名关联表
    记录证书中包含的所有域名（CN和SAN）
    """
    __tablename__ = 'certificate_domain_mappings'
    
    id = Column(Integer, primary_key=True)
    
    # 关联信息
    certificate_id = Column(Integer, ForeignKey('certificate_records.id', ondelete='CASCADE'), nullable=False, index=True)
    domain_id = Column(Integer, ForeignKey('domains.id', ondelete='SET NULL'), nullable=True, index=True)
    
    # 域名信息
    domain_name = Column(String(512), nullable=False, index=True)  # 域名（完整）
    base_domain = Column(String(256), index=True)  # 基础域名（二级域名）
    is_wildcard = Column(Boolean, default=False, index=True)  # 是否通配符域名
    is_common_name = Column(Boolean, default=False, index=True)  # 是否是CN
    
    # 发现时间
    discovered_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    
    # 关系
    certificate = relationship("CertificateRecord", backref="domain_mappings")
    domain_obj = relationship("Domain", backref="certificate_mappings")
    
    def __repr__(self):
        return f"<CertificateDomainMapping(id={self.id}, domain='{self.domain_name}', cert={self.certificate_id})>"


class CTLogSource(Base):
    """
    证书透明度日志源配置表
    管理不同的CT日志源
    """
    __tablename__ = 'ct_log_sources'
    
    id = Column(Integer, primary_key=True)
    
    # 日志源信息
    name = Column(String(50), unique=True, nullable=False, index=True)
    display_name = Column(String(100), nullable=False)
    log_url = Column(Text, nullable=False)  # CT日志URL
    api_endpoint = Column(Text)  # API端点（如果有）
    
    # 状态信息
    is_active = Column(Boolean, default=True, index=True)  # 日志源是否活跃
    last_successful_sync = Column(DateTime)  # 最后成功同步时间
    total_certificates = Column(Integer, default=0)  # 从该源获取的证书总数
    
    # 技术信息
    log_operator = Column(String(256))  # 日志运营者
    log_description = Column(Text)  # 日志描述
    public_key = Column(Text)  # 日志公钥
    log_type = Column(String(20))  # 日志类型：production, test等
    
    # 时间戳
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), 
                       onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f"<CTLogSource(id={self.id}, name='{self.name}', active={self.is_active})>"


class CertStreamSubscription(Base):
    """
    CertStream订阅配置表
    管理实时证书流订阅
    """
    __tablename__ = 'certstream_subscriptions'
    
    id = Column(Integer, primary_key=True)
    
    # 订阅配置
    subscription_name = Column(String(50), unique=True, nullable=False, index=True)
    certstream_url = Column(Text, default='wss://certstream.calidog.io/')  # CertStream WebSocket URL
    
    # 筛选条件
    filter_domains = Column(MutableList.as_mutable(ARRAY(String)), default=[])  # 关注的域名列表
    filter_organizations = Column(MutableList.as_mutable(ARRAY(String)), default=[])  # 关注的组织
    filter_issuers = Column(MutableList.as_mutable(ARRAY(String)), default=[])  # 关注的颁发者
    
    # 状态信息
    is_running = Column(Boolean, default=False, index=True)  # 是否正在运行
    last_connection_time = Column(DateTime)  # 最后连接时间
    last_message_time = Column(DateTime)  # 最后接收消息时间
    total_messages = Column(Integer, default=0)  # 总消息数
    total_certificates = Column(Integer, default=0)  # 总证书数
    
    # 错误处理
    last_error = Column(Text)  # 最后错误信息
    error_count = Column(Integer, default=0)  # 错误计数
    auto_reconnect = Column(Boolean, default=True)  # 是否自动重连
    
    # 时间戳
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), 
                       onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f"<CertStreamSubscription(id={self.id}, name='{self.subscription_name}', running={self.is_running})>"


# 创建索引以提高查询性能
Index('idx_cert_cn', CertificateRecord.common_name)
Index('idx_cert_issuer', CertificateRecord.issuer_common_name)
Index('idx_cert_dates', CertificateRecord.not_before, CertificateRecord.not_after)
Index('idx_cert_source', CertificateRecord.source, CertificateRecord.logged_at)
Index('idx_cert_domain_id', CertificateRecord.domain_id)
Index('idx_cert_mapping_domain', CertificateDomainMapping.domain_name)
Index('idx_cert_mapping_cert_domain', CertificateDomainMapping.certificate_id, CertificateDomainMapping.domain_id)


# 预定义的CT日志源配置
DEFAULT_CT_LOG_SOURCES = {
    'google_argon': {
        'name': 'google_argon',
        'display_name': 'Google Argon',
        'log_url': 'https://ct.googleapis.com/logs/argon2024/',
        'log_operator': 'Google',
        'log_type': 'production'
    },
    'google_xenon': {
        'name': 'google_xenon',
        'display_name': 'Google Xenon',
        'log_url': 'https://ct.googleapis.com/logs/xenon2024/',
        'log_operator': 'Google',
        'log_type': 'production'
    },
    'cloudflare_nimbus': {
        'name': 'cloudflare_nimbus',
        'display_name': 'Cloudflare Nimbus',
        'log_url': 'https://ct.cloudflare.com/logs/nimbus2024/',
        'log_operator': 'Cloudflare',
        'log_type': 'production'
    },
    'digicert': {
        'name': 'digicert',
        'display_name': 'DigiCert',
        'log_url': 'https://ct1.digicert-ct.com/log/',
        'log_operator': 'DigiCert',
        'log_type': 'production'
    }
}


def create_tables(engine):
    """创建证书透明度相关表"""
    Base.metadata.create_all(engine)
    print(f"证书透明度模块表创建完成: {len(Base.metadata.tables)}个表")


def drop_tables(engine):
    """删除证书透明度相关表"""
    Base.metadata.drop_all(engine)
    print("证书透明度模块表已删除")