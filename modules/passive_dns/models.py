#!/usr/bin/env python3
"""
被动DNS数据模型定义
与主数据库模型集成，提供被动DNS记录存储
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, ForeignKey, Index, Float, Boolean
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import ARRAY
from modules.database.models import Base

# 使用主数据库模块中共享的 Base，避免重复 declarative_base 导致的映射冲突


class PassiveDNSRecord(Base):
    """
    被动DNS记录表
    存储从多个数据源收集的DNS解析记录
    """
    __tablename__ = 'passive_dns_records'
    
    id = Column(Integer, primary_key=True)
    
    # 域名信息
    domain = Column(String(512), nullable=False, index=True)
    query_type = Column(String(10), nullable=False, default='A')  # A, AAAA, CNAME, NS, MX, TXT等
    
    # 解析结果
    rdata = Column(Text)  # 解析值（IP地址、CNAME目标等）
    rdata_ipv4 = Column(String(45))  # IPv4地址（如果有）
    rdata_ipv6 = Column(String(128))  # IPv6地址（如果有）
    rdata_domain = Column(String(512))  # 如果是CNAME，目标域名
    
    # 数据源信息
    source = Column(String(50), nullable=False, index=True)  # 数据源标识
    source_id = Column(String(100), index=True)  # 数据源中的唯一ID
    source_url = Column(Text)  # 原始数据URL（如果有）
    
    # 时间信息
    first_seen = Column(DateTime, nullable=False, index=True)  # 首次出现时间
    last_seen = Column(DateTime, nullable=False, index=True)  # 最近出现时间
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))  # 记录入库时间
    
    # 附加信息
    count = Column(Integer, default=1)  # 出现次数（某些数据源提供）
    ttl = Column(Integer)  # TTL值（如果有）
    bailiwick = Column(String(512))  # 权威域
    rrtype = Column(String(10))  # 记录类型（与query_type相同，兼容性字段）
    
    # 元数据
    raw_metadata = Column(JSON)  # 原始数据元数据
    tags = Column(MutableList.as_mutable(ARRAY(String)), default=[])  # 标签：malware, phishing, etc.
    
    # 关联到主域名表（可选）
    domain_id = Column(Integer, ForeignKey('domains.id', ondelete='SET NULL'), nullable=True, index=True)
    
    # 关系
    domain_obj = relationship("Domain", backref="passive_dns_records")
    
    def __repr__(self):
        return f"<PassiveDNSRecord(id={self.id}, domain='{self.domain}', rdata='{self.rdata}', source='{self.source}')>"
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式，便于JSON序列化"""
        return {
            'id': self.id,
            'domain': self.domain,
            'query_type': self.query_type,
            'rdata': self.rdata,
            'rdata_ipv4': self.rdata_ipv4,
            'rdata_ipv6': self.rdata_ipv6,
            'rdata_domain': self.rdata_domain,
            'source': self.source,
            'source_id': self.source_id,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'count': self.count,
            'ttl': self.ttl,
            'bailiwick': self.bailiwick,
            'rrtype': self.rrtype,
            'raw_metadata': self.raw_metadata,
            'tags': self.tags,
            'domain_id': self.domain_id
        }


class PassiveDNSSource(Base):
    """
    被动DNS数据源配置表
    管理不同数据源的连接信息和配置
    """
    __tablename__ = 'passive_dns_sources'
    
    id = Column(Integer, primary_key=True)
    
    # 数据源标识
    name = Column(String(50), unique=True, nullable=False, index=True)
    display_name = Column(String(100), nullable=False)
    source_type = Column(String(20), nullable=False, index=True)  # commercial, open_source, internal
    
    # 连接配置
    api_endpoint = Column(Text)  # API端点URL
    api_key = Column(Text)  # API密钥（加密存储）
    api_username = Column(String(100))  # API用户名
    api_password = Column(Text)  # API密码（加密存储）
    
    # 查询参数
    query_url_template = Column(Text)  # 查询URL模板
    query_params = Column(JSON)  # 查询参数
    request_headers = Column(JSON)  # 请求头
    
    # 速率限制
    rate_limit_per_second = Column(Float, default=1.0)  # 每秒请求限制
    rate_limit_per_day = Column(Integer, default=1000)  # 每日请求限制
    rate_limit_reset_time = Column(DateTime)  # 速率限制重置时间
    
    # 数据范围
    supports_historical = Column(Boolean, default=False)  # 是否支持历史查询
    supports_real_time = Column(Boolean, default=False)  # 是否支持实时数据流
    data_retention_days = Column(Integer, default=90)  # 数据保留天数
    max_lookback_days = Column(Integer, default=30)  # 最大回溯天数
    
    # 状态信息
    is_enabled = Column(Boolean, default=True, index=True)  # 是否启用
    last_successful_query = Column(DateTime)  # 最后成功查询时间
    total_queries = Column(Integer, default=0)  # 总查询次数
    failed_queries = Column(Integer, default=0)  # 失败查询次数
    last_error = Column(Text)  # 最后错误信息
    
    # 元数据
    description = Column(Text)  # 数据源描述
    documentation_url = Column(Text)  # 文档URL
    pricing_tier = Column(String(50))  # 定价等级
    
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def __repr__(self):
        return f"<PassiveDNSSource(id={self.id}, name='{self.name}', type='{self.source_type}', enabled={self.is_enabled})>"


class PassiveDNSQueryCache(Base):
    """
    被动DNS查询缓存表
    缓存查询结果，减少对数据源的重复请求
    """
    __tablename__ = 'passive_dns_query_cache'
    
    id = Column(Integer, primary_key=True)
    
    # 查询参数
    query_hash = Column(String(64), unique=True, nullable=False, index=True)  # 查询参数哈希
    domain = Column(String(512), nullable=False, index=True)
    query_type = Column(String(10), nullable=False, default='A')
    source_name = Column(String(50), nullable=False, index=True)
    query_params = Column(JSON)  # 原始查询参数
    
    # 结果缓存
    result_data = Column(JSON, nullable=False)  # 查询结果数据
    result_count = Column(Integer, default=0)  # 结果数量
    
    # 时间信息
    query_time = Column(DateTime, nullable=False, index=True)  # 查询时间
    cache_until = Column(DateTime, nullable=False, index=True)  # 缓存有效期至
    
    # 状态
    hit_count = Column(Integer, default=0)  # 缓存命中次数
    last_hit_time = Column(DateTime)  # 最后命中时间
    
    def __repr__(self):
        return f"<PassiveDNSQueryCache(id={self.id}, domain='{self.domain}', source='{self.source_name}', hits={self.hit_count})>"


# 创建索引以提高查询性能
Index('idx_passive_dns_domain_source', PassiveDNSRecord.domain, PassiveDNSRecord.source)
Index('idx_passive_dns_rdata', PassiveDNSRecord.rdata)
Index('idx_passive_dns_timestamp', PassiveDNSRecord.timestamp)
Index('idx_passive_dns_first_last_seen', PassiveDNSRecord.first_seen, PassiveDNSRecord.last_seen)
Index('idx_passive_dns_domain_rdata', PassiveDNSRecord.domain, PassiveDNSRecord.rdata)


# 预定义的数据源配置
DEFAULT_SOURCES_CONFIG = {
    'dnsdb': {
        'name': 'dnsdb',
        'display_name': 'Farsight DNSDB',
        'source_type': 'commercial',
        'description': 'Farsight Security DNSDB - 大型被动DNS数据库',
        'supports_historical': True,
        'supports_real_time': False,
        'max_lookback_days': 90
    },
    'virus_total': {
        'name': 'virus_total',
        'display_name': 'VirusTotal Passive DNS',
        'source_type': 'commercial',
        'description': 'VirusTotal被动DNS数据',
        'supports_historical': True,
        'supports_real_time': False,
        'max_lookback_days': 365
    },
    'circl': {
        'name': 'circl',
        'display_name': 'CIRCL Passive DNS',
        'source_type': 'open_source',
        'description': 'CIRCL Luxembourg开源被动DNS',
        'supports_historical': True,
        'supports_real_time': False,
        'max_lookback_days': 30
    },
    'internal_sensor': {
        'name': 'internal_sensor',
        'display_name': '内部DNS传感器',
        'source_type': 'internal',
        'description': '自建DNS流量传感器',
        'supports_historical': True,
        'supports_real_time': True,
        'max_lookback_days': 365
    }
}


def create_tables(engine):
    """创建被动DNS相关表"""
    Base.metadata.create_all(engine)
    print(f"被动DNS模块表创建完成: {len(Base.metadata.tables)}个表")


def drop_tables(engine):
    """删除被动DNS相关表"""
    Base.metadata.drop_all(engine)
    print("被动DNS模块表已删除")