"""
数据库模块 - 提供PostgreSQL数据存储和查询功能
"""

from .models import Base, Domain, DNSScan, HTTPScan, WhoisRecord, ThreatIntelligence, RiskAssessment, WebScreenshot
from .dao import DomainDAO, ScanDAO, ThreatIntelDAO, RiskDAO
from .connection import DatabaseConnection, create_engine, get_session

__all__ = [
    'Base',
    'Domain',
    'DNSScan', 
    'HTTPScan',
    'WhoisRecord',
    'ThreatIntelligence',
    'RiskAssessment',
    'WebScreenshot',
    'DomainDAO',
    'ScanDAO',
    'ThreatIntelDAO',
    'RiskDAO',
    'DatabaseConnection',
    'create_engine',
    'get_session'
]
