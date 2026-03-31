#!/usr/bin/env python3
"""
被动DNS模块 - 支持多种被动DNS数据源集成
"""

__version__ = "1.0.0"
__author__ = "Domain Security Monitor Team"

from .collector import PassiveDNSCollector
from .aggregator import PassiveDNSAggregator
from .models import PassiveDNSRecord

__all__ = [
    'PassiveDNSCollector',
    'PassiveDNSAggregator',
    'PassiveDNSRecord'
]
