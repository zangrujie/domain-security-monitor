"""
威胁情报模块 - 集成多源威胁情报API
输入：域名列表
输出：结构化威胁情报数据
"""

__version__ = "1.0.0"

from .intel_scanner import (
    check_domain_reputation,
    check_multiple_sources,
    scan_file,
    main
)