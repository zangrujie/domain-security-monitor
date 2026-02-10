"""
HTTP扫描模块 - 独立HTTP/HTTPS应用层扫描器
输入：域名列表文件（每行一个域名）或直接域名列表
输出：结构化JSON格式的扫描结果
"""

__version__ = "1.0.0"

from .scanner import scan_domain, scan_batch, scan_file, main