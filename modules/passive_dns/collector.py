#!/usr/bin/env python3
"""
被动DNS收集器 - 支持多种被动DNS数据源查询和整合
"""

import asyncio
import hashlib
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any, Union
from urllib.parse import urlencode

import aiohttp
import requests
from sqlalchemy.orm import Session
import ipaddress
import socket

from .models import (
    PassiveDNSRecord, PassiveDNSSource, PassiveDNSQueryCache,
    DEFAULT_SOURCES_CONFIG
)
from .aggregator import PassiveDNSAggregator

logger = logging.getLogger(__name__)


class PassiveDNSCollector:
    """
    被动DNS收集器类
    支持多个数据源的查询、缓存和结果整合
    """
    
    def __init__(
        self,
        session: Session,
        sources_config: Optional[Dict[str, Any]] = None,
        cache_ttl_hours: int = 24,
        rate_limit_delay: float = 1.0
    ):
        """
        初始化被动DNS收集器
        
        Args:
            session: SQLAlchemy数据库会话
            sources_config: 数据源配置字典，默认为DEFAULT_SOURCES_CONFIG
            cache_ttl_hours: 查询缓存有效期（小时）
            rate_limit_delay: API调用延迟（秒）
        """
        self.session = session
        self.sources_config = sources_config or DEFAULT_SOURCES_CONFIG
        self.cache_ttl_hours = cache_ttl_hours
        self.rate_limit_delay = rate_limit_delay
        
        # 初始化数据源配置
        self._init_sources()
        
        # 创建aiohttp会话（用于异步请求）
        self.aiohttp_session = None
        
        logger.info(f"被动DNS收集器初始化完成，已配置 {len(self.sources_config)} 个数据源")
    
    def _init_sources(self):
        """初始化数据源配置到数据库"""
        for source_name, source_config in self.sources_config.items():
            existing = self.session.query(PassiveDNSSource).filter_by(name=source_name).first()
            if not existing:
                # 尝试从环境变量读取常见API密钥并注入到数据源记录中，避免运行时缺少密钥
                api_key = None
                try:
                    import os
                    # VirusTotal
                    if source_name == 'virus_total':
                        api_key = os.getenv('VT_API_KEY') or os.getenv('VIRUSTOTAL_API_KEY')
                    # DNSDB / Passive DNS commercial provider
                    if source_name == 'dnsdb':
                        api_key = os.getenv('PASSIVE_DNS_API_KEY') or os.getenv('DNSDB_API_KEY')
                    # 其它数据源可以按需扩展
                    if isinstance(api_key, str):
                        api_key = api_key.replace('\r', '').strip()
                except Exception:
                    api_key = None

                source = PassiveDNSSource(
                    name=source_name,
                    display_name=source_config.get('display_name', source_name),
                    source_type=source_config.get('source_type', 'unknown'),
                    description=source_config.get('description', ''),
                    supports_historical=source_config.get('supports_historical', False),
                    supports_real_time=source_config.get('supports_real_time', False),
                    max_lookback_days=source_config.get('max_lookback_days', 30),
                    is_enabled=source_config.get('is_enabled', True),
                    api_key=api_key
                )
                self.session.add(source)
        
        try:
            self.session.commit()
        except Exception as e:
            self.session.rollback()
            logger.warning(f"初始化数据源配置时出错: {e}")
    
    def _get_query_hash(self, domain: str, query_type: str, source_name: str, params: Dict = None) -> str:
        """生成查询参数哈希作为缓存键"""
        params = params or {}
        query_str = f"{domain}:{query_type}:{source_name}:{json.dumps(params, sort_keys=True)}"
        return hashlib.sha256(query_str.encode()).hexdigest()
    
    def _get_cached_result(self, query_hash: str) -> Optional[Dict]:
        """从缓存获取查询结果"""
        try:
            cache_entry = self.session.query(PassiveDNSQueryCache).filter_by(
                query_hash=query_hash
            ).first()
            
            if cache_entry and cache_entry.cache_until > datetime.now(timezone.utc):
                # 更新命中统计
                cache_entry.hit_count += 1
                cache_entry.last_hit_time = datetime.now(timezone.utc)
                self.session.commit()
                
                logger.debug(f"缓存命中: {cache_entry.domain} from {cache_entry.source_name}")
                return cache_entry.result_data
            
        except Exception as e:
            logger.debug(f"查询缓存时出错: {e}")
        
        return None
    
    def _save_to_cache(self, query_hash: str, domain: str, query_type: str, 
                      source_name: str, params: Dict, result: Dict):
        """保存查询结果到缓存"""
        try:
            cache_until = datetime.now(timezone.utc) + timedelta(hours=self.cache_ttl_hours)
            
            cache_entry = PassiveDNSQueryCache(
                query_hash=query_hash,
                domain=domain,
                query_type=query_type,
                source_name=source_name,
                query_params=params,
                result_data=result,
                result_count=len(result.get('records', [])),
                query_time=datetime.now(timezone.utc),
                cache_until=cache_until,
                hit_count=1,
                last_hit_time=datetime.now(timezone.utc)
            )
            
            self.session.add(cache_entry)
            self.session.commit()
            
        except Exception as e:
            self.session.rollback()
            logger.debug(f"保存缓存时出错: {e}")
    
    async def _make_async_request(self, url: str, headers: Dict = None, 
                                params: Dict = None, timeout: int = 30) -> Optional[Dict]:
        """异步HTTP请求"""
        if self.aiohttp_session is None:
            self.aiohttp_session = aiohttp.ClientSession()
        
        try:
            async with self.aiohttp_session.get(
                url, headers=headers, params=params, timeout=timeout
            ) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logger.warning(f"HTTP请求失败: {response.status} - {url}")
                    return None
        except Exception as e:
            logger.debug(f"异步请求失败: {e}")
            return None
    
    def _make_sync_request(self, url: str, headers: Dict = None, 
                          params: Dict = None, timeout: int = 30) -> Optional[Dict]:
        """同步HTTP请求"""
        try:
            response = requests.get(url, headers=headers, params=params, timeout=timeout)
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"HTTP请求失败: {response.status_code} - {url}")
                return None
        except Exception as e:
            logger.debug(f"同步请求失败: {e}")
            return None
    
    def query_circl_pdns(self, domain: str, query_type: str = 'A', 
                        limit: int = 100) -> Dict[str, Any]:
        """
        查询CIRCL开源被动DNS
        
        Args:
            domain: 要查询的域名
            query_type: 查询类型（A, AAAA, CNAME等）
            limit: 返回结果数量限制
            
        Returns:
            查询结果字典
        """
        source_name = 'circl'
        params = {'limit': limit}
        query_hash = self._get_query_hash(domain, query_type, source_name, params)
        
        # 如果传入的是 IP，尝试进行反向 DNS（轻量处理），并返回伪造的被动 DNS 结果结构
        try:
            ipaddress.ip_address(domain)
            try:
                host, aliases, _ = socket.gethostbyaddr(domain)
                rdns_names = [host] + aliases
            except Exception:
                rdns_names = []

            response_data = {
                'source': source_name,
                'domain': domain,
                'query_type': query_type,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'records': []
            }
            for name in rdns_names:
                response_data['records'].append({
                    'domain': name,
                    'query_type': query_type,
                    'rdata': domain,
                    'first_seen': None,
                    'last_seen': None,
                    'count': 1,
                    'rrname': name,
                    'rrtype': 'A',
                    'source': source_name
                })

            query_hash = self._get_query_hash(domain, query_type, source_name, {'ip_reverse': True})
            self._save_to_cache(query_hash, domain, query_type, source_name, {'ip_reverse': True}, response_data)
            return response_data
        except ValueError:
            # Not an IP — continue normal flow
            pass

        # 检查缓存
        cached = self._get_cached_result(query_hash)
        if cached:
            return cached
        
        # CIRCL PDNS API端点
        url = f"https://www.circl.lu/pdns/query/{domain}"
        headers = {'Accept': 'application/json'}
        
        result = self._make_sync_request(url, headers=headers)
        
        response_data = {
            'source': source_name,
            'domain': domain,
            'query_type': query_type,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'records': []
        }
        
        if result and isinstance(result, list):
            for record in result:
                if isinstance(record, dict):
                    rdata = record.get('rdata')
                    if rdata:
                        pdns_record = {
                            'domain': domain,
                            'query_type': query_type,
                            'rdata': rdata,
                            'first_seen': record.get('time_first'),
                            'last_seen': record.get('time_last'),
                            'count': record.get('count', 1),
                            'rrname': record.get('rrname'),
                            'rrtype': record.get('rrtype'),
                            'source': source_name
                        }
                        response_data['records'].append(pdns_record)
        
        # 保存到缓存
        self._save_to_cache(query_hash, domain, query_type, source_name, params, response_data)
        
        return response_data
    
    def query_virustotal_pdns(self, domain: str, query_type: str = 'A', 
                             api_key: Optional[str] = None) -> Dict[str, Any]:
        """
        查询VirusTotal被动DNS（需要API密钥）
        
        Args:
            domain: 要查询的域名
            query_type: 查询类型
            api_key: VirusTotal API密钥
            
        Returns:
            查询结果字典
        """
        source_name = 'virus_total'
        
        # 检查API密钥
        if not api_key:
            logger.warning("VirusTotal API密钥未提供，跳过查询")
            return {
                'source': source_name,
                'domain': domain,
                'query_type': query_type,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'records': [],
                'error': 'API密钥未配置'
            }
        
        params = {'limit': 100}

        # 对于 IP 地址，VirusTotal 使用不同的 API 路径（ip_addresses）。先检测是否为 IP。
        try:
            ipaddress.ip_address(domain)
            vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{domain}/resolutions"
        except ValueError:
            vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions"

        query_hash = self._get_query_hash(domain, query_type, source_name, {'vt_url': vt_url})
        
        # 检查缓存
        cached = self._get_cached_result(query_hash)
        if cached:
            return cached
        
        # VirusTotal PDNS API
        url = vt_url
        headers = {
            'x-apikey': api_key,
            'Accept': 'application/json'
        }
        
        result = self._make_sync_request(url, headers=headers)
        
        response_data = {
            'source': source_name,
            'domain': domain,
            'query_type': query_type,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'records': []
        }
        
        if result and isinstance(result, dict):
            data = result.get('data', [])
            for item in data:
                if isinstance(item, dict):
                    attributes = item.get('attributes', {})
                    ip_address = attributes.get('ip_address')
                    if ip_address:
                        pdns_record = {
                            'domain': domain,
                            'query_type': 'A',
                            'rdata': ip_address,
                            'last_resolved': attributes.get('date'),
                            'host_name': attributes.get('host_name'),
                            'source': source_name
                        }
                        response_data['records'].append(pdns_record)
        
        # 保存到缓存
        self._save_to_cache(query_hash, domain, query_type, source_name, params, response_data)
        
        return response_data
    
    def query_dnsdb(self, domain: str, query_type: str = 'A', 
                   api_key: Optional[str] = None) -> Dict[str, Any]:
        """
        查询Farsight DNSDB（需要API密钥）
        
        Args:
            domain: 要查询的域名
            query_type: 查询类型
            api_key: DNSDB API密钥
            
        Returns:
            查询结果字典
        """
        source_name = 'dnsdb'
        
        if not api_key:
            logger.warning("DNSDB API密钥未提供，跳过查询")
            return {
                'source': source_name,
                'domain': domain,
                'query_type': query_type,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'records': [],
                'error': 'API密钥未配置'
            }
        
        params = {'limit': 100}
        query_hash = self._get_query_hash(domain, query_type, source_name, params)
        
        # 检查缓存
        cached = self._get_cached_result(query_hash)
        if cached:
            return cached
        
        # DNSDB API（简化版，实际实现需要更复杂的处理）
        url = f"https://api.dnsdb.info/lookup/rrset/name/{domain}/{query_type}"
        headers = {
            'X-API-Key': api_key,
            'Accept': 'application/json'
        }
        
        # 注意：DNSDB返回的是文本行，不是JSON
        response_data = {
            'source': source_name,
            'domain': domain,
            'query_type': query_type,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'records': [],
            'note': 'DNSDB API需要特殊处理，此处为简化实现'
        }
        
        # 这里可以添加实际的DNSDB API调用逻辑
        
        # 保存到缓存
        self._save_to_cache(query_hash, domain, query_type, source_name, params, response_data)
        
        return response_data
    
    def save_records_to_db(self, records: List[Dict]) -> int:
        """
        保存被动DNS记录到数据库
        
        Args:
            records: 被动DNS记录列表
            
        Returns:
            保存的记录数量
        """
        saved_count = 0
        
        for record_data in records:
            try:
                # 检查记录是否已存在
                existing = self.session.query(PassiveDNSRecord).filter_by(
                    domain=record_data.get('domain'),
                    rdata=record_data.get('rdata'),
                    source=record_data.get('source')
                ).first()
                
                if existing:
                    # 更新现有记录
                    existing.last_seen = record_data.get('last_seen') or datetime.now(timezone.utc)
                    existing.count = max(existing.count, record_data.get('count', 1))
                    if record_data.get('metadata'):
                        existing.metadata = record_data.get('metadata')
                    saved_count += 1
                else:
                    # 创建新记录
                    first_seen = record_data.get('first_seen')
                    if isinstance(first_seen, str):
                        try:
                            first_seen = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
                        except:
                            first_seen = datetime.now(timezone.utc)
                    elif not isinstance(first_seen, datetime):
                        first_seen = datetime.now(timezone.utc)
                    
                    last_seen = record_data.get('last_seen')
                    if isinstance(last_seen, str):
                        try:
                            last_seen = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                        except:
                            last_seen = datetime.now(timezone.utc)
                    elif not isinstance(last_seen, datetime):
                        last_seen = datetime.now(timezone.utc)
                    
                    # 提取IPv4/IPv6地址
                    rdata = record_data.get('rdata', '')
                    rdata_ipv4 = None
                    rdata_ipv6 = None
                    rdata_domain = None
                    
                    import ipaddress
                    try:
                        ip = ipaddress.ip_address(rdata)
                        if isinstance(ip, ipaddress.IPv4Address):
                            rdata_ipv4 = rdata
                        elif isinstance(ip, ipaddress.IPv6Address):
                            rdata_ipv6 = rdata
                    except:
                        # 不是IP地址，可能是域名
                        if '.' in rdata or rdata.endswith('.local'):
                            rdata_domain = rdata
                    
                    record = PassiveDNSRecord(
                        domain=record_data.get('domain', ''),
                        query_type=record_data.get('query_type', 'A'),
                        rdata=rdata,
                        rdata_ipv4=rdata_ipv4,
                        rdata_ipv6=rdata_ipv6,
                        rdata_domain=rdata_domain,
                        source=record_data.get('source', 'unknown'),
                        source_id=record_data.get('source_id'),
                        source_url=record_data.get('source_url'),
                        first_seen=first_seen,
                        last_seen=last_seen,
                        count=record_data.get('count', 1),
                        ttl=record_data.get('ttl'),
                        bailiwick=record_data.get('bailiwick'),
                        rrtype=record_data.get('rrtype') or record_data.get('query_type', 'A'),
                        metadata=record_data.get('metadata'),
                        tags=record_data.get('tags', [])
                    )
                    
                    self.session.add(record)
                    saved_count += 1
                    
            except Exception as e:
                logger.debug(f"保存被动DNS记录时出错: {e}")
                continue
        
        try:
            self.session.commit()
            logger.info(f"保存了 {saved_count} 条被动DNS记录到数据库")
        except Exception as e:
            self.session.rollback()
            logger.error(f"提交被动DNS记录时出错: {e}")
            saved_count = 0
        
        return saved_count
    
    def query_domain(self, domain: str, query_type: str = 'A', 
                    sources: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        查询域名的被动DNS记录（整合多个数据源）
        
        Args:
            domain: 要查询的域名
            query_type: 查询类型
            sources: 要查询的数据源列表，None表示使用所有已启用的数据源
            
        Returns:
            整合后的查询结果
        """
        start_time = time.time()
        
        if sources is None:
            # 获取所有已启用的数据源
            enabled_sources = self.session.query(PassiveDNSSource).filter_by(is_enabled=True).all()
            sources = [source.name for source in enabled_sources]
        
        results = {
            'domain': domain,
            'query_type': query_type,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'sources_queried': [],
            'total_records': 0,
            'records': [],
            'source_results': {}
        }
        
        all_records = []
        
        for source_name in sources:
            try:
                source_result = None
                
                if source_name == 'circl':
                    source_result = self.query_circl_pdns(domain, query_type)
                elif source_name == 'virus_total':
                    # 需要从数据库获取API密钥
                    source_config = self.session.query(PassiveDNSSource).filter_by(name=source_name).first()
                    api_key = source_config.api_key if source_config else None
                    source_result = self.query_virustotal_pdns(domain, query_type, api_key)
                elif source_name == 'dnsdb':
                    # 需要从数据库获取API密钥
                    source_config = self.session.query(PassiveDNSSource).filter_by(name=source_name).first()
                    api_key = source_config.api_key if source_config else None
                    source_result = self.query_dnsdb(domain, query_type, api_key)
                else:
                    logger.warning(f"未知的数据源: {source_name}")
                    continue
                
                if source_result:
                    results['sources_queried'].append(source_name)
                    results['source_results'][source_name] = source_result
                    
                    records = source_result.get('records', [])
                    all_records.extend(records)
                    
                    # 更新数据源状态
                    source_config = self.session.query(PassiveDNSSource).filter_by(name=source_name).first()
                    if source_config:
                        source_config.last_successful_query = datetime.now(timezone.utc)
                        source_config.total_queries += 1
                
            except Exception as e:
                logger.error(f"查询数据源 {source_name} 时出错: {e}")
                # 更新数据源错误状态
                source_config = self.session.query(PassiveDNSSource).filter_by(name=source_name).first()
                if source_config:
                    source_config.failed_queries += 1
                    source_config.last_error = str(e)
        
        # 使用聚合器跨源去重与指标计算
        aggregator = PassiveDNSAggregator()
        aggregated = aggregator.merge_source_results(
            results['source_results'],
            domain=domain,
            query_type=query_type
        )

        results['records'] = aggregated.get('records', [])
        results['total_records'] = aggregated.get('total_records', 0)
        results['indicators'] = aggregated.get('indicators', {})
        results['query_duration_seconds'] = round(time.time() - start_time, 2)
        
        # 保存到数据库
        if results['records']:
            saved_count = self.save_records_to_db(results['records'])
            results['saved_to_db_count'] = saved_count
        
        try:
            self.session.commit()
        except:
            self.session.rollback()
        
        return results
    
    def get_domain_resolution_history(self, domain: str, 
                                     lookback_days: int = 30) -> Dict[str, Any]:
        """
        获取域名的解析历史记录（从数据库）
        
        Args:
            domain: 域名
            lookback_days: 回溯天数
            
        Returns:
            解析历史记录
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=lookback_days)
        
        try:
            records = self.session.query(PassiveDNSRecord).filter(
                PassiveDNSRecord.domain == domain,
                PassiveDNSRecord.last_seen >= cutoff_date
            ).order_by(PassiveDNSRecord.last_seen.desc()).all()
            
            # 按IP地址分组
            ip_groups = {}
            for record in records:
                rdata = record.rdata
                if rdata not in ip_groups:
                    ip_groups[rdata] = {
                        'ip_address': rdata,
                        'first_seen': record.first_seen,
                        'last_seen': record.last_seen,
                        'count': record.count,
                        'sources': set(),
                        'records': []
                    }
                
                ip_groups[rdata]['sources'].add(record.source)
                ip_groups[rdata]['records'].append({
                    'source': record.source,
                    'first_seen': record.first_seen,
                    'last_seen': record.last_seen,
                    'count': record.count
                })
            
            # 转换格式
            history = {
                'domain': domain,
                'lookback_days': lookback_days,
                'total_records': len(records),
                'unique_ips': len(ip_groups),
                'ip_resolution_history': []
            }
            
            for ip_data in ip_groups.values():
                history['ip_resolution_history'].append({
                    'ip_address': ip_data['ip_address'],
                    'first_seen': ip_data['first_seen'].isoformat() if ip_data['first_seen'] else None,
                    'last_seen': ip_data['last_seen'].isoformat() if ip_data['last_seen'] else None,
                    'total_count': ip_data['count'],
                    'sources': list(ip_data['sources']),
                    'record_count': len(ip_data['records'])
                })
            
            return history
            
        except Exception as e:
            logger.error(f"获取域名解析历史时出错: {e}")
            return {
                'domain': domain,
                'lookback_days': lookback_days,
                'error': str(e),
                'total_records': 0,
                'unique_ips': 0,
                'ip_resolution_history': []
            }
    
    def close(self):
        """关闭收集器，清理资源"""
        if self.aiohttp_session:
            asyncio.run(self.aiohttp_session.close())


# 单例实例管理器
_collector_instance = None

def get_passive_dns_collector(session: Optional[Session] = None) -> PassiveDNSCollector:
    """
    获取被动DNS收集器单例实例
    
    Args:
        session: 可选的数据库会话
        
    Returns:
        PassiveDNSCollector实例
    """
    global _collector_instance
    
    if _collector_instance is None:
        if session is None:
            # 需要创建数据库会话
            from modules.database.connection import DatabaseSession
            session = DatabaseSession()
        
        _collector_instance = PassiveDNSCollector(session)
    
    return _collector_instance


if __name__ == "__main__":
    """命令行测试"""
    import sys
    
    if len(sys.argv) < 2:
        print("使用方法: python collector.py <域名> [查询类型]")
        sys.exit(1)
    
    domain = sys.argv[1]
    query_type = sys.argv[2] if len(sys.argv) > 2 else 'A'
    
    from modules.database.connection import DatabaseSession
    
    with DatabaseSession() as session:
        collector = PassiveDNSCollector(session)
        
        print(f"查询域名: {domain} (类型: {query_type})")
        print("-" * 50)
        
        # 查询被动DNS记录
        result = collector.query_domain(domain, query_type, sources=['circl'])
        
        print(f"查询完成，耗时: {result.get('query_duration_seconds', 0)}秒")
        print(f"数据源: {', '.join(result.get('sources_queried', []))}")
        print(f"总记录数: {result.get('total_records', 0)}")
        print(f"保存到数据库: {result.get('saved_to_db_count', 0)}条")
        
        # 显示前5条记录
        records = result.get('records', [])[:5]
        if records:
            print("\n前5条记录:")
            for i, record in enumerate(records, 1):
                print(f"  {i}. {record.get('rdata')} (首次出现: {record.get('first_seen')}, "
                      f"最后出现: {record.get('last_seen')}, 次数: {record.get('count', 1)})")
        
        # 获取解析历史
        print("\n解析历史 (最近30天):")
        history = collector.get_domain_resolution_history(domain, lookback_days=30)
        if history.get('ip_resolution_history'):
            for ip_info in history['ip_resolution_history'][:5]:
                print(f"  IP: {ip_info['ip_address']}, "
                      f"首次: {ip_info['first_seen']}, "
                      f"最后: {ip_info['last_seen']}, "
                      f"来源: {', '.join(ip_info['sources'])}")
        
        collector.close()
