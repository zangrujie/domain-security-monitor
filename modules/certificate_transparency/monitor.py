#!/usr/bin/env python3
"""
证书透明度监控器 - 实时监控和查询证书透明度日志
"""

import asyncio
import hashlib
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlencode

import aiohttp
import certstream
import requests
import ipaddress
import socket
from sqlalchemy.orm import Session

from .models import (
    CertificateRecord, CertificateDomainMapping, CTLogSource, 
    CertStreamSubscription, DEFAULT_CT_LOG_SOURCES
)

logger = logging.getLogger(__name__)


class CertificateTransparencyMonitor:
    """
    证书透明度监控器
    支持实时监控（CertStream）和历史查询（crt.sh API）
    """
    
    def __init__(
        self,
        session: Session,
        ct_sources_config: Optional[Dict[str, Any]] = None,
        enable_certstream: bool = True,
        enable_crtsh: bool = True
    ):
        """
        初始化证书透明度监控器
        
        Args:
            session: SQLAlchemy数据库会话
            ct_sources_config: CT日志源配置
            enable_certstream: 是否启用CertStream实时监控
            enable_crtsh: 是否启用crt.sh历史查询
        """
        self.session = session
        self.ct_sources_config = ct_sources_config or DEFAULT_CT_LOG_SOURCES
        self.enable_certstream = enable_certstream
        self.enable_crtsh = enable_crtsh
        
        # 初始化CT日志源
        self._init_ct_sources()
        
        # CertStream相关
        self.certstream_tasks = {}
        self.is_running = False
        
        # 创建aiohttp会话
        self.aiohttp_session = None
        
        logger.info(f"证书透明度监控器初始化完成，已配置 {len(self.ct_sources_config)} 个CT日志源")
    
    def _init_ct_sources(self):
        """初始化CT日志源配置到数据库"""
        for source_name, source_config in self.ct_sources_config.items():
            existing = self.session.query(CTLogSource).filter_by(name=source_name).first()
            if not existing:
                source = CTLogSource(
                    name=source_name,
                    display_name=source_config.get('display_name', source_name),
                    log_url=source_config.get('log_url', ''),
                    log_operator=source_config.get('log_operator', ''),
                    log_type=source_config.get('log_type', 'production'),
                    is_active=source_config.get('is_active', True)
                )
                self.session.add(source)
        
        try:
            self.session.commit()
        except Exception as e:
            self.session.rollback()
            logger.warning(f"初始化CT日志源配置时出错: {e}")
    
    def _extract_domains_from_cert(self, cert_data: Dict) -> List[str]:
        """从证书数据中提取所有域名（CN和SAN）"""
        domains = set()
        
        # 提取Common Name
        common_name = cert_data.get('common_name')
        if common_name:
            domains.add(common_name)
        
        # 提取Subject Alternative Names
        sans = cert_data.get('subject_alternative_names', [])
        if sans:
            if isinstance(sans, list):
                domains.update(sans)
            elif isinstance(sans, str):
                # 处理逗号分隔的字符串
                domains.update([s.strip() for s in sans.split(',')])
        
        return list(domains)
    
    def _process_certificate_data(self, cert_data: Dict, source: str = 'crt.sh') -> Optional[CertificateRecord]:
        """处理证书数据并创建CertificateRecord对象"""
        try:
            # 提取证书指纹作为唯一标识
            cert_id = cert_data.get('sha256_fingerprint') or cert_data.get('id')
            if not cert_id:
                # 生成SHA-256哈希作为备用ID
                cert_json = json.dumps(cert_data, sort_keys=True)
                cert_id = hashlib.sha256(cert_json.encode()).hexdigest()
            
            # 检查证书是否已存在
            existing = self.session.query(CertificateRecord).filter_by(
                certificate_id=cert_id
            ).first()
            
            if existing:
                logger.debug(f"证书已存在: {cert_id}")
                return existing
            
            # 解析时间字段
            not_before = cert_data.get('not_before')
            not_after = cert_data.get('not_after')
            logged_at = cert_data.get('logged_at') or datetime.now(timezone.utc)
            
            if isinstance(not_before, str):
                try:
                    not_before = datetime.fromisoformat(not_before.replace('Z', '+00:00'))
                except:
                    not_before = None
            
            if isinstance(not_after, str):
                try:
                    not_after = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
                except:
                    not_after = None
            
            if isinstance(logged_at, str):
                try:
                    logged_at = datetime.fromisoformat(logged_at.replace('Z', '+00:00'))
                except:
                    logged_at = datetime.now(timezone.utc)
            
            # 检查证书是否过期
            is_expired = False
            if not_after:
                is_expired = not_after < datetime.now(timezone.utc)
            
            # 检查是否是通配符证书
            common_name = cert_data.get('common_name', '')
            is_wildcard = common_name.startswith('*.')
            
            # 检查是否是自签名证书
            issuer_cn = cert_data.get('issuer_common_name', '')
            is_self_signed = common_name == issuer_cn
            
            # 创建证书记录
            record = CertificateRecord(
                certificate_id=cert_id,
                serial_number=cert_data.get('serial_number', ''),
                common_name=common_name,
                subject_alternative_names=cert_data.get('subject_alternative_names', []),
                organization=cert_data.get('organization', ''),
                issuer_common_name=issuer_cn,
                issuer_organization=cert_data.get('issuer_organization', ''),
                certificate_authority=cert_data.get('certificate_authority', ''),
                not_before=not_before,
                not_after=not_after,
                logged_at=logged_at,
                signature_algorithm=cert_data.get('signature_algorithm', ''),
                key_algorithm=cert_data.get('key_algorithm', ''),
                key_size=cert_data.get('key_size'),
                version=cert_data.get('version', 3),
                ct_log_id=cert_data.get('ct_log_id', ''),
                log_entry_index=cert_data.get('log_entry_index'),
                source=source,
                source_url=cert_data.get('source_url', ''),
                raw_data=cert_data,
                is_expired=is_expired,
                is_self_signed=is_self_signed,
                is_wildcard=is_wildcard,
                has_revoked=cert_data.get('has_revoked', False)
            )
            
            return record
            
        except Exception as e:
            logger.error(f"处理证书数据时出错: {e}")
            return None
    
    def query_crtsh(self, domain: str, include_expired: bool = False) -> Dict[str, Any]:
        """
        查询crt.sh API获取域名的证书历史
        
        Args:
            domain: 要查询的域名
            include_expired: 是否包含过期证书
            
        Returns:
            查询结果字典
        """
        # 如果输入是 IP，尝试反向 DNS 获取主机名并用主机名查询 crt.sh
        try:
            ipaddress.ip_address(domain)
            try:
                host, aliases, _ = socket.gethostbyaddr(domain)
                # 优先使用主机名
                query_names = [host] + aliases
            except Exception:
                query_names = []

            if query_names:
                # 将多个名字的查询合并，取第一个有结果的
                for qn in query_names:
                    res = self.query_crtsh(qn, include_expired=include_expired)
                    if res.get('success') and res.get('certificate_count', 0) > 0:
                        return res
                # 如果都没有结果，返回空结果
                return {
                    'success': True,
                    'domain': domain,
                    'certificate_count': 0,
                    'certificates': [],
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
        except ValueError:
            # not an IP
            pass

        try:
            # crt.sh API查询
            url = f"https://crt.sh/json"
            params = {
                'q': domain,
                'output': 'json'
            }
            
            if not include_expired:
                params['exclude'] = 'expired'
            
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code != 200:
                logger.warning(f"crt.sh查询失败: {response.status_code}")
                return {
                    'success': False,
                    'error': f"HTTP {response.status_code}",
                    'certificates': []
                }
            
            certificates = response.json()
            
            # 处理证书数据
            processed_certs = []
            for cert_data in certificates:
                try:
                    cert_record = self._process_certificate_data(cert_data, source='crt.sh')
                    if cert_record:
                        # 保存到数据库
                        try:
                            self.session.add(cert_record)
                            # flush to assign PK (id) so mappings can reference it
                            self.session.flush()
                        except Exception as e:
                            self.session.rollback()
                            logger.debug(f"保存证书记录失败: {e}")
                            continue

                        processed_certs.append(cert_record)

                        # 创建域名映射（使用已分配的 cert_record.id）
                        domains = self._extract_domains_from_cert(cert_data)
                        for domain_name in domains:
                            try:
                                mapping = CertificateDomainMapping(
                                    certificate_id=cert_record.id,
                                    domain_name=domain_name,
                                    is_wildcard=domain_name.startswith('*.') ,
                                    is_common_name=domain_name == cert_record.common_name
                                )
                                self.session.add(mapping)
                            except Exception as e:
                                self.session.rollback()
                                logger.debug(f"添加证书域名映射失败: {e}")
                                # continue with other domains
                                continue
                except Exception as e:
                    logger.debug(f"处理证书时出错: {e}")
                    continue
            
            # 提交到数据库
            self.session.commit()
            
            return {
                'success': True,
                'domain': domain,
                'certificate_count': len(processed_certs),
                'certificates': [cert.to_dict() for cert in processed_certs],
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            self.session.rollback()
            logger.error(f"查询crt.sh时出错: {e}")
            return {
                'success': False,
                'error': str(e),
                'domain': domain,
                'certificates': []
            }
    
    def _certstream_callback(self, message: Dict, context: Any):
        """CertStream消息回调函数"""
        try:
            message_type = message.get('message_type')
            
            if message_type != 'certificate_update':
                return
            
            data = message.get('data', {})
            leaf_cert = data.get('leaf_cert', {})
            
            # 处理证书数据
            cert_record = self._process_certificate_data(leaf_cert, source='certstream')
            if cert_record:
                try:
                    self.session.add(cert_record)
                    self.session.flush()
                except Exception as e:
                    self.session.rollback()
                    logger.error(f"保存CertStream证书记录失败: {e}")
                    return

                # 创建域名映射
                domains = self._extract_domains_from_cert(leaf_cert)
                for domain_name in domains:
                    try:
                        mapping = CertificateDomainMapping(
                            certificate_id=cert_record.id,
                            domain_name=domain_name,
                            is_wildcard=domain_name.startswith('*.') ,
                            is_common_name=domain_name == cert_record.common_name
                        )
                        self.session.add(mapping)
                    except Exception as e:
                        self.session.rollback()
                        logger.error(f"添加CertStream证书域名映射失败: {e}")
                        return

                # 提交到数据库
                try:
                    self.session.commit()
                except Exception as e:
                    self.session.rollback()
                    logger.error(f"提交CertStream证书到数据库失败: {e}")
                    return
                
                # 更新订阅统计
                subscription_id = context.get('subscription_id')
                if subscription_id:
                    subscription = self.session.query(CertStreamSubscription).get(subscription_id)
                    if subscription:
                        subscription.total_certificates += 1
                        subscription.last_message_time = datetime.now(timezone.utc)
                        self.session.commit()
                
                logger.debug(f"从CertStream接收到证书: {cert_record.common_name}")
                
        except Exception as e:
            self.session.rollback()
            logger.error(f"处理CertStream消息时出错: {e}")
    
    async def start_certstream_monitor(self, subscription_name: str = 'default'):
        """
        启动CertStream实时监控
        
        Args:
            subscription_name: 订阅名称
        """
        try:
            # 创建或获取订阅配置
            subscription = self.session.query(CertStreamSubscription).filter_by(
                subscription_name=subscription_name
            ).first()
            
            if not subscription:
                subscription = CertStreamSubscription(
                    subscription_name=subscription_name,
                    is_running=True,
                    last_connection_time=datetime.now(timezone.utc)
                )
                self.session.add(subscription)
                self.session.commit()
            else:
                subscription.is_running = True
                subscription.last_connection_time = datetime.now(timezone.utc)
                self.session.commit()
            
            # 启动CertStream监听
            def callback(message, context):
                context['subscription_id'] = subscription.id
                self._certstream_callback(message, context)
            
            certstream.listen_for_events(
                callback=callback,
                url='wss://certstream.calidog.io/',
                skip_heartbeats=True
            )
            
        except Exception as e:
            logger.error(f"启动CertStream监控时出错: {e}")
            subscription = self.session.query(CertStreamSubscription).filter_by(
                subscription_name=subscription_name
            ).first()
            if subscription:
                subscription.is_running = False
                subscription.last_error = str(e)
                subscription.error_count += 1
                self.session.commit()
    
    def stop_certstream_monitor(self, subscription_name: str = 'default'):
        """停止CertStream监控"""
        # CertStream没有直接的停止方法，但可以通过设置标志来停止
        subscription = self.session.query(CertStreamSubscription).filter_by(
            subscription_name=subscription_name
        ).first()
        
        if subscription:
            subscription.is_running = False
            self.session.commit()
            logger.info(f"CertStream订阅 '{subscription_name}' 已停止")
    
    def get_certificates_by_domain(self, domain: str, lookback_days: int = 30) -> Dict[str, Any]:
        """
        获取指定域名的证书历史
        
        Args:
            domain: 域名
            lookback_days: 回溯天数
            
        Returns:
            证书历史记录
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=lookback_days)
        
        try:
            # 查询证书映射
            mappings = self.session.query(CertificateDomainMapping).filter(
                CertificateDomainMapping.domain_name.ilike(f'%{domain}%'),
                CertificateDomainMapping.discovered_at >= cutoff_date
            ).all()
            
            # 获取相关证书
            certificates = []
            certificate_ids = set()
            
            for mapping in mappings:
                if mapping.certificate_id not in certificate_ids:
                    cert = self.session.query(CertificateRecord).get(mapping.certificate_id)
                    if cert:
                        certificates.append(cert)
                        certificate_ids.add(mapping.certificate_id)
            
            # 分组统计
            stats = {
                'total_certificates': len(certificates),
                'valid_certificates': sum(1 for c in certificates if not c.is_expired and not c.has_revoked),
                'expired_certificates': sum(1 for c in certificates if c.is_expired),
                'self_signed_certificates': sum(1 for c in certificates if c.is_self_signed),
                'wildcard_certificates': sum(1 for c in certificates if c.is_wildcard),
                'unique_issuers': len(set(c.issuer_common_name for c in certificates if c.issuer_common_name))
            }
            
            # 按颁发者分组
            issuer_groups = {}
            for cert in certificates:
                issuer = cert.issuer_common_name or 'Unknown'
                if issuer not in issuer_groups:
                    issuer_groups[issuer] = []
                issuer_groups[issuer].append(cert)
            
            return {
                'success': True,
                'domain': domain,
                'lookback_days': lookback_days,
                'stats': stats,
                'certificate_count': len(certificates),
                'certificates': [cert.to_dict() for cert in certificates[:100]],  # 限制数量
                'issuer_distribution': {
                    issuer: len(certs) for issuer, certs in issuer_groups.items()
                }
            }
            
        except Exception as e:
            logger.error(f"获取域名证书历史时出错: {e}")
            return {
                'success': False,
                'error': str(e),
                'domain': domain,
                'certificates': []
            }
    
    def detect_suspicious_certificates(self, domain: str) -> Dict[str, Any]:
        """
        检测与域名相关的可疑证书
        
        Args:
            domain: 目标域名
            
        Returns:
            可疑证书检测结果
        """
        try:
            # 获取域名所有证书
            result = self.get_certificates_by_domain(domain, lookback_days=90)
            
            if not result.get('success', False):
                return result
            
            certificates = result.get('certificates', [])
            suspicious_certs = []
            alerts = []
            
            # 检测可疑模式
            for cert in certificates:
                cert_alerts = []
                
                # 检查证书颁发者
                issuer = cert.get('issuer_common_name', '')
                if not issuer or issuer == 'Unknown':
                    cert_alerts.append('未知颁发者')
                
                # 检查证书有效期
                not_after = cert.get('not_after')
                if not_after:
                    try:
                        expiry_date = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
                        days_until_expiry = (expiry_date - datetime.now(timezone.utc)).days
                        
                        if days_until_expiry < 0:
                            cert_alerts.append('证书已过期')
                        elif days_until_expiry < 30:
                            cert_alerts.append(f'证书将在{days_until_expiry}天后过期')
                    except:
                        pass
                
                # 检查自签名证书
                if cert.get('is_self_signed', False):
                    cert_alerts.append('自签名证书')
                
                # 检查证书密钥长度
                key_size = cert.get('key_size', 0)
                if key_size and key_size < 2048:
                    cert_alerts.append(f'密钥长度过短({key_size}位)')
                
                # 检查通配符证书用于重要域名
                if cert.get('is_wildcard', False) and 'gov.' in domain or 'bank.' in domain:
                    cert_alerts.append('重要域名使用通配符证书')
                
                if cert_alerts:
                    suspicious_certs.append({
                        'certificate': cert,
                        'alerts': cert_alerts,
                        'severity': 'high' if '自签名证书' in cert_alerts or '证书已过期' in cert_alerts else 'medium'
                    })
                    alerts.extend(cert_alerts)
            
            return {
                'success': True,
                'domain': domain,
                'total_certificates': len(certificates),
                'suspicious_certificates': len(suspicious_certs),
                'alerts': list(set(alerts)),
                'suspicious_certificates_details': suspicious_certs,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"检测可疑证书时出错: {e}")
            return {
                'success': False,
                'error': str(e),
                'domain': domain,
                'suspicious_certificates': 0
            }
    
    def close(self):
        """关闭监控器，清理资源"""
        # 停止所有CertStream监控
        subscriptions = self.session.query(CertStreamSubscription).filter_by(is_running=True).all()
        for subscription in subscriptions:
            subscription.is_running = False
        
        try:
            self.session.commit()
        except:
            self.session.rollback()
        
        if self.aiohttp_session:
            asyncio.run(self.aiohttp_session.close())


# 单例实例管理器
_ct_monitor_instance = None

def get_ct_monitor(session: Optional[Session] = None) -> CertificateTransparencyMonitor:
    """
    获取证书透明度监控器单例实例
    
    Args:
        session: 可选的数据库会话
        
    Returns:
        CertificateTransparencyMonitor实例
    """
    global _ct_monitor_instance
    
    if _ct_monitor_instance is None:
        if session is None:
            # 需要创建数据库会话
            from modules.database.connection import DatabaseSession
            session = DatabaseSession()
        
        _ct_monitor_instance = CertificateTransparencyMonitor(session)
    
    return _ct_monitor_instance


if __name__ == "__main__":
    """命令行测试"""
    import sys
    
    if len(sys.argv) < 2:
        print("使用方法: python monitor.py <域名> [选项]")
        print("选项:")
        print("  --query-crtsh    查询crt.sh历史证书")
        print("  --detect-suspicious  检测可疑证书")
        sys.exit(1)
    
    domain = sys.argv[1]
    action = sys.argv[2] if len(sys.argv) > 2 else '--query-crtsh'
    
    from modules.database.connection import DatabaseSession
    
    with DatabaseSession() as session:
        monitor = CertificateTransparencyMonitor(session)
        
        print(f"证书透明度监控测试 - 域名: {domain}")
        print("-" * 50)
        
        if action == '--query-crtsh':
            print("查询crt.sh证书历史...")
            result = monitor.query_crtsh(domain)
            
            if result.get('success'):
                print(f"查询成功，找到 {result.get('certificate_count', 0)} 个证书")
                
                certs = result.get('certificates', [])
                if certs:
                    print("\n前5个证书:")
                    for i, cert in enumerate(certs[:5], 1):
                        print(f"  {i}. CN: {cert.get('common_name')}")
                        print(f"     颁发者: {cert.get('issuer_common_name')}")
                        print(f"     有效期: {cert.get('not_before')} 到 {cert.get('not_after')}")
                        print(f"     是否过期: {cert.get('is_expired')}")
            else:
                print(f"查询失败: {result.get('error')}")
        
        elif action == '--detect-suspicious':
            print("检测可疑证书...")
            result = monitor.detect_suspicious_certificates(domain)
            
            if result.get('success'):
                suspicious_count = result.get('suspicious_certificates', 0)
                print(f"检测到 {suspicious_count} 个可疑证书")
                
                if suspicious_count > 0:
                    print("\n警报:")
                    for alert in result.get('alerts', []):
                        print(f"  - {alert}")
                    
                    print("\n可疑证书详情:")
                    for cert_info in result.get('suspicious_certificates_details', [])[:3]:
                        cert = cert_info['certificate']
                        print(f"  CN: {cert.get('common_name')}")
                        print(f"    警报: {', '.join(cert_info['alerts'])}")
                        print(f"    严重程度: {cert_info['severity']}")
        
        monitor.close()