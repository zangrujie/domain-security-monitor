#!/usr/bin/env python3
"""
数据访问层(DAO) - 提供数据库操作接口
"""

import logging
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session, Query
from sqlalchemy import or_, and_, desc, func
import subprocess
import sys

from .models import (
    Domain, DNSScan, HTTPScan, WhoisRecord, 
    ThreatIntelligence, RiskAssessment, WebScreenshot
)
from .connection import DatabaseSession

logger = logging.getLogger(__name__)

class DomainDAO:
    """域名数据访问对象"""
    
    @staticmethod
    def get_or_create_domain(session: Session, domain: str, **kwargs) -> Domain:
        """
        获取或创建域名记录
        
        Args:
            session: 数据库会话
            domain: 域名
            **kwargs: 其他域名属性
            
        Returns:
            Domain: 域名对象
        """
        # 查找现有域名
        domain_obj = session.query(Domain).filter(Domain.domain == domain).first()
        
        if not domain_obj:
            # 创建新域名记录
            domain_obj = Domain(domain=domain, **kwargs)
            session.add(domain_obj)
            session.flush()  # 获取ID
            logger.info(f"创建域名记录: {domain}")
        else:
            # 更新现有记录
            for key, value in kwargs.items():
                if hasattr(domain_obj, key):
                    setattr(domain_obj, key, value)
            domain_obj.last_updated = datetime.utcnow()
            logger.debug(f"更新域名记录: {domain}")
        
        return domain_obj
    
    @staticmethod
    def get_domain_by_id(session: Session, domain_id: int) -> Optional[Domain]:
        """根据ID获取域名"""
        return session.query(Domain).filter(Domain.id == domain_id).first()
    
    @staticmethod
    def get_domain_by_name(session: Session, domain: str) -> Optional[Domain]:
        """根据域名获取域名记录"""
        return session.query(Domain).filter(Domain.domain == domain).first()
    
    @staticmethod
    def get_domains_by_target(session: Session, target: str) -> List[Domain]:
        """根据原始目标获取域名列表"""
        return session.query(Domain).filter(Domain.original_target == target).all()
    
    @staticmethod
    def get_recent_domains(session: Session, days: int = 7) -> List[Domain]:
        """获取最近几天的域名"""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        return session.query(Domain).filter(
            Domain.first_seen >= cutoff_date
        ).order_by(desc(Domain.first_seen)).all()
    
    @staticmethod
    def delete_domain(session: Session, domain_id: int) -> bool:
        """删除域名及其相关记录"""
        domain = DomainDAO.get_domain_by_id(session, domain_id)
        if domain:
            session.delete(domain)
            logger.info(f"删除域名记录: {domain.domain}")
            return True
        return False

class ScanDAO:
    """扫描结果数据访问对象"""
    
    @staticmethod
    def save_dns_scan(session: Session, domain_id: int, scan_data: Dict) -> DNSScan:
        """
        保存DNS扫描结果
        
        Args:
            session: 数据库会话
            domain_id: 域名ID
            scan_data: 扫描数据
            
        Returns:
            DNSScan: DNS扫描对象
        """
        dns_scan = DNSScan(
            domain_id=domain_id,
            has_dns_record=scan_data.get('has_dns_record', False),
            resolved_ips=scan_data.get('resolved_ips', []),
            response_time_ms=scan_data.get('response_time_ms', 0.0),
            dns_server=scan_data.get('dns_server', ''),
            scan_timestamp=datetime.utcnow()
        )
        session.add(dns_scan)
        logger.debug(f"保存DNS扫描结果: 域名ID={domain_id}")
        return dns_scan
    
    @staticmethod
    def save_http_scan(session: Session, domain_id: int, http_data: Dict) -> HTTPScan:
        """
        保存HTTP扫描结果
        
        Args:
            session: 数据库会话
            domain_id: 域名ID
            http_data: HTTP扫描数据
            
        Returns:
            HTTPScan: HTTP扫描对象
        """
        http_scan = HTTPScan(
            domain_id=domain_id,
            http_status=http_data.get('http_status'),
            https_status=http_data.get('https_status'),
            preferred_protocol=http_data.get('preferred_protocol', ''),
            final_url=http_data.get('final_url', ''),
            redirect_count=http_data.get('redirect_count', 0),
            headers=http_data.get('headers', {}),
            ssl_certificate=http_data.get('ssl_certificate'),
            page_analysis=http_data.get('page_analysis', {}),
            http_risk_score=http_data.get('http_risk_score', 0.0),
            risk_level=http_data.get('risk_level', 'unknown'),
            scan_timestamp=datetime.utcnow()
        )
        session.add(http_scan)
        logger.debug(f"保存HTTP扫描结果: 域名ID={domain_id}")
        return http_scan
    
    @staticmethod
    def get_latest_dns_scan(session: Session, domain_id: int) -> Optional[DNSScan]:
        """获取最新的DNS扫描结果"""
        return session.query(DNSScan).filter(
            DNSScan.domain_id == domain_id
        ).order_by(desc(DNSScan.scan_timestamp)).first()
    
    @staticmethod
    def get_latest_http_scan(session: Session, domain_id: int) -> Optional[HTTPScan]:
        """获取最新的HTTP扫描结果"""
        return session.query(HTTPScan).filter(
            HTTPScan.domain_id == domain_id
        ).order_by(desc(HTTPScan.scan_timestamp)).first()
    
    @staticmethod
    def get_dns_scans_by_domain(session: Session, domain_id: int, limit: int = 10) -> List[DNSScan]:
        """获取域名的DNS扫描历史"""
        return session.query(DNSScan).filter(
            DNSScan.domain_id == domain_id
        ).order_by(desc(DNSScan.scan_timestamp)).limit(limit).all()
    
    @staticmethod
    def get_http_scans_by_domain(session: Session, domain_id: int, limit: int = 10) -> List[HTTPScan]:
        """获取域名的HTTP扫描历史"""
        return session.query(HTTPScan).filter(
            HTTPScan.domain_id == domain_id
        ).order_by(desc(HTTPScan.scan_timestamp)).limit(limit).all()

    @staticmethod
    def save_web_screenshot(session: Session, screenshot_data: Dict) -> WebScreenshot:
        """
        保存主动探测截图及页面元数据
        """
        row = WebScreenshot(
            domain=screenshot_data.get("domain", ""),
            screenshot_path=screenshot_data.get("screenshot_path", ""),
            perceptual_hash=screenshot_data.get("perceptual_hash"),
            ssim_score=screenshot_data.get("ssim_score"),
            page_title=screenshot_data.get("page_title"),
            status_code=screenshot_data.get("status_code"),
            load_ms=screenshot_data.get("load_ms"),
            created_at=datetime.utcnow(),
        )
        session.add(row)
        logger.debug(f"保存主动探测截图: domain={row.domain}, path={row.screenshot_path}")
        return row

class ThreatIntelDAO:
    """威胁情报数据访问对象"""
    
    @staticmethod
    def save_threat_intel(session: Session, domain_id: int, intel_data: Dict) -> ThreatIntelligence:
        """
        保存威胁情报结果
        
        Args:
            session: 数据库会话
            domain_id: 域名ID
            intel_data: 威胁情报数据
            
        Returns:
            ThreatIntelligence: 威胁情报对象
        """
        threat_intel = ThreatIntelligence(
            domain_id=domain_id,
            threat_sources_checked=intel_data.get('threat_sources_checked', []),
            threat_results=intel_data.get('threat_results', {}),
            threat_risk_score=intel_data.get('threat_risk_score', 0.0),
            risk_level=intel_data.get('risk_level', 'unknown'),
            check_timestamp=datetime.utcnow()
        )
        session.add(threat_intel)
        logger.debug(f"保存威胁情报结果: 域名ID={domain_id}")
        return threat_intel
    
    @staticmethod
    def get_latest_threat_intel(session: Session, domain_id: int) -> Optional[ThreatIntelligence]:
        """获取最新的威胁情报结果"""
        return session.query(ThreatIntelligence).filter(
            ThreatIntelligence.domain_id == domain_id
        ).order_by(desc(ThreatIntelligence.check_timestamp)).first()
    
    @staticmethod
    def get_high_risk_domains(session: Session, min_score: float = 15.0, limit: int = 50) -> List[Dict]:
        """获取高风险域名列表"""
        results = session.query(
            Domain.domain,
            ThreatIntelligence.threat_risk_score,
            ThreatIntelligence.risk_level,
            ThreatIntelligence.check_timestamp
        ).join(
            ThreatIntelligence, Domain.id == ThreatIntelligence.domain_id
        ).filter(
            ThreatIntelligence.threat_risk_score >= min_score
        ).order_by(
            desc(ThreatIntelligence.threat_risk_score)
        ).limit(limit).all()
        
        return [
            {
                'domain': r.domain,
                'threat_risk_score': r.threat_risk_score,
                'risk_level': r.risk_level,
                'check_timestamp': r.check_timestamp
            }
            for r in results
        ]

class RiskDAO:
    """风险评估数据访问对象"""
    
    @staticmethod
    def save_risk_assessment(session: Session, domain_id: int, risk_data: Dict) -> RiskAssessment:
        """
        保存风险评估结果
        
        Args:
            session: 数据库会话
            domain_id: 域名ID
            risk_data: 风险评估数据
            
        Returns:
            RiskAssessment: 风险评估对象
        """
        risk_assessment = RiskAssessment(
            domain_id=domain_id,
            visual_similarity_score=risk_data.get('visual_similarity_score', 0.0),
            whois_risk_score=risk_data.get('whois_risk_score', 0.0),
            http_risk_score=risk_data.get('http_risk_score', 0.0),
            threat_risk_score=risk_data.get('threat_risk_score', 0.0),
            dns_risk_score=risk_data.get('dns_risk_score', 0.0),
            weighted_total_score=risk_data.get('weighted_total_score', 0.0),
            risk_level=risk_data.get('risk_level', 'unknown'),
            risk_factors=risk_data.get('risk_factors', []),
            confidence=risk_data.get('confidence', 0.0),
            assessment_timestamp=datetime.utcnow()
        )
        session.add(risk_assessment)
        logger.debug(f"保存风险评估结果: 域名ID={domain_id}")
        return risk_assessment
    
    @staticmethod
    def get_latest_risk_assessment(session: Session, domain_id: int) -> Optional[RiskAssessment]:
        """获取最新的风险评估结果"""
        return session.query(RiskAssessment).filter(
            RiskAssessment.domain_id == domain_id
        ).order_by(desc(RiskAssessment.assessment_timestamp)).first()
    
    @staticmethod
    def get_high_risk_assessments(session: Session, min_score: float = 15.0, limit: int = 50) -> List[Dict]:
        """获取高风险评估结果"""
        results = session.query(
            Domain.domain,
            RiskAssessment.weighted_total_score,
            RiskAssessment.risk_level,
            RiskAssessment.risk_factors,
            RiskAssessment.assessment_timestamp
        ).join(
            RiskAssessment, Domain.id == RiskAssessment.domain_id
        ).filter(
            RiskAssessment.weighted_total_score >= min_score
        ).order_by(
            desc(RiskAssessment.weighted_total_score)
        ).limit(limit).all()
        
        return [
            {
                'domain': r.domain,
                'weighted_total_score': r.weighted_total_score,
                'risk_level': r.risk_level,
                'risk_factors': r.risk_factors,
                'assessment_timestamp': r.assessment_timestamp
            }
            for r in results
        ]
    
    @staticmethod
    def get_risk_statistics(session: Session, days: int = 30) -> Dict:
        """获取风险评估统计信息"""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # 获取风险评估总数
        total_count = session.query(func.count(RiskAssessment.id)).filter(
            RiskAssessment.assessment_timestamp >= cutoff_date
        ).scalar() or 0
        
        # 按风险等级统计
        risk_level_stats = session.query(
            RiskAssessment.risk_level,
            func.count(RiskAssessment.id)
        ).filter(
            RiskAssessment.assessment_timestamp >= cutoff_date
        ).group_by(RiskAssessment.risk_level).all()
        
        # 高风险域名趋势
        high_risk_trend = session.query(
            func.date(RiskAssessment.assessment_timestamp),
            func.count(RiskAssessment.id)
        ).filter(
            RiskAssessment.assessment_timestamp >= cutoff_date,
            RiskAssessment.risk_level.in_(['high', 'critical'])
        ).group_by(func.date(RiskAssessment.assessment_timestamp)).all()
        
        return {
            'total_assessments': total_count,
            'risk_level_stats': dict(risk_level_stats),
            'high_risk_trend': [
                {'date': str(date), 'count': count}
                for date, count in high_risk_trend
            ]
        }

class WhoisDAO:
    """WHOIS数据访问对象"""
    
    @staticmethod
    def save_whois_record(session: Session, domain_id: int, whois_data: Dict) -> WhoisRecord:
        """
        保存WHOIS记录
        
        Args:
            session: 数据库会话
            domain_id: 域名ID
            whois_data: WHOIS数据
            
        Returns:
            WhoisRecord: WHOIS记录对象
        """
        # 处理日期字段
        def parse_date(date_str):
            if not date_str:
                return None
            if isinstance(date_str, datetime):
                return date_str
            if isinstance(date_str, (list, tuple)):
                for item in date_str:
                    parsed = parse_date(item)
                    if parsed is not None:
                        return parsed
                return None
            try:
                return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            except:
                return None
        
        whois_record = WhoisRecord(
            domain_id=domain_id,
            registrar=whois_data.get('registrar', ''),
            creation_date=parse_date(whois_data.get('creation_date')),
            expiration_date=parse_date(whois_data.get('expiration_date')),
            updated_date=parse_date(whois_data.get('updated_date')),
            name_servers=whois_data.get('name_servers', []),
            status=whois_data.get('status', []),
            emails=whois_data.get('emails', []),
            registrant=whois_data.get('registrant', {}),
            admin=whois_data.get('admin', {}),
            tech=whois_data.get('tech', {}),
            raw_text=whois_data.get('raw_text', ''),
            whois_risk_score=whois_data.get('whois_risk_score', 0.0),
            risk_level=whois_data.get('risk_level', 'unknown'),
            query_timestamp=datetime.utcnow()
        )
        session.add(whois_record)
        logger.debug(f"保存WHOIS记录: 域名ID={domain_id}")
        return whois_record
    
    @staticmethod
    def get_latest_whois_record(session: Session, domain_id: int) -> Optional[WhoisRecord]:
        """获取最新的WHOIS记录"""
        return session.query(WhoisRecord).filter(
            WhoisRecord.domain_id == domain_id
        ).order_by(desc(WhoisRecord.query_timestamp)).first()

# 组合DAO类
class DomainDataManager:
    """域名数据管理器 - 提供完整的数据操作接口"""
    
    def __init__(self):
        self.domain_dao = DomainDAO()
        self.scan_dao = ScanDAO()
        self.threat_intel_dao = ThreatIntelDAO()
        self.risk_dao = RiskDAO()
        self.whois_dao = WhoisDAO()
    
    def save_complete_monitoring_result(self, domain: str, original_target: str, 
                                      monitoring_data: Dict) -> Dict:
        """
        保存完整的监控结果
        
        Args:
            domain: 域名
            original_target: 原始目标域名
            monitoring_data: 监控数据，包含各模块结果
            
        Returns:
            Dict: 保存结果统计
        """
        with DatabaseSession() as session:
            try:
                # 1. 保存域名基本信息
                domain_obj = self.domain_dao.get_or_create_domain(
                    session, domain,
                    original_target=original_target,
                    visual_similarity=monitoring_data.get('visual_similarity', 0.0),
                    generation_method=monitoring_data.get('generation_method', 'unknown')
                )
                
                stats = {'domain_id': domain_obj.id}
                
                # 2. 保存DNS扫描结果（如果有）
                if 'dns_result' in monitoring_data and monitoring_data['dns_result']:
                    self.scan_dao.save_dns_scan(session, domain_obj.id, monitoring_data['dns_result'])
                    stats['dns_scan'] = True
                
                # 3. 保存HTTP扫描结果（如果有）
                if 'http_result' in monitoring_data and monitoring_data['http_result']:
                    http_data = monitoring_data['http_result']
                    if isinstance(http_data, dict):
                        self.scan_dao.save_http_scan(session, domain_obj.id, http_data)
                        stats['http_scan'] = True
                
                # 4. 保存WHOIS记录（如果有）
                if 'whois_result' in monitoring_data and monitoring_data['whois_result']:
                    whois_data = monitoring_data['whois_result']
                    if isinstance(whois_data, dict):
                        self.whois_dao.save_whois_record(session, domain_obj.id, whois_data)
                        stats['whois_record'] = True
                
                # 5. 保存威胁情报（如果有）
                if 'threat_intel_result' in monitoring_data and monitoring_data['threat_intel_result']:
                    threat_data = monitoring_data['threat_intel_result']
                    if isinstance(threat_data, dict):
                        self.threat_intel_dao.save_threat_intel(session, domain_obj.id, threat_data)
                        stats['threat_intel'] = True
                
                # 6. 保存风险评估（如果有）
                if 'risk_assessment' in monitoring_data and monitoring_data['risk_assessment']:
                    risk_data = monitoring_data['risk_assessment']
                    if isinstance(risk_data, dict):
                        self.risk_dao.save_risk_assessment(session, domain_obj.id, risk_data)
                        stats['risk_assessment'] = True
                
                session.commit()
                logger.info(f"完整监控结果已保存: {domain}")

                # 异步触发前端使用的预聚合刷新与缓存失效
                try:
                    # 通过独立 Python 进程调用 web_app 的 manager，避免在当前进程产生循环导入
                    safe_target = (original_target or "").replace("'", "\\'")
                    cmd = (
                        "from web_app import manager; "
                        f"manager.invalidate_analysis_cache('{safe_target}'); "
                        f"manager.refresh_original_target_summary('{safe_target}')"
                    )
                    subprocess.Popen([sys.executable, "-c", cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    logger.debug(f"已异步请求刷新 original_target_summary: {original_target}")
                except Exception as e:
                    logger.warning(f"触发 original_target_summary 刷新失败: {e}")

                return stats
                
            except Exception as e:
                session.rollback()
                logger.error(f"保存监控结果失败 {domain}: {e}")
                raise

    def get_domain_stats(self, days: int = 30) -> Dict:
        """
        获取域名统计信息
        
        Args:
            days: 统计天数
            
        Returns:
            Dict: 统计信息
        """
        with DatabaseSession() as session:
            try:
                # 获取域名总数
                total_count = session.query(func.count(Domain.id)).scalar() or 0
                
                # 获取最近N天的域名数
                cutoff_date = datetime.utcnow() - timedelta(days=days)
                recent_count = session.query(func.count(Domain.id)).filter(
                    Domain.first_seen >= cutoff_date
                ).scalar() or 0
                
                # 获取高风险域名数
                high_risk_count = session.query(func.count(Domain.id)).join(
                    RiskAssessment, Domain.id == RiskAssessment.domain_id
                ).filter(
                    RiskAssessment.risk_level.in_(['high', 'critical'])
                ).scalar() or 0
                
                # 获取中风险域名数
                medium_risk_count = session.query(func.count(Domain.id)).join(
                    RiskAssessment, Domain.id == RiskAssessment.domain_id
                ).filter(
                    RiskAssessment.risk_level == 'medium'
                ).scalar() or 0
                
                # 获取低风险域名数
                low_risk_count = session.query(func.count(Domain.id)).join(
                    RiskAssessment, Domain.id == RiskAssessment.domain_id
                ).filter(
                    RiskAssessment.risk_level == 'low'
                ).scalar() or 0
                
                return {
                    'total_domains': total_count,
                    'recent_domains': recent_count,
                    'high_risk_domains': high_risk_count,
                    'medium_risk_domains': medium_risk_count,
                    'low_risk_domains': low_risk_count,
                    'threats_detected': high_risk_count
                }
            except Exception as e:
                logger.error(f"获取域名统计失败: {e}")
                return {}

    def get_recent_domains(self, limit: int = 10) -> List[Dict]:
        """
        获取最近域名列表
        
        Args:
            limit: 限制数量
            
        Returns:
            List[Dict]: 域名列表
        """
        with DatabaseSession() as session:
            try:
                domains = DomainDAO.get_recent_domains(session, days=7)
                result = []
                
                for domain in domains[:limit]:
                    # 获取最新风险评估
                    risk_assessment = RiskDAO.get_latest_risk_assessment(session, domain.id)
                    
                    domain_info = {
                        'domain': domain.domain,
                        'original_target': domain.original_target,
                        'scan_time': domain.first_seen.strftime("%Y-%m-%d %H:%M:%S") if domain.first_seen else '',
                        'risk_level': risk_assessment.risk_level if risk_assessment else 'unknown',
                        'risk_score': risk_assessment.weighted_total_score if risk_assessment else 0.0,
                        'variant_count': 0  # 需要从其他表计算
                    }
                    result.append(domain_info)
                
                return result
            except Exception as e:
                logger.error(f"获取最近域名失败: {e}")
                return []

    def get_risk_assessment_stats(self, days: int = 30) -> Dict:
        """
        获取风险评估统计信息
        
        Args:
            days: 统计天数
            
        Returns:
            Dict: 风险评估统计
        """
        with DatabaseSession() as session:
            try:
                return RiskDAO.get_risk_statistics(session, days=days)
            except Exception as e:
                logger.error(f"获取风险评估统计失败: {e}")
                return {}

# 全局数据管理器实例
_data_manager: Optional[DomainDataManager] = None

def get_data_manager() -> DomainDataManager:
    """获取全局数据管理器"""
    global _data_manager
    if _data_manager is None:
        _data_manager = DomainDataManager()
    return _data_manager

if __name__ == "__main__":
    # 测试DAO功能
    from .connection import DatabaseConnection
    
    db = DatabaseConnection()
    if db.connect():
        print("✅ 数据库连接成功")
        
        try:
            # 测试创建表
            db.create_tables()
            print("✅ 数据库表创建成功")
            
            # 测试DAO功能
            with DatabaseSession() as session:
                # 测试域名创建
                domain = DomainDAO.get_or_create_domain(
                    session, "test.example.com",
                    original_target="example.com",
                    visual_similarity=0.95,
                    generation_method="test"
                )
                print(f"✅ 域名创建成功: {domain.domain} (ID: {domain.id})")
                
                # 测试DNS扫描保存
                dns_scan = ScanDAO.save_dns_scan(session, domain.id, {
                    'has_dns_record': True,
                    'resolved_ips': ['8.8.8.8', '8.8.4.4'],
                    'response_time_ms': 45.2,
                    'dns_server': '8.8.8.8'
                })
                print(f"✅ DNS扫描保存成功: {dns_scan.id}")
                
                # 测试WHOIS记录保存
                whois_record = WhoisDAO.save_whois_record(session, domain.id, {
                    'registrar': 'Test Registrar',
                    'creation_date': '2023-01-01T00:00:00Z',
                    'whois_risk_score': 5.0,
                    'risk_level': 'low'
                })
                print(f"✅ WHOIS记录保存成功: {whois_record.id}")
                
                session.commit()
                print("✅ 所有测试通过")
                
        except Exception as e:
            print(f"❌ 测试失败: {e}")
        
        finally:
            db.close()
    else:
        print("❌ 数据库连接失败")
