#!/usr/bin/env python3
"""
数据模式定义 - 统一各模块的数据格式
"""

from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
import json

@dataclass
class DomainInfo:
    """域名基础信息"""
    domain: str
    original_target: str = ""
    punycode: str = ""
    visual_similarity: float = 0.0
    generation_method: str = ""
    first_seen: str = ""
    last_updated: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class DNSResult:
    """DNS解析结果（来自xdig）"""
    domain: str
    has_dns_record: bool = False
    resolved_ips: List[str] = field(default_factory=list)
    response_time_ms: float = 0.0
    dns_server: str = ""
    timestamp: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class HTTPResult:
    """HTTP扫描结果（来自http_scanner）"""
    domain: str
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    preferred_protocol: str = ""
    final_url: str = ""
    redirect_count: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    ssl_certificate: Optional[Dict] = None
    page_analysis: Dict[str, Any] = field(default_factory=dict)
    http_risk_score: float = 0.0
    risk_level: str = "unknown"
    timestamp: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class WhoisResult:
    """WHOIS查询结果（来自whois_enhanced）"""
    domain: str
    registrar: str = ""
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    registrant: Dict[str, Any] = field(default_factory=dict)
    admin: Dict[str, Any] = field(default_factory=dict)
    tech: Dict[str, Any] = field(default_factory=dict)
    raw_text: str = ""
    whois_risk_score: float = 0.0
    risk_level: str = "unknown"
    timestamp: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class ThreatIntelligenceResult:
    """威胁情报结果（来自threat_intelligence）"""
    domain: str
    threat_sources_checked: List[str] = field(default_factory=list)
    threat_results: Dict[str, Any] = field(default_factory=dict)
    threat_risk_score: float = 0.0
    risk_level: str = "unknown"
    timestamp: str = ""
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class ComprehensiveRiskScore:
    """综合风险评估结果"""
    domain: str
    # 各维度风险评分（原始分数）
    visual_similarity_score: float = 0.0  # 25%权重（临时）
    whois_risk_score: float = 0.0         # 20%权重（临时）
    http_risk_score: float = 0.0          # 35%权重（临时）
    threat_risk_score: float = 0.0        # 20%权重（临时）
    dns_risk_score: float = 0.0           # 0%权重（暂时）
    
    # 加权综合评分
    weighted_total_score: float = 0.0
    
    # 风险等级
    risk_level: str = "unknown"
    
    # 详细分析
    risk_factors: List[str] = field(default_factory=list)
    confidence: float = 0.0  # 置信度 (0-1)
    timestamp: str = ""
    
    def calculate_total_score(self) -> None:
        """计算加权总分"""
        weights = {
            'visual_similarity': 0.25,  # 25%
            'whois': 0.20,              # 20%
            'http': 0.35,               # 35%
            'threat': 0.20,             # 20%
            'dns': 0.00                 # 0%（暂时）
        }
        
        total = (
            self.visual_similarity_score * weights['visual_similarity'] +
            self.whois_risk_score * weights['whois'] +
            self.http_risk_score * weights['http'] +
            self.threat_risk_score * weights['threat'] +
            self.dns_risk_score * weights['dns']
        )
        
        self.weighted_total_score = round(total, 2)
        
        # 确定风险等级
        if self.weighted_total_score >= 20:
            self.risk_level = "critical"
        elif self.weighted_total_score >= 15:
            self.risk_level = "high"
        elif self.weighted_total_score >= 8:
            self.risk_level = "medium"
        elif self.weighted_total_score >= 3:
            self.risk_level = "low"
        else:
            self.risk_level = "info"
    
    def to_dict(self) -> Dict:
        self.calculate_total_score()
        return asdict(self)

@dataclass
class DomainMonitoringResult:
    """域名监控完整结果"""
    domain_info: DomainInfo
    dns_result: Optional[DNSResult] = None
    http_result: Optional[HTTPResult] = None
    whois_result: Optional[WhoisResult] = None
    threat_intel_result: Optional[ThreatIntelligenceResult] = None
    risk_assessment: Optional[ComprehensiveRiskScore] = None
    
    def to_dict(self) -> Dict:
        return {
            'domain_info': self.domain_info.to_dict() if self.domain_info else None,
            'dns_result': self.dns_result.to_dict() if self.dns_result else None,
            'http_result': self.http_result.to_dict() if self.http_result else None,
            'whois_result': self.whois_result.to_dict() if self.whois_result else None,
            'threat_intel_result': self.threat_intel_result.to_dict() if self.threat_intel_result else None,
            'risk_assessment': self.risk_assessment.to_dict() if self.risk_assessment else None,
            'timestamp': datetime.now().isoformat()
        }

# 工具函数
def create_domain_info_from_main_go(domain: str, original: str, similarity: float, method: str) -> DomainInfo:
    """从main.go的输出创建DomainInfo"""
    return DomainInfo(
        domain=domain,
        original_target=original,
        visual_similarity=similarity,
        generation_method=method,
        first_seen=datetime.now().isoformat(),
        last_updated=datetime.now().isoformat()
    )

def create_http_result_from_scanner(scan_result: Dict) -> HTTPResult:
    """从http_scanner的输出创建HTTPResult"""
    http_results = scan_result.get('http_results', {})
    preferred = http_results.get('preferred')
    
    preferred_result = None
    if preferred and preferred != 'none':
        preferred_result = http_results.get(preferred, {})
    
    return HTTPResult(
        domain=scan_result['domain'],
        http_status=http_results.get('http', {}).get('status'),
        https_status=http_results.get('https', {}).get('status'),
        preferred_protocol=preferred if preferred != 'none' else '',
        final_url=preferred_result.get('final_url', '') if preferred_result else '',
        redirect_count=preferred_result.get('redirect_count', 0) if preferred_result else 0,
        headers=preferred_result.get('headers', {}) if preferred_result else {},
        ssl_certificate=preferred_result.get('ssl_certificate') if preferred_result else None,
        page_analysis=preferred_result.get('page_analysis', {}) if preferred_result else {},
        http_risk_score=scan_result.get('http_risk_score', 0.0),
        risk_level=scan_result.get('risk_level', 'unknown'),
        timestamp=scan_result.get('scan_timestamp', datetime.now().isoformat())
    )

def create_whois_result_from_enhanced(whois_result: Dict) -> WhoisResult:
    """从whois_enhanced的输出创建WhoisResult"""
    whois_info = whois_result.get('whois_info', {})
    
    return WhoisResult(
        domain=whois_result['domain'],
        registrar=whois_info.get('registrar', ''),
        creation_date=whois_info.get('creation_date'),
        expiration_date=whois_info.get('expiration_date'),
        updated_date=whois_info.get('updated_date'),
        name_servers=whois_info.get('name_servers', []),
        status=whois_info.get('status', []),
        emails=whois_info.get('emails', []),
        registrant=whois_info.get('registrant', {}),
        admin=whois_info.get('admin', {}),
        tech=whois_info.get('tech', {}),
        raw_text=whois_info.get('raw_text', ''),
        whois_risk_score=whois_result.get('whois_risk_score', 0.0),
        risk_level=whois_result.get('risk_level', 'unknown'),
        timestamp=whois_result.get('query_timestamp', datetime.now().isoformat())
    )

def create_threat_intel_result_from_scanner(intel_result: Dict) -> ThreatIntelligenceResult:
    """从threat_intelligence的输出创建ThreatIntelligenceResult"""
    return ThreatIntelligenceResult(
        domain=intel_result['domain'],
        threat_sources_checked=intel_result.get('threat_sources_checked', []),
        threat_results=intel_result.get('threat_results', {}),
        threat_risk_score=intel_result.get('threat_risk_score', 0.0),
        risk_level=intel_result.get('risk_level', 'unknown'),
        timestamp=intel_result.get('check_timestamp', datetime.now().isoformat())
    )

def create_comprehensive_risk_assessment(
    domain: str,
    visual_similarity_score: float,
    whois_risk_score: float,
    http_risk_score: float,
    threat_risk_score: float,
    dns_risk_score: float = 0.0
) -> ComprehensiveRiskScore:
    """创建综合风险评估"""
    risk = ComprehensiveRiskScore(
        domain=domain,
        visual_similarity_score=visual_similarity_score,
        whois_risk_score=whois_risk_score,
        http_risk_score=http_risk_score,
        threat_risk_score=threat_risk_score,
        dns_risk_score=dns_risk_score,
        timestamp=datetime.now().isoformat()
    )
    
    # 收集风险因素
    risk_factors = []
    if visual_similarity_score > 15:
        risk_factors.append(f"高视觉相似度: {visual_similarity_score}")
    if whois_risk_score > 10:
        risk_factors.append(f"WHOIS异常: {whois_risk_score}")
    if http_risk_score > 20:
        risk_factors.append(f"HTTP风险: {http_risk_score}")
    if threat_risk_score > 15:
        risk_factors.append(f"威胁情报风险: {threat_risk_score}")
    
    risk.risk_factors = risk_factors
    risk.calculate_total_score()
    
    return risk

def save_results_to_json(results: List[DomainMonitoringResult], output_file: str) -> None:
    """保存结果到JSON文件"""
    data = [result.to_dict() for result in results]
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_results_from_json(input_file: str) -> List[Dict]:
    """从JSON文件加载结果"""
    with open(input_file, 'r', encoding='utf-8') as f:
        return json.load(f)