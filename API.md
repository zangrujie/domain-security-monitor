# Domain Security Monitor API 文档

Domain Security Monitor 提供完整的RESTful API接口，支持程序化访问域名安全监控系统的所有功能。

## 概述

API采用标准的RESTful设计，支持JSON格式的请求和响应。所有API端点均以 `/api/` 开头。

### 基础信息
- **API根路径**: `http://localhost:5000/api/`
- **请求格式**: JSON
- **响应格式**: JSON
- **认证**: 当前版本不需要认证（开发环境）
- **速率限制**: 无限制（生产环境建议添加）

### 响应格式
所有API响应都遵循以下格式：

```json
{
  "success": true,
  "data": {...},
  "error": null,
  "message": "操作成功"
}
```

或错误响应：

```json
{
  "success": false,
  "data": null,
  "error": "错误描述",
  "message": "操作失败"
}
```

## API 端点

### 1. 仪表板统计

#### 获取仪表板统计信息
```
GET /api/dashboard/stats
```

**响应示例**:
```json
{
  "success": true,
  "data": {
    "total_domains": 2950,
    "high_risk_domains": 685,
    "medium_risk_domains": 920,
    "low_risk_domains": 1345,
    "recent_scans": 50,
    "threats_detected": 685
  }
}
```

#### 获取最近域名
```
GET /api/dashboard/recent-domains
```

**查询参数**:
- `limit` (可选): 返回数量，默认10

**响应示例**:
```json
{
  "success": true,
  "data": [
    {
      "domain": "xn--beepsek-07a.com",
      "original_target": "deepseek.com",
      "scan_time": "2026-02-09 14:30:25",
      "risk_level": "high",
      "risk_score": 78.5
    }
  ]
}
```

#### 获取风险分布
```
GET /api/dashboard/risk-distribution
```

**响应示例**:
```json
{
  "success": true,
  "data": {
    "high": 685,
    "medium": 920,
    "low": 1345,
    "critical": 1
  }
}
```

### 2. 域名管理

#### 获取域名列表
```
GET /api/domains
```

**查询参数**:
- `page` (可选): 页码，默认1
- `page_size` (可选): 每页数量，默认20
- `search` (可选): 搜索关键词
- `risk_level` (可选): 风险等级筛选 (high/medium/low)

**响应示例**:
```json
{
  "success": true,
  "data": [
    {
      "domain": "xn--beepsek-07a.com",
      "original_target": "deepseek.com",
      "scan_time": "2026-02-09 14:30:25",
      "risk_level": "high",
      "risk_score": 78.5
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total": 2950,
    "total_pages": 148
  }
}
```

#### 获取域名详情
```
GET /api/domains/{domain_name}
```

**路径参数**:
- `domain_name`: 域名名称

**响应示例**:
```json
{
  "success": true,
  "data": {
    "domain_info": {
      "domain": "deepseek.com",
      "original_target": "deepseek.com",
      "scan_time": "2026-02-09 14:30:25",
      "risk_level": "medium",
      "risk_score": 35.2
    },
    "variants": {
      "total": 125,
      "list": ["xn--beepsek-07a.com", "xn--deepsek-6ya.com", ...],
      "high_risk": ["xn--beepsek-07a.com", "xn--deepsek-6ya.com"]
    },
    "scan_results": {
      "http": [{
        "domain": "xn--beepsek-07a.com",
        "status_code": 200,
        "ssl_valid": true,
        "title": "DeepSeek - AI助手"
      }],
      "threat": [{
        "domain": "xn--beepsek-07a.com",
        "virustotal_score": 2,
        "urlhaus_status": "clean"
      }]
    }
  }
}
```

### 3. 扫描管理

#### 启动域名扫描
```
POST /api/scan/start
Content-Type: application/json
```

**请求体**:
```json
{
  "domain": "example.com"
}
```

**响应示例**:
```json
{
  "success": true,
  "message": "已开始扫描域名: example.com",
  "data": {
    "scan_id": "scan_1741771825",
    "domain": "example.com",
    "start_time": "2026-02-09 15:30:25",
    "status": "processing",
    "method": "subprocess",
    "variant_count": 0
  }
}
```

### 4. 数据分析

#### 获取综合分析
```
GET /api/data/analysis
```

**查询参数**:
- `type` (可选): 分析类型，可以是:
  - `comprehensive`: 综合分析（默认）
  - `registration_time`: 注册时间分布
  - `registrar`: 注册商分布
  - `resolution`: 解析结果分析
  - `domain_usage`: 域名用途分析
  - `high_risk_details`: 高风险域名详情

**响应示例** (综合分析):
```json
{
  "success": true,
  "data": {
    "registration_time": {
      "total_with_creation_date": 2950,
      "year_month_distribution": {"2025-01": 150, "2025-02": 180},
      "year_distribution": {"2025": 2700, "2026": 250},
      "monthly_data": [{"year": 2025, "month": 1, "count": 150}],
      "recent_registrations": [{"domain": "example1.com", "creation_date": "2026-02-09"}],
      "analysis": {
        "peak_year": 2025,
        "peak_month": "2025-10",
        "average_per_month": 227,
        "most_active_period": {
          "most_active_month": "2026-01",
          "count_in_peak_month": 320
        }
      }
    },
    "registrar_distribution": {
      "total_domains": 2950,
      "registrar_distribution": [
        {"registrar": "GoDaddy", "domain_count": 850, "percentage": 28.8}
      ],
      "high_risk_registrars": [
        {"registrar": "GoDaddy", "high_risk_count": 165}
      ]
    }
  }
}
```

#### 获取相似域名示例
```
GET /api/data/similar-domains
```

**响应示例**:
```json
{
  "success": true,
  "data": {
    "similar_domains": [{
      "original_domain": "deepseek.com",
      "similar_domains": [
        {"domain": "ďeepseek.com", "similarity_score": 0.98, "visual_similarity": 0.99},
        {"domain": "ḍeepseek.com", "similarity_score": 0.97, "visual_similarity": 0.98}
      ],
      "similarity_type": "visual",
      "risk_level": "high",
      "detection_method": "字形相似度分析"
    }]
  }
}
```

#### 获取注册时间分析
```
GET /api/data/registration-analysis
```

#### 获取注册商分析
```
GET /api/data/registrar-analysis
```

#### 获取域名用途分析
```
GET /api/data/usage-analysis
```

### 5. xdig分析

#### 获取xdig分析
```
GET /api/xdig/analysis
```

**响应示例**:
```json
{
  "success": true,
  "data": {
    "summary": {
      "total_domains": 45,
      "high_risk_domains": 35,
      "detection_method": "xdig_dns_probe",
      "com_variants": 32
    },
    "dangerous_domains": [
      {
        "domain": "dlaw.com",
        "original_target": "claw",
        "scan_time": "2026-02-09 14:30:25",
        "risk_level": "high",
        "risk_score": 85,
        "detection_method": "xdig_dns_probe",
        "status": "active"
      }
    ],
    "domain_examples": ["dlaw.com", "flaw.com", "vlaw.com", "xlaw.com"]
  }
}
```

#### 增强型xdig分析
```
POST /api/xdig/enhanced-analysis
Content-Type: application/json
```

**请求体**:
```json
{
  "domain": "example.com",
  "threshold": 0.98
}
```

#### 统一xdig分析
```
GET /api/xdig/unified-analysis
```

### 6. 系统状态

#### 获取系统状态
```
GET /api/system/status
```

**响应示例**:
```json
{
  "success": true,
  "data": {
    "database": true,
    "api_keys": {
      "virustotal": true,
      "urlhaus": false
    },
    "storage": {
      "domain_variants": true,
      "monitoring_results": true,
      "domain_count": 25
    },
    "project_info": {
      "name": "域名安全监控系统",
      "version": "1.0.0",
      "description": "域名仿冒检测与安全监控平台"
    }
  }
}
```

## API 使用示例

### Python 示例

```python
import requests
import json

class DomainSecurityAPI:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
    
    def get_dashboard_stats(self):
        """获取仪表板统计"""
        response = requests.get(f"{self.base_url}/api/dashboard/stats")
        return response.json()
    
    def get_domains(self, page=1, page_size=20, risk_level=None):
        """获取域名列表"""
        params = {"page": page, "page_size": page_size}
        if risk_level:
            params["risk_level"] = risk_level
        
        response = requests.get(f"{self.base_url}/api/domains", params=params)
        return response.json()
    
    def start_scan(self, domain):
        """启动域名扫描"""
        payload = {"domain": domain}
        response = requests.post(
            f"{self.base_url}/api/scan/start",
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        return response.json()
    
    def get_data_analysis(self, analysis_type="comprehensive"):
        """获取数据分析"""
        params = {"type": analysis_type}
        response = requests.get(f"{self.base_url}/api/data/analysis", params=params)
        return response.json()
    
    def get_system_status(self):
        """获取系统状态"""
        response = requests.get(f"{self.base_url}/api/system/status")
        return response.json()

# 使用示例
api = DomainSecurityAPI()

# 获取统计信息
stats = api.get_dashboard_stats()
print(f"总域名数: {stats['data']['total_domains']}")

# 获取高风险域名
domains = api.get_domains(risk_level="high", page_size=5)
for domain in domains['data']:
    print(f"高风险域名: {domain['domain']} (得分: {domain['risk_score']})")

# 启动扫描
scan_result = api.start_scan("example.com")
print(f"扫描ID: {scan_result['data']['scan_id']}")
```

### Shell 示例 (cURL)

```bash
# 获取仪表板统计
curl -X GET "http://localhost:5000/api/dashboard/stats"

# 获取最近域名
curl -X GET "http://localhost:5000/api/dashboard/recent-domains?limit=5"

# 获取域名列表（分页）
curl -X GET "http://localhost:5000/api/domains?page=1&page_size=10&risk_level=high"

# 启动域名扫描
curl -X POST "http://localhost:5000/api/scan/start" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# 获取系统状态
curl -X GET "http://localhost:5000/api/system/status"
```

### JavaScript 示例

```javascript
class DomainSecurityAPI {
    constructor(baseUrl = 'http://localhost:5000') {
        this.baseUrl = baseUrl;
    }

    async getDashboardStats() {
        const response = await fetch(`${this.baseUrl}/api/dashboard/stats`);
        return await response.json();
    }

    async startScan(domain) {
        const response = await fetch(`${this.baseUrl}/api/scan/start`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ domain }),
        });
        return await response.json();
    }

    async getDomains(options = {}) {
        const { page = 1, pageSize = 20, riskLevel } = options;
        let url = `${this.baseUrl}/api/domains?page=${page}&page_size=${pageSize}`;
        if (riskLevel) url += `&risk_level=${riskLevel}`;
        
        const response = await fetch(url);
        return await response.json();
    }

    async getDataAnalysis(type = 'comprehensive') {
        const response = await fetch(`${this.baseUrl}/api/data/analysis?type=${type}`);
        return await response.json();
    }
}

// 使用示例
async function exampleUsage() {
    const api = new DomainSecurityAPI();
    
    // 获取统计信息
    const stats = await api.getDashboardStats();
    console.log('总域名数:', stats.data.total_domains);
    
    // 获取高风险域名
    const domains = await api.getDomains({ riskLevel: 'high', pageSize: 5 });
    domains.data.forEach(domain => {
        console.log(`高风险域名: ${domain.domain} (得分: ${domain.risk_score})`);
    });
    
    // 启动扫描
    const scanResult = await api.startScan('example.com');
    console.log('扫描ID:', scanResult.data.scan_id);
}

// 运行示例
exampleUsage().catch(console.error);
```

## 错误处理

API使用标准的HTTP状态码：

- `200 OK`: 请求成功
- `400 Bad Request`: 请求参数错误
- `404 Not Found`: 资源不存在
- `500 Internal Server Error`: 服务器内部错误

**常见错误响应示例**:

```json
{
  "success": false,
  "error": "域名格式不正确",
  "message": "请输入有效的域名格式，如 example.com"
}
```

```json
{
  "success": false,
  "error": "数据库连接失败",
  "message": "无法连接到数据库，请检查数据库服务是否运行"
}
```

## 注意事项

1. **开发环境**: API在开发环境下运行在 `http://localhost:5000`
2. **生产环境**: 建议添加认证和速率限制
3. **API版本**: 当前为v1版本，后续如有重大变更会通过版本号区分
4. **数据更新**: 部分数据可能来自文件缓存，实时性受扫描频率影响
5. **性能建议**: 大数据量查询建议使用分页参数

## 相关链接

- [项目GitHub仓库](https://github.com/zangrujie/domain-security-monitor)
- [部署指南](DEPLOYMENT.md)
- [使用指南](USAGE_GUIDE.md)
- [贡献指南](CONTRIBUTING.md)

---

*API文档最后更新: 2026年2月10日*