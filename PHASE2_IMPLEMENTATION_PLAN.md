# 第二阶段实施计划：特征扩展

## 概述
基于第一阶段的基础设施，扩展系统功能，集成威胁情报API并建立数据存储层。

## 当前状态分析
### ✅ 已完成的模块
1. **数据模式** (`modules/data_schemas.py`) - 统一的数据结构定义
2. **数据处理管道** (`modules/data_pipeline.py`) - 基础协调框架  
3. **HTTP扫描器** (`modules/http_scanner/`) - 基础HTTP探测
4. **WHOIS增强模块** (`modules/whois_enhanced.py`) - 结构化WHOIS查询
5. **威胁情报模块** (`modules/threat_intelligence/`) - 模拟版本存在

### ⚠️ 需要增强的模块
1. **威胁情报模块** - 需要集成真实API（目前为模拟）
2. **数据库存储层** - PostgreSQL存储和查询API（缺失）
3. **数据管道连接** - 完善各模块间的数据流

## 实施步骤

### 步骤1：增强威胁情报模块
**目标**：集成1-2个免费API源（VirusTotal + URLhaus）
**具体任务**：
1. 获取VirusTotal API密钥（需要用户注册）
2. 实现真实VirusTotal API调用
3. 增强URLhaus API调用（已有基础）
4. 添加PhishTank API或数据库集成
5. 优化风险评分算法
6. 添加API密钥配置管理

### 步骤2：构建PostgreSQL数据库层
**目标**：实现结构化数据存储和查询API
**具体任务**：
1. 设计数据库表结构
   - 域名基础信息表
   - DNS扫描结果表  
   - HTTP扫描结果表
   - WHOIS信息表
   - 威胁情报表
   - 综合风险评估表
2. 创建数据库初始化脚本
3. 实现数据访问层（DAO）
4. 创建查询API接口
5. 添加数据迁移和备份功能

### 步骤3：完善数据处理管道
**目标**：连接xdig → HTTP扫描 → 威胁情报 → 存储
**具体任务**：
1. 优化现有数据管道类
2. 添加数据库存储步骤
3. 实现错误处理和重试机制
4. 添加进度跟踪和日志记录
5. 创建管道配置管理
6. 添加并行处理优化

### 步骤4：配置管理和文档
**目标**：完善系统配置和使用文档
**具体任务**：
1. 创建配置文件模板
2. 添加环境变量支持
3. 更新使用指南
4. 创建数据库部署文档
5. 添加API密钥配置说明

## 技术实现细节

### 威胁情报API选择
1. **VirusTotal**（需要API密钥）- 全面的恶意软件检测
   - 免费版：4 requests/minute, 500 requests/day
   - 需要注册获取API密钥
   
2. **URLhaus**（免费公开API）- 恶意URL数据库
   - 无需API密钥
   - 实时恶意URL数据
   
3. **PhishTank**（可选）- 钓鱼网站数据库
   - 需要下载数据库或使用API
   - 有每日更新

### 数据库设计（初步）
```sql
-- 域名基础信息
CREATE TABLE domains (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    original_target VARCHAR(255),
    punycode VARCHAR(255),
    visual_similarity FLOAT,
    generation_method VARCHAR(50),
    first_seen TIMESTAMP,
    last_updated TIMESTAMP
);

-- DNS扫描结果  
CREATE TABLE dns_scans (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id),
    has_dns_record BOOLEAN,
    resolved_ips TEXT[],
    response_time_ms FLOAT,
    dns_server VARCHAR(50),
    scan_timestamp TIMESTAMP
);

-- HTTP扫描结果
CREATE TABLE http_scans (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id),
    http_status INTEGER,
    https_status INTEGER,
    preferred_protocol VARCHAR(10),
    final_url TEXT,
    redirect_count INTEGER,
    headers JSONB,
    ssl_certificate JSONB,
    page_analysis JSONB,
    http_risk_score FLOAT,
    risk_level VARCHAR(20),
    scan_timestamp TIMESTAMP
);

-- WHOIS信息
CREATE TABLE whois_records (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id),
    registrar VARCHAR(255),
    creation_date TIMESTAMP,
    expiration_date TIMESTAMP,
    updated_date TIMESTAMP,
    name_servers TEXT[],
    status TEXT[],
    emails TEXT[],
    registrant JSONB,
    admin JSONB,
    tech JSONB,
    raw_text TEXT,
    whois_risk_score FLOAT,
    risk_level VARCHAR(20),
    query_timestamp TIMESTAMP
);

-- 威胁情报
CREATE TABLE threat_intelligence (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id),
    threat_sources_checked TEXT[],
    threat_results JSONB,
    threat_risk_score FLOAT,
    risk_level VARCHAR(20),
    check_timestamp TIMESTAMP
);

-- 综合风险评估
CREATE TABLE risk_assessments (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id),
    visual_similarity_score FLOAT,
    whois_risk_score FLOAT,
    http_risk_score FLOAT,
    threat_risk_score FLOAT,
    dns_risk_score FLOAT,
    weighted_total_score FLOAT,
    risk_level VARCHAR(20),
    risk_factors TEXT[],
    confidence FLOAT,
    assessment_timestamp TIMESTAMP
);
```

### 实施优先级
1. **高优先级**：威胁情报真实API集成
2. **中优先级**：数据库基础结构
3. **低优先级**：查询API和Web界面

## 时间估计
- 步骤1：2-3天（威胁情报API集成）
- 步骤2：2-3天（数据库层实现）
- 步骤3：1-2天（管道完善和测试）
- 步骤4：0.5-1天（文档和配置）

**总计**：5-7天（符合原计划的1周）

## 风险与缓解
1. **API限制**：免费API有调用限制 → 添加速率限制和缓存
2. **数据库部署**：用户可能没有PostgreSQL → 提供Docker部署选项
3. **密钥管理**：API密钥需要安全存储 → 使用环境变量和配置文件
4. **性能问题**：大量域名扫描可能慢 → 优化并发和批处理

## 下一步行动
1. 立即开始实施威胁情报API集成
2. 同时设计数据库结构
3. 逐步完善数据管道连接