# 项目改进方案 - 基于课题需求的缺失核心功能实现

## 当前项目状态分析

### 已有功能
1. **域名变体生成**：Go实现的字符替换和Punycode生成
2. **DNS探测**：xdig高速DNS扫描器
3. **Web界面**：Flask基础管理界面
4. **威胁情报**：VirusTotal、URLhaus API集成
5. **数据库存储**：PostgreSQL数据模型
6. **多维度风险引擎**：基础风险评分框架

### 缺失的核心功能（按课题要求）

#### 1. 存活验证增强
- [ ] **被动DNS接入**：商业/开源被动DNS数据源
- [ ] **证书透明度查询**：crt.sh API和CertStream集成
- [ ] **主动Web探测**：Playwright/Selenium进行JS渲染
- [ ] **视觉比对**：页面截图和相似度分析
- [ ] **初步可疑指示器**：黑名单匹配、证书不匹配等

#### 2. 多维特征抽取扩展
- [ ] **解析链路关系分析**：DNS解析路径追踪
- [ ] **注册商数据增强**：注册商信誉评分
- [ ] **地理归属分析**：IP地理位置和ASN分析
- [ ] **历史变更轨迹**：WHOIS历史记录分析
- [ ] **团伙关联挖掘**：邮箱、IP、注册者关联分析

#### 3. 风险建模与告警决策
- [ ] **机器学习模型**：聚类分析和模式识别
- [ ] **图关系挖掘**：团伙行为网络分析
- [ ] **知识库比对**：动态威胁情报更新
- [ ] **分级告警机制**：优先级告警策略
- [ ] **处置决策支持**：自动化建议生成

#### 4. 平台功能增强
- [ ] **知识图谱可视化**：域名关联关系展示
- [ ] **趋势分析**：时间序列风险变化
- [ ] **动态规则更新**：模型参数在线调整
- [ ] **告警推送**：多通道通知机制
- [ ] **持续化运维**：自动数据更新和监控

## 实施优先级

### 第一阶段：核心数据源集成（立即实施）
1. **被动DNS模块**：`modules/passive_dns/`
2. **证书透明度模块**：`modules/certificate_transparency/`
3. **主动Web探测模块**：`modules/active_probing/`

### 第二阶段：增强特征分析（第2步）
1. **团伙分析模块**：`modules/cluster_analysis/`
2. **图分析模块**：`modules/graph_analysis/`
3. **时空分析模块**：`modules/spatiotemporal_analysis/`

### 第三阶段：智能模型集成（第3步）
1. **机器学习模块**：`modules/machine_learning/`
2. **告警引擎**：`modules/alert_engine/`
3. **决策支持**：`modules/decision_support/`

### 第四阶段：平台功能增强（第4步）
1. **可视化增强**：`static/js/visualization/`
2. **运维自动化**：`scripts/maintenance/`
3. **API扩展**：`modules/api_extensions/`

## 详细实施计划

### 模块1：被动DNS采集器 (`modules/passive_dns/collector.py`)
**功能**：
- 支持多个被动DNS数据源（Farsight DNSDB、QAX、自建传感器）
- 实时流式数据采集和历史查询
- 解析关系图谱构建

**技术实现**：
- 使用`dnspython`进行DNS查询
- 支持Redis缓存和PostgreSQL存储
- 异步数据采集架构

### 模块2：证书透明度监控 (`modules/certificate_transparency/monitor.py`)
**功能**：
- 实时监控CertStream证书流
- 定期查询crt.sh历史证书
- 证书与域名关联分析

**技术实现**：
- WebSocket连接CertStream
- crt.sh API批量查询
- 证书链分析和域名提取

### 模块3：主动Web探测 (`modules/active_probing/web_scanner.py`)
**功能**：
- 使用Playwright进行完整页面渲染
- JavaScript执行和资源加载
- 页面截图和视觉比对
- 表单和交互元素分析

**技术实现**：
- 异步Playwright浏览器实例
- 视觉相似度算法（SSIM、感知哈希）
- 资源加载时间分析

### 模块4：团伙关联分析 (`modules/cluster_analysis/association.py`)
**功能**：
- 基于注册邮箱的域名聚类
- 基于IP地址的关联分析
- 基于WHOIS信息的团伙识别
- 时间序列注册模式分析

**技术实现**：
- 图数据库（可选Neo4j或NetworkX）
- 聚类算法（DBSCAN、社区发现）
- 时间窗口分析

### 模块5：机器学习风险模型 (`modules/machine_learning/risk_predictor.py`)
**功能**：
- 基于历史数据的监督学习
- 无监督异常检测
- 实时风险预测
- 模型在线更新

**技术实现**：
- Scikit-learn/XGBoost模型
- 特征工程和选择
- 模型评估和验证

## 数据库扩展

需要新增表结构：
1. **passive_dns_records**：被动DNS记录
2. **certificate_records**：证书透明度记录
3. **web_screenshots**：页面截图和元数据
4. **cluster_groups**：团伙分组信息
5. **alert_rules**：告警规则配置
6. **model_versions**：机器学习模型版本

## 配置管理

新增配置项：
1. 被动DNS API密钥
2. 证书透明度服务端点
3. 机器学习模型参数
4. 告警阈值配置
5. 数据保留策略

## 测试计划

1. **单元测试**：每个新模块的独立测试
2. **集成测试**：模块间数据流测试
3. **性能测试**：大规模域名处理能力
4. **安全测试**：API密钥和数据处理安全性

## 风险评估和缓解

1. **API限制**：实现速率限制和缓存机制
2. **数据量**：分片存储和查询优化
3. **性能影响**：异步处理和队列系统
4. **误报率**：可调节的敏感度参数

## 成功标准

1. 实现所有缺失的核心功能
2. 处理性能提升30%以上
3. 检测准确率提升20%以上
4. 告警响应时间缩短50%
5. 系统可扩展性满足持续运维需求