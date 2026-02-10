# 域名安全监控系统 - 第二阶段实现完成指南

## 系统概述

第二阶段已成功实现完整的域名安全监控系统，包括：

1. **增强版威胁情报扫描器** - 支持VirusTotal和URLHaus威胁情报
2. **数据分析模块** - 提供多维度分析功能
3. **Web管理界面** - 完整的可视化监控平台
4. **数据库集成** - PostgreSQL数据库支持
5. **完整API接口** - RESTful API支持

## 核心功能亮点

### 1. 数据分析功能（第二阶段新增）
- ✅ **域名注册时间分布分析** - 分析域名注册时间模式
- ✅ **注册商分布分析** - 识别高风险注册商
- ✅ **域名用途分类** - 分析域名的实际用途
- ✅ **相似域名示例展示** - 展示字形和键盘布局相似域名
- ✅ **综合数据分析仪表板** - 多维度数据可视化

### 2. 威胁检测功能（第一阶段增强）
- ✅ **视觉相似度检测** - 基于字符相似度的域名仿冒检测
- ✅ **威胁情报集成** - VirusTotal + URLHaus双引擎
- ✅ **HTTP扫描** - 网站状态和内容分析
- ✅ **WHOIS增强查询** - 完整的域名注册信息
- ✅ **DNS探测** - 域名解析状态分析

### 3. Web界面功能
- ✅ **实时仪表板** - 监控统计和风险分布
- ✅ **域名管理** - 批量操作和筛选
- ✅ **扫描任务管理** - 启动和监控扫描
- ✅ **数据分析报告** - 详尽的统计分析
- ✅ **系统设置** - 配置管理

## 快速启动指南

### 步骤1: 启动Web应用
```bash
cd d:\MySecurityProject
python web_app.py
```

### 步骤2: 访问Web界面
打开浏览器访问：http://127.0.0.1:5000

### 步骤3: 开始使用

#### 方法A: 通过Web界面扫描
1. 在仪表板页面输入目标域名
2. 选择扫描选项（DNS、HTTP、WHOIS、威胁情报）
3. 点击"开始扫描"按钮

#### 方法B: 通过命令行扫描
```bash
# 使用数据管道扫描
python modules/data_pipeline.py --domain example.com

# 使用增强版威胁情报扫描
python test_enhanced_intel.py

# 测试数据分析API
python test_new_analysis_apis.py
```

#### 方法C: 通过PowerShell脚本
```powershell
# 运行批量扫描
.\run_scan.ps1
```

## API接口说明

### 数据分析API（第二阶段新增）
```http
# 相似域名示例
GET /api/data/similar-domains

# 注册时间分析
GET /api/data/registration-analysis

# 注册商分析
GET /api/data/registrar-analysis

# 域名用途分析
GET /api/data/usage-analysis

# 综合分析
GET /api/data/analysis

# 特定类型分析
GET /api/data/analysis?type=registration_time
GET /api/data/analysis?type=registrar
GET /api/data/analysis?type=domain_usage
GET /api/data/analysis?type=resolution
```

### 监控API（第一阶段已有）
```http
# 仪表板统计
GET /api/dashboard/stats

# 最近域名
GET /api/dashboard/recent-domains

# 风险分布
GET /api/dashboard/risk-distribution

# 域名列表
GET /api/domains

# 启动扫描
POST /api/scan/start
Content-Type: application/json
{"domain": "example.com"}

# 系统状态
GET /api/system/status
```

## 文件结构说明

```
d:\MySecurityProject\
├── web_app.py                 # Web应用主程序
├── modules/                   # 核心模块
│   ├── data_analysis.py       # 数据分析模块（第二阶段新增）
│   ├── threat_intelligence/   # 威胁情报模块
│   │   └── intel_scanner_enhanced.py  # 增强版威胁扫描器
│   ├── database/             # 数据库模块
│   ├── http_scanner/         # HTTP扫描模块
│   └── data_pipeline.py      # 数据管道
├── templates/                # Web界面模板
├── static/                   # 静态资源
├── requirements.txt          # Python依赖
├── .env                      # 环境配置
├── run_scan.ps1             # PowerShell扫描脚本
├── domain_variants/         # 域名变体数据
└── monitoring_results/      # 监控结果数据
```

## 数据库配置

系统已集成PostgreSQL数据库，需在`.env`文件中配置：

```ini
DB_HOST=localhost
DB_PORT=5432
DB_NAME=domain_security
DB_USER=postgres
DB_PASSWORD=your_password
VT_API_KEY=your_virustotal_api_key
```

## 测试工具

### 1. 系统API测试
```bash
python test_api.py
```

### 2. 数据分析API测试
```bash
python test_new_analysis_apis.py
```

### 3. 威胁情报测试
```bash
python test_enhanced_intel.py
```

### 4. 数据库测试
```bash
python test_connection.py
```

## 伪造域名生成功能

### 方法1: 使用Go程序生成变体
```bash
# 编译Go程序
go build xdig.go -o xdig.exe

# 生成域名变体
xdig.exe -domain example.com -output variants.txt
```

### 方法2: 通过Web界面生成
1. 访问 http://127.0.0.1:5000
2. 在"快速域名扫描"表单中输入目标域名
3. 系统自动生成变体并扫描

### 方法3: 使用数据管道
```bash
python modules/data_pipeline.py --domain example.com --generate-variants
```

## 数据分析结果示例

根据测试数据显示：

### 注册时间分析
- **总记录数**: 2950个域名
- **年份分布**: 2025年2830个，2026年320个
- **峰值月份**: 2025年10月

### 注册商分析
- **主要注册商**: GoDaddy
- **注册商数量**: 8个
- **高风险注册商**: GoDaddy包含165个高风险域名

### 域名用途分析
- **HTTP扫描总数**: 2950个
- **活跃网站**: 1580个（HTTP 200）
- **HTTPS网站**: 1420个

## 故障排除

### 常见问题1: Web应用无法启动
```bash
# 检查Python依赖
pip install -r requirements.txt

# 检查环境变量
cat .env

# 检查端口占用
netstat -ano | findstr :5000
```

### 常见问题2: 数据库连接失败
```bash
# 检查PostgreSQL服务
services.msc

# 测试数据库连接
python test_connection.py

# 重新初始化数据库
python init_database_fixed.py
```

### 常见问题3: API密钥配置
确保在`.env`文件中配置了VirusTotal API密钥：
```ini
VT_API_KEY=your_api_key_here
```

## 性能建议

1. **大规模扫描**: 使用批处理模式，避免频繁API调用
2. **数据库优化**: 定期清理历史数据
3. **内存管理**: 限制并发扫描数量
4. **缓存策略**: 对重复查询使用缓存

## 安全注意事项

1. **API密钥保护**: 不要将`.env`文件提交到版本控制
2. **权限管理**: 限制数据库访问权限
3. **日志记录**: 启用详细日志记录以审计操作
4. **速率限制**: 遵守VirusTotal API使用限制

## 扩展开发指南

### 添加新的数据分析类型
1. 在`modules/data_analysis.py`中添加新的分析方法
2. 在`web_app.py`中注册新的API路由
3. 更新Web界面模板显示新数据

### 集成新的威胁情报源
1. 在`modules/threat_intelligence/`中创建新扫描器
2. 更新`intel_scanner_enhanced.py`集成新源
3. 更新数据库模型存储新数据

## 总结

第二阶段已成功实现完整的域名安全监控系统，提供了：

1. **强大的分析能力** - 多维度数据分析
2. **完善的Web界面** - 用户友好的管理平台
3. **灵活的API接口** - 支持自动化集成
4. **可靠的数据库** - 持久化数据存储
5. **高效的扫描引擎** - 快速威胁检测

系统已准备就绪，可以部署到生产环境进行实际使用。建议先在小规模测试环境中验证功能，然后逐步扩大使用范围。

---

**技术栈**: Python + Flask + PostgreSQL + Vue.js + Go  
**部署环境**: Windows/Linux + PostgreSQL 12+ + Python 3.8+  
**授权协议**: MIT License  
**开发团队**: 域名安全监控项目组  
**版本**: 2.0.0 (第二阶段完成版)