# Domain Security Monitor 部署指南

本指南提供Domain Security Monitor的完整部署说明，包括本地开发环境、生产环境部署和云部署方案。

## 目录

1. [系统要求](#系统要求)
2. [快速开始](#快速开始)
3. [本地开发环境部署](#本地开发环境部署)
4. [生产环境部署](#生产环境部署)
5. [云平台部署](#云平台部署)
6. [配置说明](#配置说明)
7. [维护和监控](#维护和监控)
8. [故障排除](#故障排除)

## 系统要求

### 最低配置
- **CPU**: 双核处理器
- **内存**: 4GB RAM
- **存储**: 10GB可用空间
- **操作系统**: Windows 10/11, Ubuntu 20.04+, macOS 10.15+
- **网络**: 稳定的互联网连接

### 软件依赖
- **Python**: 3.8+
- **PostgreSQL**: 12+
- **Go**: 1.19+（可选，用于构建DNS扫描器）
- **Git**: 最新版本
- **Npcap** (Windows) / **libpcap** (Linux)：用于原始socket DNS扫描

### 推荐配置（生产环境）
- **CPU**: 4核处理器或更多
- **内存**: 8GB RAM或更多
- **存储**: 50GB SSD
- **带宽**: 100Mbps+

## 快速开始

### 1. 克隆项目
```bash
git clone https://github.com/zangrujie/domain-security-monitor.git
cd domain-security-monitor
```

### 2. 快速安装脚本（Linux/macOS）
```bash
# 运行安装脚本
chmod +x scripts/install.sh
./scripts/install.sh
```

### 3. 快速安装脚本（Windows）
```powershell
# 以管理员身份运行PowerShell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

## 本地开发环境部署

### 步骤1：安装PostgreSQL
参考 [postgres_install_guide.md](postgres_install_guide.md) 完成PostgreSQL安装。

### 步骤2：设置Python环境
```bash
# 创建虚拟环境
python -m venv .venv

# 激活虚拟环境
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

# 安装依赖
pip install -r requirements.txt
```

### 步骤3：配置环境变量
```bash
# 复制环境变量模板
cp .env.example .env

# 编辑.env文件，配置以下关键项
# Windows: 使用记事本或VSCode编辑
# Linux/macOS: nano .env 或 vim .env
```

### 步骤4：初始化数据库
```bash
# 运行数据库初始化脚本
python init_database_fixed.py

# 或者手动设置数据库
# 参考postgres_install_guide.md中的数据库创建步骤
```

### 步骤5：安装Go组件（可选）
```bash
# 下载并安装Go编译器
# 参考: https://golang.org/dl/

# 编译项目Go组件
go build -o xdig xdig.go
go build -o domain_gen main.go
```

### 步骤6：启动Web应用
```bash
# 开发模式启动
python web_app.py

# 或者使用生产WSGI服务器
# 安装gunicorn
pip install gunicorn

# 使用gunicorn启动
gunicorn -w 4 -b 127.0.0.1:5000 web_app:app
```

### 步骤7：验证安装
1. 访问 http://127.0.0.1:5000
2. 检查仪表板是否正常显示
3. 运行测试扫描
4. 验证数据存储

## 生产环境部署

### 部署架构
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│    Web前端      │    │   Flask应用     │    │  PostgreSQL数据库│
│   (Nginx/Apache)│◄──►│   (Gunicorn)    │◄──►│     (主从)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                        │                        │
         ▼                        ▼                        ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   负载均衡器    │    │    Redis缓存     │    │   备份系统      │
│   (HAProxy)     │    │   (可选)         │    │   (pgBackRest)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 部署步骤

#### 1. 服务器准备
```bash
# Ubuntu/Debian系统更新
sudo apt update
sudo apt upgrade -y

# 安装基础工具
sudo apt install -y git curl wget python3-pip python3-venv \
     postgresql postgresql-contrib nginx
```

#### 2. 创建部署用户
```bash
# 创建专用用户
sudo useradd -m -s /bin/bash domainsec
sudo passwd domainsec

# 切换到部署用户
sudo su - domainsec
```

#### 3. 部署应用程序
```bash
# 克隆项目
git clone https://github.com/zangrujie/domain-security-monitor.git
cd domain-security-monitor

# 设置Python环境
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install gunicorn

# 配置环境变量
cp .env.example .env
nano .env  # 编辑配置
```

#### 4. 配置PostgreSQL（生产环境）
```bash
# 以postgres用户操作
sudo -u postgres psql

# 创建生产数据库和用户
CREATE DATABASE domain_security_prod;
CREATE USER domainsec_prod WITH PASSWORD 'strong_password';
GRANT ALL PRIVILEGES ON DATABASE domain_security_prod TO domainsec_prod;

# 调整PostgreSQL配置
sudo nano /etc/postgresql/16/main/postgresql.conf
# 修改以下配置：
# max_connections = 200
# shared_buffers = 256MB
# work_mem = 8MB

# 重启PostgreSQL
sudo systemctl restart postgresql
```

#### 5. 配置Gunicorn系统服务
```bash
# 创建Gunicorn配置文件
sudo nano /etc/systemd/system/domainsec.service
```

**domainsec.service内容**:
```ini
[Unit]
Description=Domain Security Monitor Gunicorn Service
After=network.target postgresql.service

[Service]
User=domainsec
Group=www-data
WorkingDirectory=/home/domainsec/domain-security-monitor
Environment="PATH=/home/domainsec/domain-security-monitor/.venv/bin"
ExecStart=/home/domainsec/domain-security-monitor/.venv/bin/gunicorn \
          --workers 4 \
          --bind unix:/tmp/domainsec.sock \
          --access-logfile /var/log/domainsec/access.log \
          --error-logfile /var/log/domainsec/error.log \
          web_app:app

[Install]
WantedBy=multi-user.target
```

```bash
# 创建日志目录
sudo mkdir -p /var/log/domainsec
sudo chown domainsec:www-data /var/log/domainsec

# 启动服务
sudo systemctl daemon-reload
sudo systemctl start domainsec
sudo systemctl enable domainsec

# 检查状态
sudo systemctl status domainsec
```

#### 6. 配置Nginx反向代理
```bash
# 创建Nginx配置文件
sudo nano /etc/nginx/sites-available/domainsec
```

**Nginx配置**:
```nginx
server {
    listen 80;
    server_name your-domain.com;  # 修改为你的域名
    client_max_body_size 100M;

    location / {
        proxy_pass http://unix:/tmp/domainsec.sock;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static {
        alias /home/domainsec/domain-security-monitor/static;
        expires 30d;
    }

    # 限制API访问频率
    location /api/ {
        proxy_pass http://unix:/tmp/domainsec.sock;
        limit_req zone=api burst=20 nodelay;
        limit_req_status 429;
    }

    # 启用压缩
    gzip on;
    gzip_types text/plain text/css application/json application/javascript;
}

# API限制区域
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
```

```bash
# 启用站点
sudo ln -s /etc/nginx/sites-available/domainsec /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

#### 7. 配置SSL/TLS（使用Let's Encrypt）
```bash
# 安装Certbot
sudo apt install certbot python3-certbot-nginx

# 获取SSL证书
sudo certbot --nginx -d your-domain.com

# 自动续期测试
sudo certbot renew --dry-run
```

#### 8. 配置防火墙
```bash
# 配置UFW防火墙
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

#### 9. 配置日志轮转
```bash
# 创建日志轮转配置
sudo nano /etc/logrotate.d/domainsec
```

```bash
/var/log/domainsec/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 domainsec www-data
    sharedscripts
    postrotate
        systemctl reload domainsec > /dev/null 2>&1 || true
    endscript
}
```

## 容器化部署（已移除示例）

原文档中的 Docker Compose 与 Dockerfile 示例已移除。若需使用容器化部署，请根据目标平台（Docker Compose、Kubernetes、云容器服务等）自行创建部署清单，并确保遵循组织安全与运行时规范。

建议替代步骤：
- 在生产环境使用系统服务（systemd + gunicorn + nginx）或容器平台（Kubernetes）部署服务
- 为数据库和缓存使用托管或独立服务（例如 RDS、Cloud SQL、Managed Redis）而非内置容器
- 将敏感配置通过环境变量或机密管理（例如 Vault、Kubernetes Secrets）提供给运行时

若你希望我为特定平台（如 Kubernetes 或 Docker Compose）生成安全的部署示例，请告诉我目标平台与约束，我可以为你创建相应部署清单。

## 云平台部署

### AWS Elastic Beanstalk
1. **准备部署包**:
```bash
# 创建部署配置文件 .ebextensions/domainsec.config
option_settings:
  aws:elasticbeanstalk:container:python:
    WSGIPath: web_app:app
  aws:elasticbeanstalk:application:environment:
    DB_HOST: ${DB_HOST}
    DB_PORT: 5432
    DB_NAME: ${DB_NAME}
    DB_USER: ${DB_USER}
    DB_PASSWORD: ${DB_PASSWORD}
```

2. **创建RDS数据库**:
```bash
aws rds create-db-instance \
  --db-instance-identifier domainsec-db \
  --db-instance-class db.t3.micro \
  --engine postgres \
  --master-username admin \
  --master-user-password ${DB_PASSWORD} \
  --allocated-storage 20
```

### Google Cloud Platform (GCP)
1. **创建Cloud SQL实例**:
```bash
gcloud sql instances create domainsec-sql \
  --database-version=POSTGRES_16 \
  --tier=db-f1-micro \
  --region=us-central1
```

2. **部署到Cloud Run**:
```bash
# 构建容器
gcloud builds submit --tag gcr.io/${PROJECT_ID}/domainsec

# 部署到Cloud Run
gcloud run deploy domainsec \
  --image gcr.io/${PROJECT_ID}/domainsec \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars="DB_HOST=${DB_HOST}"
```

### Azure App Service
1. **创建PostgreSQL数据库**:
```bash
az postgres server create \
  --name domainsec-postgres \
  --resource-group DomainSecRG \
  --location eastus \
  --admin-user adminuser \
  --admin-password ${PASSWORD} \
  --sku-name B_Gen5_1
```

2. **部署Web应用**:
```bash
az webapp create \
  --name domainsec-app \
  --resource-group DomainSecRG \
  --plan DomainSecPlan \
  --runtime "PYTHON|3.10"
```

## 配置说明

### 关键配置文件

#### 1. .env 文件配置
```env
# 数据库配置（必须）
DB_HOST=localhost
DB_PORT=5432
DB_NAME=domain_security
DB_USER=postgres
DB_PASSWORD=your_secure_password

# Flask配置
FLASK_ENV=production
SECRET_KEY=your-secret-key-change-this
DEBUG=False

# 威胁情报API（可选但推荐）
VT_API_KEY=your_virustotal_api_key_here

# 性能配置
DNS_SCAN_RATE=500
VT_RATE_LIMIT_REQUESTS=4
VT_RATE_LIMIT_PERIOD=60

# 缓存配置
REDIS_URL=redis://localhost:6379/0
CACHE_TIMEOUT=3600

# 安全配置
MAX_CONTENT_LENGTH=16777216  # 16MB
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
```

#### 2. Nginx配置优化
```nginx
# 在/etc/nginx/nginx.conf中添加
worker_processes auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    multi_accept on;
}

http {
    # 基础配置
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    # 安全头
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # 压缩
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript;
}
```

#### 3. Gunicorn配置优化
创建 `gunicorn_config.py`:
```python
import multiprocessing

bind = "unix:/tmp/domainsec.sock"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "gevent"
worker_connections = 1000
timeout = 30
keepalive = 2
max_requests = 1000
max_requests_jitter = 50
```

## 维护和监控

### 1. 备份策略
```bash
# 创建数据库备份脚本 /usr/local/bin/backup_domainsec.sh
#!/bin/bash
BACKUP_DIR="/backups/domainsec"
DATE=$(date +%Y%m%d_%H%M%S)

# 数据库备份
pg_dump -h localhost -U domainsec domain_security_prod \
  > "${BACKUP_DIR}/db_backup_${DATE}.sql"

# 应用数据备份
tar -czf "${BACKUP_DIR}/app_data_${DATE}.tar.gz" \
  /home/domainsec/domain-security-monitor/monitoring_results \
  /home/domainsec/domain-security-monitor/domain_variants

# 保留最近30天备份
find "${BACKUP_DIR}" -type f -name "*.sql" -mtime +30 -delete
find "${BACKUP_DIR}" -type f -name "*.tar.gz" -mtime +30 -delete

# 添加定时任务
# crontab -e
# 0 2 * * * /usr/local/bin/backup_domainsec.sh
```

### 2. 监控配置
```bash
# 使用Prometheus监控
# 安装Prometheus客户端
pip install prometheus-flask-exporter

# 在web_app.py中添加
from prometheus_flask_exporter import PrometheusMetrics
metrics = PrometheusMetrics(app)
```

### 3. 日志监控
```bash
# 使用logwatch监控日志
sudo apt install logwatch

# 配置logwatch
sudo nano /etc/logwatch/conf/logwatch.conf
# 添加domainsec服务
Service = "domainsec"
```

### 4. 性能监控脚本
创建 `monitor_performance.py`:
```python
#!/usr/bin/env python3
"""
性能监控脚本
"""

import psutil
import requests
import json
from datetime import datetime

def check_system_resources():
    """检查系统资源使用情况"""
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return {
        "timestamp": datetime.now().isoformat(),
        "cpu_percent": cpu_percent,
        "memory_percent": memory.percent,
        "disk_percent": disk.percent,
        "network_io": psutil.net_io_counters()._asdict()
    }

def check_application_health():
    """检查应用健康状态"""
    try:
        response = requests.get("http://localhost:5000/api/system/status", timeout=5)
        return response.json()
    except Exception as e:
        return {"error": str(e), "healthy": False}

if __name__ == "__main__":
    # 监控系统资源
    system_status = check_system_resources()
    
    # 监控应用状态
    app_status = check_application_health()
    
    # 输出监控结果
    print(json.dumps({
        "system": system_status,
        "application": app_status
    }, indent=2))
```

## 故障排除

### 常见问题及解决方案

#### 问题1：数据库连接失败
**症状**: `psycopg2.OperationalError: connection to server at "localhost" (::1), port 5432 failed`
**解决方案**:
1. 检查PostgreSQL服务状态: `sudo systemctl status postgresql`
2. 验证连接参数: `psql -h localhost -U postgres -d domain_security`
3. 检查防火墙设置: `sudo ufw status`
4. 检查pg_hba.conf配置

#### 问题2：内存不足
**症状**: 应用崩溃，系统变慢
**解决方案**:
1. 调整Gunicorn worker数量: `workers = 2`
2. 增加系统交换空间
3. 优化数据库查询
4. 启用Redis缓存

#### 问题3：API响应慢
**症状**: API请求超时
**解决方案**:
1. 检查数据库查询性能
2. 启用数据库连接池
3. 添加Redis缓存
4. 优化Nginx配置

#### 问题4：SSL证书问题
**症状**: 浏览器显示安全警告
**解决方案**:
1. 更新Let's Encrypt证书: `sudo certbot renew`
2. 检查Nginx SSL配置
3. 验证证书链

### 调试技巧

#### 1. 查看应用日志
```bash
# 查看实时日志
sudo journalctl -u domainsec -f

# 查看错误日志
tail -f /var/log/domainsec/error.log
```

#### 2. 测试API端点
```bash
# 测试健康检查
curl http://localhost:5000/api/system/status

# 测试数据库连接
curl http://localhost:5000/api/dashboard/stats

# 测试扫描功能
curl -X POST http://localhost:5000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{"domain": "test.com"}'
```

#### 3. 性能分析
```bash
# 使用ab进行压力测试
ab -n 1000 -c 10 http://localhost:5000/api/dashboard/stats

# 使用htop查看资源使用
htop
```

## 升级指南

### 从旧版本升级
```bash
# 1. 备份当前数据和配置
./scripts/backup.sh

# 2. 拉取最新代码
git pull origin main

# 3. 更新依赖
source .venv/bin/activate
pip install -r requirements.txt

# 4. 运行数据库迁移
python -m modules.database.migrations

# 5. 重启服务
sudo systemctl restart domainsec
sudo systemctl restart nginx
```

### 数据库迁移
```sql
-- 如果数据库结构有变化，可能需要手动迁移
-- 例如：添加新表或列
ALTER TABLE domains ADD COLUMN threat_score FLOAT DEFAULT 0.0;
```

## 安全建议

### 生产环境安全配置
1. **更改默认密码**: 所有默认密码必须更改
2. **限制访问**: 仅允许必要的网络访问
3. **定期更新**: 保持系统和依赖库更新
4. **启用防火墙**: 配置适当的防火墙规则
5. **监控日志**: 定期审查安全日志
6. **数据加密**: 启用数据库和传输层加密
7. **备份验证**: 定期测试备份恢复过程

### 安全审计清单
- [ ] 所有默认密码已更改
- [ ] SSL/TLS已正确配置
- [ ] 防火墙规则已设置
- [ ] 定期安全更新已启用
- [ ] 访问日志已开启
- [ ] 数据库备份已配置
- [ ] API访问已限制
- [ ] 文件权限已正确设置

## 支持与资源

### 获取帮助
1. **项目文档**: 查看项目README和本指南
2. **GitHub Issues**: 报告问题和请求功能
3. **社区讨论**: 参与项目讨论
4. **邮件支持**: 联系维护团队

### 相关资源
- [PostgreSQL文档](https://www.postgresql.org/docs/)
- [Flask文档](https://flask.palletsprojects.com/)
- [Gunicorn文档](https://docs.gunicorn.org/)
- [Nginx文档](https://nginx.org/en/docs/)

### 联系信息
- **项目主页**: https://github.com/zangrujie/domain-security-monitor
- **问题反馈**: GitHub Issues
- **安全报告**: security@example.com

---

*部署指南最后更新: 2026年2月10日*
*版本: Domain Security Monitor v2.0*