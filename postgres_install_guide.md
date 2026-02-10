# PostgreSQL 安装和配置指南

## 概述

本指南将帮助您完成PostgreSQL的安装、配置，以及与本项目的集成。

## 步骤1：安装PostgreSQL

### Windows 安装方法

#### 方法一：使用安装程序（推荐）

1. **下载PostgreSQL**
   - 访问 [PostgreSQL官网](https://www.postgresql.org/download/windows/)
   - 下载最新版本的安装程序（如 PostgreSQL 16）

2. **运行安装程序**
   - 双击安装程序
   - 选择安装目录（默认: `C:\Program Files\PostgreSQL\16`）
   - 选择组件：建议全选
   - 设置数据目录（默认: `C:\Program Files\PostgreSQL\16\data`）

3. **设置密码**
   - **重要**：设置超级用户（postgres）的密码，记住这个密码
   - 例如：设置密码为 `postgres123`（或您选择的密码）

4. **配置端口**
   - 默认端口：5432（保持默认）

5. **选择地区设置**
   - 选择默认值或根据您的区域设置

6. **完成安装**
   - 等待安装完成
   - 取消选中"Stack Builder"（除非需要额外工具）

#### 方法二：使用包管理器（PowerShell）

```powershell
# 使用Chocolatey包管理器
choco install postgresql

# 或使用Winget
winget install PostgreSQL.PostgreSQL
```

### 验证安装

安装完成后，验证PostgreSQL服务：

```powershell
# 检查PostgreSQL服务状态
sc query postgresql-x64-16  # 或 postgresql-x64-15，根据版本

# 如果服务没有运行，启动它
net start postgresql-x64-16

# 验证安装路径
dir "C:\Program Files\PostgreSQL"
```

## 步骤2：配置数据库

### 创建数据库和用户

1. **使用pgAdmin（图形界面）**
   - 安装时包含pgAdmin，从开始菜单打开
   - 连接时使用密码（安装时设置的）
   - 创建新数据库：`domain_security`

2. **使用命令行（psql）**

```powershell
# 打开命令行工具（以管理员身份运行）
cd "C:\Program Files\PostgreSQL\16\bin"

# 连接到PostgreSQL
.\psql.exe -U postgres -h localhost

# 输入密码（安装时设置的）

# 创建数据库
CREATE DATABASE domain_security;

# 列出所有数据库验证
\l

# 退出
\q
```

### 创建数据库初始化脚本（已提供）

项目已包含 `init_database.py` 脚本，但需要修改密码：

```python
# 编辑 init_database.py 文件，将密码修改为您设置的密码
conn_params = {
    'host': 'localhost',
    'port': '5432',
    'user': 'postgres',
    'password': '您设置的密码'  # 修改这里
}
```

## 步骤3：配置项目环境

### 1. 编辑环境变量文件

打开 `.env` 文件，修改数据库配置：

```env
# PostgreSQL数据库连接配置
DB_USER=postgres
DB_PASSWORD=您设置的密码  # 修改这里
DB_HOST=localhost
DB_PORT=5432
DB_NAME=domain_security

# 可选：威胁情报API密钥
# VT_API_KEY=your_virustotal_api_key_here
```

### 2. 安装必要的Python包

```bash
# 激活虚拟环境
.\myenv\Scripts\activate

# 安装PostgreSQL驱动
pip install psycopg2-binary
pip install sqlalchemy
```

### 3. 测试数据库连接

```bash
# 运行数据库初始化脚本
python init_database.py

# 或者使用配置助手
python postgres_config.py
```

## 步骤4：运行数据库测试

### 测试数据库连接

创建测试脚本 `test_db_connection.py`：

```python
#!/usr/bin/env python3
"""
测试数据库连接
"""

import os
from dotenv import load_dotenv
import psycopg2

# 加载环境变量
load_dotenv()

def test_connection():
    try:
        conn_params = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': os.getenv('DB_PORT', '5432'),
            'user': os.getenv('DB_USER', 'postgres'),
            'password': os.getenv('DB_PASSWORD'),
            'database': os.getenv('DB_NAME', 'domain_security')
        }
        
        print("测试数据库连接...")
        print(f"主机: {conn_params['host']}")
        print(f"数据库: {conn_params['database']}")
        
        conn = psycopg2.connect(**conn_params)
        cursor = conn.cursor()
        
        # 测试查询
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        
        print(f"✅ 连接成功!")
        print(f"PostgreSQL版本: {version}")
        
        # 检查表结构
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name;
        """)
        
        tables = cursor.fetchall()
        if tables:
            print(f"现有表: {[t[0] for t in tables]}")
        else:
            print("数据库为空，运行数据管道时将创建表")
        
        cursor.close()
        conn.close()
        return True
        
    except psycopg2.OperationalError as e:
        print(f"❌ 连接失败: {e}")
        return False
    except Exception as e:
        print(f"❌ 错误: {e}")
        return False

if __name__ == "__main__":
    test_connection()
```

## 常见问题解决

### 问题1：连接被拒绝

**症状**：
```
psycopg2.OperationalError: connection to server at "localhost" (::1), port 5432 failed
```

**解决方案**：
1. 确保PostgreSQL服务正在运行：
   ```powershell
   net start postgresql-x64-16
   ```

2. 检查防火墙设置：
   ```powershell
   # 允许PostgreSQL通过防火墙
   New-NetFirewallRule -DisplayName "PostgreSQL" -Direction Inbound -Protocol TCP -LocalPort 5432 -Action Allow
   ```

3. 验证连接参数：
   - 主机：localhost 或 127.0.0.1
   - 端口：5432
   - 密码：正确

### 问题2：数据库不存在

**症状**：
```
psycopg2.OperationalError: database "domain_security" does not exist
```

**解决方案**：
```sql
-- 连接到默认数据库
psql -U postgres -h localhost

-- 创建数据库
CREATE DATABASE domain_security;
```

### 问题3：身份验证失败

**症状**：
```
psycopg2.OperationalError: FATAL: password authentication failed for user "postgres"
```

**解决方案**：
1. 重置密码：
   ```powershell
   # 停止服务
   net stop postgresql-x64-16
   
   # 编辑pg_hba.conf文件
   # 位置: C:\Program Files\PostgreSQL\16\data\pg_hba.conf
   # 将 "md5" 改为 "trust"（临时）
   
   # 重启服务
   net start postgresql-x64-16
   
   # 连接到数据库（无需密码）
   psql -U postgres -h localhost
   
   # 修改密码
   ALTER USER postgres WITH PASSWORD '新密码';
   
   # 恢复pg_hba.conf设置
   # 将 "trust" 改回 "md5"
   ```

## 高级配置

### 创建专用用户（可选）

为了安全，可以创建专用用户：

```sql
-- 创建新用户
CREATE USER domain_user WITH PASSWORD 'secure_password';

-- 授予数据库权限
GRANT ALL PRIVILEGES ON DATABASE domain_security TO domain_user;

-- 更新 .env 文件
DB_USER=domain_user
DB_PASSWORD=secure_password
```

### 配置数据库性能（可选）

```sql
-- 调整连接数（适合小型应用）
ALTER SYSTEM SET max_connections = '100';

-- 调整共享缓冲区
ALTER SYSTEM SET shared_buffers = '128MB';

-- 重启服务使设置生效
```

## 下一步操作

### 完成安装后的验证

1. **验证数据库连接**：
   ```bash
   python test_db_connection.py
   ```

2. **运行完整数据管道测试**：
   ```bash
   python -m modules.data_pipeline -d test.com
   ```

3. **检查数据库表创建**：
   ```bash
   # 运行数据管道后，检查数据库表
   psql -U postgres -d domain_security -c "\dt"
   ```

### 安装完成检查清单

- [ ] PostgreSQL服务正在运行
- [ ] 数据库 `domain_security` 已创建
- [ ] `.env` 文件已正确配置
- [ ] Python包已安装（psycopg2-binary, sqlalchemy）
- [ ] 数据库连接测试成功
- [ ] 数据管道可以正常运行

## 故障排除支持

如果遇到问题：

1. **查看PostgreSQL日志**：
   ```
   C:\Program Files\PostgreSQL\16\data\log\
   ```

2. **使用pgAdmin工具**：
   - 图形界面更易诊断问题

3. **在线资源**：
   - [PostgreSQL官方文档](https://www.postgresql.org/docs/)
   - [Stack Overflow PostgreSQL标签](https://stackoverflow.com/questions/tagged/postgresql)

## 性能优化（后续步骤）

完成基本安装后，可以考虑：

1. **定期备份策略**
2. **监控和告警设置**
3. **查询性能优化**
4. **高可用性配置**

完成PostgreSQL安装和配置后，您的域名安全分析工具将具备完整的数据存储能力！