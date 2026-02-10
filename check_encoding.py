#!/usr/bin/env python3
"""
检查环境变量编码问题
"""

import os

print("检查环境变量...")
print(f"DB_USER: {repr(os.getenv('DB_USER'))}")
print(f"DB_PASSWORD: {repr(os.getenv('DB_PASSWORD'))}")
print(f"DB_HOST: {repr(os.getenv('DB_HOST'))}")
print(f"DB_PORT: {repr(os.getenv('DB_PORT'))}")
print(f"DB_NAME: {repr(os.getenv('DB_NAME'))}")

# 检查字节表示
password = os.getenv('DB_PASSWORD', '')
print(f"\nDB_PASSWORD 原始字节: {password.encode('utf-8')}")
print(f"DB_PASSWORD 十六进制: {password.encode('utf-8').hex()}")

# 检查.env文件
print("\n检查.env文件内容...")
with open('.env', 'rb') as f:
    content = f.read()
    print(f"文件字节: {content[:100]}")
    print(f"文件十六进制: {content[:100].hex()}")

# 尝试解码为不同编码
encodings = ['utf-8', 'gbk', 'gb2312', 'latin-1', 'cp1252']
print("\n尝试不同编码解码...")
for encoding in encodings:
    try:
        decoded = content.decode(encoding)
        lines = decoded.split('\n')
        for line in lines:
            if 'DB_PASSWORD' in line:
                print(f"{encoding}: {repr(line)}")
                break
    except Exception as e:
        print(f"{encoding}: 解码失败 - {e}")

print("\n建议修复方案:")
print("1. 删除.env文件中的不可见字符")
print("2. 重新创建.env文件")
print("3. 使用ASCII密码")