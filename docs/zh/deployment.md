# MiBee Steward 部署指南

本指南涵盖 MiBee Steward 的生产环境部署方法，包括 Systemd、Docker、Nginx 反向代理、备份策略和监控。

## 概览

MiBee Steward 是一个设备管理和监控系统，具有 Go 后端（Chi + SQLite）和嵌入式 SvelteKit SPA。它支持 SNMP/ICMP/TCP/HTTP 探测、Prometheus 指标收集和心跳监控。

## 部署方式

### 1. Systemd 部署（推荐）

#### 构建 Binary

**从源代码构建：**
```bash
# 克隆仓库
git clone https://github.com/Mi-Bee-Studio/MiBeeSteward.git
cd mibee-steward

# 构建 binary
make build

# 或交叉编译
make build-linux-amd64
```

#### 创建系统用户

```bash
# 创建无登录 shell 的 mibee 用户
sudo useradd -r -s /usr/sbin/nologin -d /opt/mibee-steward mibee
```

#### 安装应用程序文件

```bash
# 创建安装目录
sudo mkdir -p /opt/mibee-steward
sudo mkdir -p /opt/mibee-steward/data
sudo mkdir -p /opt/mibee-steward/data/uploads
sudo mkdir -p /opt/mibee-steward/data/backups
sudo mkdir -p /opt/mibee-steward/configs

# 复制二进制文件和配置
sudo cp mibee-steward /opt/mibee-steward/
sudo cp -r configs/* /opt/mibee-steward/configs/

# 设置权限
sudo chown -R mibee:mibee /opt/mibee-steward
sudo chmod +x /opt/mibee-steward/mibee-steward
```

#### 配置生产环境

```bash
# 复制生产环境配置模板
sudo cp /opt/mibee-steward/configs/config.production.yaml /opt/mibee-steward/configs/config.yaml

# 编辑配置
sudo nano /opt/mibee-steward/configs/config.yaml
```

**关键生产环境设置：**

```yaml
auth:
  jwt_secret: "<32位随机字符>"  # 使用以下命令生成：openssl rand -base64 32
  initial_admin_password: "<强密码>"
  cookie_secure: true
  cookie_same_site: "strict"
```

#### 安装 Systemd 服务

```bash
# 复制服务文件
sudo cp deploy/mibee-steward.service /etc/systemd/system/

# 重载 systemd
sudo systemctl daemon-reload

# 启用并启动服务
sudo systemctl enable mibee-steward
sudo systemctl start mibee-steward

# 检查状态
sudo systemctl status mibee-steward
```

该服务包含安全加固：
- `NoNewPrivileges=true`
- `ProtectSystem=strict`
- `ReadWritePaths=/opt/mibee-steward/data`

### 2. Docker 部署

#### 多阶段 Dockerfile

Dockerfile 使用三阶段构建：
- **阶段 1**: Node 20 Alpine 用于前端构建（SvelteKit SPA）
- **阶段 2**: Go 1.26 Alpine 用于后端编译
- **阶段 3**: Alpine 3.19 运行时镜像

#### Docker Compose 设置

```yaml
services:
  mibee-steward:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - mibee-data:/data
      - ./configs/config.yaml:/app/configs/config.yaml:ro
    environment:
      - MIBEE_SERVER_PORT=8080
    restart: unless-stopped

volumes:
  mibee-data:
```

**构建和启动：**
```bash
# 构建 Docker 镜像
docker compose build

# 启动服务
docker compose up -d

# 检查状态
docker compose ps
docker compose logs -f
```

**环境变量：**
- `MIBEE_SERVER_PORT`: 服务器端口（默认：8080）
- `MIBEE_AUTH_JWT_SECRET`: JWT 密钥（必需）
- `MIBEE_AUTH_INITIAL_ADMIN_PASSWORD`: 管理员密码（必需）

### 3. Nginx 反向代理

#### 配置

将以下配置放置在 `/etc/nginx/sites-available/mibee-steward`：

```nginx
# HTTP 重定向到 HTTPS
server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL 证书配置
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;

    # 现代 TLS 配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # 安全头
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "0" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # 代理到 mibee-steward
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket 支持
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # 缓冲
        proxy_buffering off;
        proxy_request_buffering off;
        
        # 超时
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # 最大上传大小（100MB）
        client_max_body_size 100m;
    }

    # Prometheus 指标 - 仅限 localhost
    location /metrics {
        proxy_pass http://127.0.0.1:8080;
        allow 127.0.0.1;
        deny all;
    }
}
```

#### 启用和测试

```bash
# 启用站点
sudo ln -s /etc/nginx/sites-available/mibee-steward /etc/nginx/sites-enabled/

# 测试配置
sudo nginx -t

# 重启 nginx
sudo systemctl restart nginx
```

#### SSL 证书设置

**使用 Let's Encrypt 和 Certbot：**
```bash
# 安装 certbot
sudo apt install certbot python3-certbot-nginx

# 请求证书
sudo certbot --nginx -d your-domain.com

# 自动续订
sudo crontab -e
# 添加：0 12 * * * /usr/bin/certbot renew --quiet
```

### 4. 备份策略

#### 备份脚本

`scripts/backup.sh` 脚本提供安全的 SQLite 备份：

```bash
#!/usr/bin/env bash
# 用法: ./scripts/backup.sh [数据库路径] [备份目录] [保留天数]

# 默认参数
DB_PATH="${1:-./data/mibee.db}"
BACKUP_DIR="${2:-./data/backups}"
RETENTION_DAYS="${3:-7}"

# 确保备份目录存在
mkdir -p "$BACKUP_DIR"

# 生成基于时间戳的文件名
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/mibee-${TIMESTAMP}.db"

# 检查数据库是否存在
if [ ! -f "$DB_PATH" ]; then
    echo "错误: 数据库文件未找到: $DB_PATH" >&2
    exit 1
fi

# 执行安全备份（无数据库锁定）
echo "正在备份 ${DB_PATH} 到 ${BACKUP_FILE}..."
sqlite3 "$DB_PATH" ".backup '${BACKUP_FILE}'"

# 验证备份完整性
if sqlite3 "$BACKUP_FILE" "PRAGMA integrity_check;" | grep -q "ok"; then
    SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    echo "备份成功完成: ${BACKUP_FILE} (${SIZE})"
else
    echo "错误: 备份完整性检查失败: ${BACKUP_FILE}" >&2
    rm -f "$BACKUP_FILE"
    exit 1
fi

# 删除旧备份
find "$BACKUP_DIR" -name "mibee-*.db" -mtime +"$RETENTION_DAYS" -delete -print | wc -l
```

#### 定期备份

**Systemd/Cron：**
```bash
# 复制备份脚本
sudo cp scripts/backup.sh /opt/mibee-steward/

# 设置权限
sudo chmod +x /opt/mibee-steward/scripts/backup.sh
sudo chown mibee:mibee /opt/mibee-steward/scripts/backup.sh

# 每天凌晨 2 点备份
sudo crontab -e
# 添加：0 2 * * * /opt/mibee-steward/scripts/backup.sh /opt/mibee-steward/data/mibee.db /opt/mibee-steward/data/backups 30
```

#### 恢复过程

```bash
# 停止服务
sudo systemctl stop mibee-steward

# 恢复数据库
sqlite3 /opt/mibee-steward/data/mibee.db < /path/to/backup/mibee-20240101_120000.db

# 启动服务
sudo systemctl start mibee-steward
```

### 5. 监控

#### 健康检查

**服务健康状态：**
```bash
# 检查服务状态
curl -s http://localhost:8080/api/v1/health
# 响应: {"status":"ok","db":"ok","version":"0.1.0"}
```

**Prometheus 指标：**
```bash
# 查看指标（仅限 localhost 通过 nginx）
curl -s http://localhost:8080/metrics
```

**关键指标：**
- `mibee_devices_total`: 设备总数
- `mibee_heartbeat_checks_total`: 执行的心跳检查总数
- `mibee_heartbeat_latency_seconds`: 心跳检查延迟

#### 日志监控

**Systemd 日志：**
```bash
# 查看服务日志
sudo journalctl -u mibee-steward -f

# JSON 格式日志（推荐）
sudo journalctl -u mibee-steward -f -o json
```

#### 监控仪表板

嵌入式 SvelteKit SPA 提供：
- 实时设备状态仪表板
- 心跳监控图表
- 系统性能指标
- 设备运行时间统计

## 配置参考

### 关键生产环境设置

| 设置 | 描述 | 推荐值 |
|---------|-------------|------------------|
| `auth.jwt_secret` | JWT 签名密钥 | `openssl rand -base64 32` |
| `auth.initial_admin_password` | 初始管理员密码 | 强密码（12+ 字符） |
| `server.port` | 服务端口 | `8080` |
| `server.host` | 监听地址 | `0.0.0.0` |
| `database.sqlite.path` | 数据库路径 | `./data/mibee.db` |
| `log.level` | 日志级别 | `info` |
| `log.format` | 日志格式 | `json` |
| `storage.max_file_size` | 最大上传大小 | `104857600` (100MB) |

### 环境变量

所有配置都可以使用 `MIBEE_` 前缀的环境变量覆盖：

```bash
export MIBEE_SERVER_PORT=8080
export MIBEE_AUTH_JWT_SECRET="your-secret-here"
export MIBEE_AUTH_INITIAL_ADMIN_PASSWORD="your-password"
export MIBEE_LOG_LEVEL=info
export MIBEE_AUTH_COOKIE_SECURE=true
```

## 安全最佳实践

1. **更改默认密码**: 始终更改默认的管理员密码
2. **保护 JWT 密钥**: 使用 `openssl rand -base64 32` 生成强 JWT 密钥
3. **使用 HTTPS**: 使用 Let's Encrypt 或其他证书配置 SSL/TLS
4. **限制指标访问`: 配置 nginx 只允许 localhost 访问 `/metrics`
5. **定期备份**: 实施自动化每日备份
6. **监控日志**: 设置日志监控和警报
7. **防火墙配置**: 仅开放必要端口（80, 443）
8. **安全更新**: 保持系统包更新

## 故障排除

### 常见问题

**服务无法启动：**
```bash
# 检查服务状态
sudo systemctl status mibee-steward

# 查看详细日志
sudo journalctl -u mibee-steward --no-pager -n 100

# 检查配置语法
sudo -u mibee /opt/mibee-steward/mibee-steward --check-config
```

**数据库连接问题：**
```bash
# 检查数据库权限
ls -la /opt/mibee-steward/data/

# 验证数据库表
sqlite3 /opt/mibee-steward/data/mibee.db ".tables"

# 数据库模式在应用启动时自动执行
sudo -u mibee /opt/mibee-steward/mibee-steward
```

**Nginx 配置错误：**
```bash
# 测试 nginx 配置
sudo nginx -t

# 检查错误日志
sudo tail -f /var/log/nginx/error.log
```

**性能问题：**
```bash
# 监控资源使用
htop

# PProf 分析
curl -s http://localhost:8080/debug/pprof/heap > heap.prof
go tool pprof heap.prof
```

## 支持

获取额外支持：
- 项目文档: https://github.com/Mi-Bee-Studio/MiBeeSteward
- 问题跟踪器: https://github.com/Mi-Bee-Studio/MiBeeSteward/issues
- 邮件支持: support@example.com