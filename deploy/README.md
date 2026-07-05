# MiBee Steward 部署指南

## 概述

MiBee Steward 是一个设备管理和监控系统，采用 Go 后端（Chi + SQLite）与嵌入式 SvelteKit 单页应用（SPA）的架构。支持 SNMP/ICMP/TCP/HTTP 探测、Prometheus 指标收集和心跳监控。

本指南提供了两种部署方案：
- 方案 A：Systemd 部署（推荐用于生产环境）
- 方案 B：Docker 部署（适用于容器化环境）

## 前置条件

### 基础环境
- Linux 系统（Ubuntu 20.04+ 或 CentOS 8+）
- SQLite（通常随 Linux 发行版自带）
- Go 1.26+（如需从源码构建）
- Docker 和 Docker Compose（如选择 Docker 部署）

### 网络要求
- 域名（建议使用，用于 SSL 证书）
- 反向代理（Nginx）
- 防火墙配置（开放 443 端口用于 HTTPS）

### SSL 证书
准备 SSL 证书，推荐使用 Let's Encrypt：
```bash
# 安装 certbot
sudo apt install certbot python3-certbot-nginx

# 申请证书
sudo certbot --nginx -d your-domain.com
```

## 方案 A: Systemd 部署

### 1. 构建或下载二进制文件

**从源码构建（推荐）：**
```bash
# 克隆代码仓库
git clone https://github.com/Mi-Bee-Studio/MiBeeSteward.git
cd mibee-steward

# 构建二进制文件
make build

# 或者交叉编译
make build-all
```

**下载预编译二进制文件：**
```bash
# 下载对应平台的二进制文件
wget https://github.com/Mi-Bee-Studio/MiBeeSteward/releases/latest/download/mibee-steward-linux-amd64
chmod +x mibee-steward-linux-amd64
```

### 2. 创建系统用户

```bash
# 创建 mibee 用户
sudo useradd -r -s /usr/sbin/nologin -d /opt/mibee-steward mibee
```

### 3. 安装程序文件

```bash
# 创建安装目录
sudo mkdir -p /opt/mibee-steward
sudo mkdir -p /opt/mibee-steward/data
sudo mkdir -p /opt/mibee-steward/data/uploads
sudo mkdir -p /opt/mibee-steward/data/backups
sudo mkdir -p /opt/mibee-steward/configs

# 复制二进制文件
sudo cp mibee-steward /opt/mibee-steward/
sudo cp -r configs/* /opt/mibee-steward/configs/

# 设置文件权限
sudo chown -R mibee:mibee /opt/mibee-steward
sudo chmod +x /opt/mibee-steward/mibee-steward
```

### 4. 配置生产环境文件

```bash
# 复制生产配置模板
sudo cp /opt/mibee-steward/configs/config.production.yaml /opt/mibee-steward/configs/config.yaml

# 编辑配置文件
sudo nano /opt/mibee-steward/configs/config.yaml
```

**重要配置项：**
- `auth.jwt_secret`: 生成安全的密钥：`openssl rand -base64 32`
- `auth.initial_admin_password`: 设置强密码
- 根据需要调整其他配置项

### 5. 安装 Systemd 服务

```bash
# 复制服务文件
sudo cp deploy/mibee-steward.service /etc/systemd/system/

# 重新加载 systemd
sudo systemctl daemon-reload

# 启用服务
sudo systemctl enable mibee-steward
sudo systemctl start mibee-steward

# 检查服务状态
sudo systemctl status mibee-steward
```

### 6. 配置 Nginx 反向代理

```bash
# 复制 nginx 配置
sudo cp deploy/nginx.conf /etc/nginx/sites-available/mibee-steward

# 创建软链接启用站点
sudo ln -s /etc/nginx/sites-available/mibee-steward /etc/nginx/sites-enabled/

# 测试 nginx 配置
sudo nginx -t

# 重启 nginx
sudo systemctl restart nginx
```

**配置说明：**
- 确保 SSL 证书路径正确
- 根据 domain 修改 `server_name`
- 确保代理设置正确

### 7. 设置 SSL 证书

```bash
# 使用 Let's Encrypt 申请证书
sudo certbot --nginx -d your-domain.com

# 自动续期设置
sudo crontab -e
# 添加以下行（每月执行一次）
0 12 * * * /usr/bin/certbot renew --quiet
```

### 8. 启动服务

```bash
# 重启服务
sudo systemctl restart mibee-steward

# 检查服务状态
sudo systemctl status mibee-steward

# 查看日志
sudo journalctl -u mibee-steward -f
```

### 9. 设置备份计划

```bash
# 复制备份脚本
sudo cp scripts/backup.sh /opt/mibee-steward/

# 设置脚本权限
sudo chmod +x /opt/mibee-steward/scripts/backup.sh
sudo chown mibee:mibee /opt/mibee-steward/scripts/backup.sh

# 设置每日备份（凌晨 2 点执行）
sudo crontab -e
# 添加以下行
0 2 * * * /opt/mibee-steward/scripts/backup.sh /opt/mibee-steward/data/mibee.db /opt/mibee-steward/data/backups 30
```

## 方案 B: Docker 部署

### 1. 准备配置文件

```bash
# 创建部署目录
mkdir -p ~/mibee-steward-deploy
cd ~/mibee-steward-deploy

# 复制配置文件
cp /path/to/mibee-steward/configs/config.production.yaml ./config.yaml

# 编辑配置文件
nano config.yaml
```

### 2. 准备 Docker Compose 文件

```bash
# 复制 docker-compose.yml
cp /path/to/mibee-steward/docker-compose.yml .

# 编辑 docker-compose.yml（如需要）
nano docker-compose.yml
```

### 3. 构建和启动服务

```bash
# 构建 Docker 镜像
docker compose build

# 启动服务
docker compose up -d

# 检查服务状态
docker compose ps
docker compose logs -f
```

### 4. 配置 Nginx 反向代理（同方案 A）

参考方案 A 的第 6 步配置 Nginx 反向代理。

### 5. 设置备份计划（Docker 环境）

```bash
# 创建备份目录
mkdir -p ~/mibee-steward-backups

# 设置 Docker 容器内的备份任务
docker compose exec mibee-steward bash -c "cd /app && ./scripts/backup.sh /app/data/mibee.db /app/data/backups 30"

# 或者设置宿主机上的备份脚本
echo '#!/bin/bash
DB_PATH="/home/$(whoami)/mibee-steward-deploy/data/mibee.db"
BACKUP_DIR="/home/$(whoami)/mibee-steward-backups"
docker compose exec mibee-steward bash -c "cd /app && sqlite3 \"\$DB_PATH\" \".backup '/tmp/backup.db'\""
docker cp mibee-steward:/tmp/backup.db "${BACKUP_DIR}/mibee-$(date +%Y%m%d_%H%M%S).db"
rm /tmp/backup.db
' > ~/backup-mibee-docker.sh
chmod +x ~/backup-mibee-docker.sh

# 添加到 crontab
echo "0 2 * * * /home/$(whoami)/backup-mibee-docker.sh" | crontab -
```

## 配置说明

### 关键配置项

| 配置项 | 说明 | 生产环境推荐值 |
|--------|------|----------------|
| `auth.jwt_secret` | JWT 签名密钥 | 使用 `openssl rand -base64 32` 生成 |
| `auth.initial_admin_password` | 首次管理员密码 | 强密码，至少 12 位 |
| `server.port` | 服务端口 | 8080 |
| `server.host` | 监听地址 | `0.0.0.0` |
| `database.sqlite.path` | 数据库路径 | `./data/mibee.db` |
| `log.level` | 日志级别 | `info` |
| `log.format` | 日志格式 | `json` |
| `storage.upload_path` | 上传目录 | `./data/uploads` |
| `storage.max_file_size` | 最大文件大小 | `104857600` (100MB) |
| `rate_limit.login_per_minute` | 登录限制 | `10` |
| `rate_limit.global_per_minute` | 全局限制 | `100` |

### 环境变量配置

除了配置文件，还可以通过环境变量覆盖配置：

```bash
# 示例环境变量
export MIBEE_SERVER_PORT=8080
export MIBEE_AUTH_JWT_SECRET="your-secret-here"
export MIBEE_AUTH_INITIAL_ADMIN_PASSWORD="your-password"
```

## 备份恢复

### 备份操作

```bash
# 使用内置备份脚本
./scripts/backup.sh

# 指定数据库路径和备份目录
./scripts/backup.sh /path/to/db /path/to/backups 30
```

### 恢复操作

```bash
# 停止服务
sudo systemctl stop mibee-steward

# 恢复数据库
sqlite3 ./data/mibee.db < /path/to/backup/mibee-20240101_120000.db

# 启动服务
sudo systemctl start mibee-steward
```

## 监控

### 健康检查

```bash
# 检查服务状态
curl -s http://localhost:8080/api/v1/health
# 响应: {"status":"ok","db":"ok","version":"0.1.0"}
```

### Prometheus 指标

```bash
# 查看指标（仅限本地访问）
curl -s http://localhost:8080/metrics
```

### 日志监控

```bash
# 查看 systemd 服务日志
sudo journalctl -u mibee-steward -f

# 查看 JSON 格式日志（推荐）
sudo journalctl -u mibee-steward -f -o json
```

## 故障排查

### 常见问题

#### 1. 服务无法启动
```bash
# 检查服务状态
sudo systemctl status mibee-steward

# 查看详细错误日志
sudo journalctl -u mibee-steward --no-pager -n 100

# 检查配置文件语法
sudo -u mibee /opt/mibee-steward/mibee-steward --check-config
```

#### 2. 数据库连接失败
```bash
# 检查数据库文件权限
ls -la /opt/mibee-steward/data/

# 检查数据库文件
sqlite3 /opt/mibee-steward/data/mibee.db ".tables"

# 重新运行数据库迁移
# 检查数据库文件完整性
sqlite3 /opt/mibee-steward/data/mibee.db ".schema devices" > /dev/null 2>&1

# 数据库模式在启动时自动应用，无需手动迁移
```

#### 3. Nginx 配置错误
```bash
# 检查 nginx 配置
sudo nginx -t

# 查看 nginx 错误日志
sudo tail -f /var/log/nginx/error.log
```

#### 4. SSL 证书问题
```bash
# 检查证书有效期
sudo openssl x509 -in /etc/nginx/ssl/cert.pem -text -noout

# 重新申请证书
sudo certbot --nginx --force-renewal
```

#### 5. 性能问题
```bash
# 查看资源使用情况
htop

# 查看 PProf 堆栈分析
curl -s http://localhost:8080/debug/pprof/heap > heap.prof
go tool pprof heap.prof
```

### 调试模式

启用调试模式以便详细排查问题：
```bash
# 设置日志级别为 debug
sudo sed -i 's/level: "info"/level: "debug"/' /opt/mibee-steward/configs/config.yaml

# 重启服务
sudo systemctl restart mibee-steward
```

### 维护模式

进入维护模式进行维护操作：
```bash
# 创建维护页面
echo "MiBee Steward is under maintenance" | sudo tee /opt/mibee-steward/data/maintenance.html

# 配置 Nginx 显示维护页面
# 在 nginx.conf 中添加 location / { return 503; }

# 退出维护模式
sudo rm -f /opt/mibee-steward/data/maintenance.html
```

## 安全建议

1. **定期更新密码**：定期更改管理员密码
2. **监控日志**：设置日志监控和告警
3. **防火墙配置**：只开放必要的端口
4. **定期备份**：设置自动备份计划
5. **SSL 证书**：定期更新 SSL 证书
6. **访问控制**：限制对 `/metrics` 端口的访问
7. **安全扫描**：定期进行安全漏洞扫描

## 性能优化

1. **数据库优化**：
   - 定期执行 VACUUM
   - 考虑使用 SQLite 的 PRAGMA 优化设置

2. **缓存配置**：
   - 配置浏览器缓存
   - 考虑实现 Redis 缓存

3. **负载均衡**：
   - 多实例部署
   - 使用负载均衡器

## 支持

如遇到问题，请参考：
- 项目文档：https://github.com/Mi-Bee-Studio/MiBeeSteward
- Issue 跟踪：https://github.com/Mi-Bee-Studio/MiBeeSteward/issues
- 邮件支持：support@example.com