# 快速开始指南

本指南将帮助您在几分钟内启动 MiBee Steward。按照这些步骤设置开发环境并运行您的第一个监控系统。

## 前置条件

- Go 1.26+ 
- Node.js 20+
- Git

## 安装

### 1. 克隆仓库

```bash
git clone https://github.com/Mi-Bee-Studio/MiBeeSteward.git
cd mibee-steward
```

### 2. 安装前端依赖

前端使用 SvelteKit 构建，需要 Node.js 依赖：

```bash
cd web
npm install
cd ..
```

### 3. 配置应用

复制示例配置文件并进行自定义：

```bash
cp configs/config.example.yaml configs/config.yaml
```

根据需要编辑 `configs/config.yaml`，但默认值适用于开发：
- 服务器在端口 8080 运行
- SQLite 数据库在 `./data/mibee.db` 创建
- Prometheus 指标已启用

### 4. 启动开发模式

同时启动前端和后端开发模式：

```bash
make dev
```

此命令：
- 在后台启动 SvelteKit 前端
- 启动 Go 后端服务器
- 前端和后端更改的热重载

## 首次运行

### 5. 访问应用

打开浏览器并导航到：

```
http://localhost:8080
```

### 6. 首次登录

使用您配置的管理员凭据登录：
- **用户名**: `admin`
- **密码**: `config.yaml` 中 `auth.initial_admin_password` 的值

### 7. 修改密码（关键）

首次登录后：
1. 导航到用户资料或设置
2. 立即更改管理员密码
3. **生产环境中切勿使用默认密码**

## 可用命令

### 开发命令

```bash
# 启动开发服务器（前端 + 后端）
make dev

# 运行测试
make test

# 清理构建产物
make clean
```

### 构建命令

```bash
# 为生产环境构建（先前端，后后端）
make build

# 交叉编译到多个平台
make build-all              # linux amd64 + arm64
make build-linux-amd64      # 仅 linux amd64  
make build-linux-arm64      # 仅 linux arm64

# 仅构建前端
make build-frontend

# 仅构建服务器
make build-server
```

### 前端命令

```bash
# 启动前端开发服务器
cd web && npm run dev

# 为生产环境构建前端
cd web && npm run build
```

### 数据库命令

```bash
# 更改 db/queries/*.sql 后生成数据库查询
sqlc generate
```

## 访问点

运行后，您可以访问：

### Web 界面
- **主仪表板**: http://localhost:8080
- 使用管理员凭据登录

### API 端点
- **健康检查**: http://localhost:8080/api/v1/health
- **API 文档**: http://localhost:8080/api/v1/docs（如果可用）
- **指标**: http://localhost:8080/metrics（Prometheus 格式）

### 开发功能
- **热重载**: 前端在文件更改时自动重载
- **开发者工具**: 在 http://localhost:8080 可用
- **API 测试**: 对健康端点使用 curl 或 Postman

## 配置

### 环境变量

您可以使用 `MIBEE_` 前缀的环境变量覆盖配置：

```bash
# 覆盖服务器端口
export MIBEE_SERVER_PORT=9090

# 覆盖数据库路径
export MIBEE_DATABASE_SQLITE_PATH=/path/to/custom.db

# 覆盖 JWT 密钥
export MIBEE_AUTH_JWT_SECRET=your-secret-key
```

### 配置文件

主配置文件是 `configs/config.yaml`。主要部分：

```yaml
server:
  port: 8080
  host: "0.0.0.0"

database:
  type: "sqlite"
  sqlite:
    path: "./data/mibee.db"

auth:
  jwt_secret: "change-me-in-production"
  initial_admin_password: "change-me"
```

## 后续步骤

1. **添加第一个设备**: 使用 Web 界面添加要监控的网络设备
2. **配置探针**: 为您的设备设置 SNMP、ICMP、TCP 或 HTTP 监控
3. **探索 API**: 查看 `/api/v1/health` 端点和其他 API 端点
4. **设置生产环境**: 按照部署指南进行生产环境设置

## 故障排除

### 端口已在使用中

如果端口 8080 已被占用，可以：
- 终止现有进程：`pkill -f mibee-steward`
- 更改配置中的端口
- 使用环境变量使用不同端口：`export MIBEE_SERVER_PORT=8081`

### 前端构建问题

如果遇到前端构建错误：
- 确保 Node.js 20+ 已安装
- 删除 `web/node_modules` 并再次运行 `npm install`
- 清理 SvelteKit 缓存：`rm -rf web/.svelte-kit`

### 数据库问题

如果数据库创建失败：
- 确保 `data/` 目录存在
- 检查项目目录中的写权限
- 验证 SQLite 是否正常工作：`sqlite3 --version`

## 安全提示

⚠️ **重要安全警告**: 请务必在 `config.yaml` 中将 `auth.initial_admin_password` 设置为强唯一密码。切勿以空密码或默认密码部署。

有关更详细的信息，请参阅完整的 [架构](architecture.md) 和 [配置](configuration.md) 文档。