# MiBee Steward 开发指南

本指南为 MiBee Steward 项目的完整贡献说明，涵盖开发环境设置、项目结构、常见开发任务和编码规范。

## 开发环境设置

### 启动开发环境

`make dev` 命令启动前端和后端并支持热重载：

```bash
# 首先安装依赖
cd web && npm install
cd ..

# 启动开发服务器（前端 + 后端）
make dev
```

这会运行：
- 前端：端口 5173 上的 `npm run dev`
- 后端：端口 8080 上的 `go run cmd/server/main.go`
- 前端和后端都启用了热重载

### 生产环境构建

```bash
# 构建前端和后端
make build

# 交叉编译到多个平台
make build-all              # linux amd64 + arm64
make build-linux-arm64      # 仅 arm64
```

## 项目结构

```
.
├── cmd/server/           # 入口点 — main.go
├── configs/              # YAML 配置（koanf）
├── db/                   # schema.sql + sqlc 查询 → internal/db/
├── internal/
│   ├── api/             # HTTP 层（Chi）：处理器、中间件、路由
│   ├── config/          # 配置加载（koanf/v2）
│   ├── db/              # ⚡ 由 sqlc 生成 — 请勿编辑
│   ├── domain/          # 领域模型（设备、用户、文档）
│   ├── repository/      # 数据访问（封装 sqlc 生成的代码）
│   └── service/         # 业务逻辑 + 探测子系统
├── web/                 # SvelteKit 5 SPA → 通过 go:embed 嵌入
├── deploy/              # Systemd 服务、nginx、Docker 配置
├── scripts/              # backup.sh（SQLite 备份与完整性检查）
└── tests/integration/
```

### 关键架构层

- **领域层** (`internal/domain/`)：DTO、常量、请求/响应模型
- **仓储层** (`internal/repository/`)：数据访问（可选的 sqlc 包装器）
- **服务层** (`internal/service/`)：业务逻辑、探测子系统
- **处理器层** (`internal/api/handler/`)：HTTP 请求处理、响应格式化

## 如何添加 API 端点

按照以下步骤添加新的 API 端点：

### 1. 定义请求/响应 DTO

在 `internal/domain/` 中创建或更新领域模型：

```go
// internal/domain/your_domain.go
type CreateYourResourceRequest struct {
    Name        string `json:"name" validate:"required"`
    Description string `json:"description" validate:"max:255"`
}

type UpdateYourResourceRequest struct {
    Name        *string `json:"name"`
    Description *string `json:"description"`
}

type YourResourceResponse struct {
    ID          int64     `json:"id"`
    Name        string    `json:"name"`
    Description string    `json:"description"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}
```

### 2. 创建 sqlc 查询

在 `db/queries/your_resource.sql` 中添加 SQL 查询：

```sql
-- db/queries/your_resource.sql
-- name: CreateYourResource :one
INSERT INTO your_resources (name, description) 
VALUES ($1, $2) 
RETURNING *;

-- name: GetYourResource :one
SELECT * FROM your_resources WHERE id = $1;

-- name: ListYourResources :many
SELECT * FROM your_resources ORDER BY created_at DESC;
```

### 3. 生成 sqlc 代码

运行 sqlc 生成 Go 代码：

```bash
~/go/bin/sqlc generate
```

生成的代码出现在 `internal/db/` 中。

### 4. 添加服务方法

在 `internal/service/your_service.go` 中创建服务方法：

```go
// internal/service/your_service.go
type YourService struct {
    db *sqlc.Queries
}

func NewYourService(db *sqlc.Queries) *YourService {
    return &YourService{db: db}
}

func (s *YourService) CreateYourResource(ctx context.Context, req domain.CreateYourResourceRequest) (*domain.YourResourceResponse, error) {
    dbRes, err := s.db.CreateYourResource(ctx, req.Name, req.Description)
    if err != nil {
        return nil, fmt.Errorf("failed to create resource: %w", err)
    }
    return s.toYourResourceResponse(dbRes), nil
}
```

### 5. 创建处理器

在 `internal/api/handler/your_handler.go` 中创建处理器：

```go
// internal/api/handler/your_handler.go
type YourHandler struct {
    service *service.YourService
}

func NewYourHandler(service *service.YourService) *YourHandler {
    return &YourHandler{service: service}
}

func (h *YourHandler) CreateYourResource(w http.ResponseWriter, r *http.Request) {
    var req domain.CreateYourResourceRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        response.Error(w, http.StatusBadRequest, "Invalid request body")
        return
    }

    res, err := h.service.CreateYourResource(r.Context(), req)
    if err != nil {
        response.Error(w, http.StatusInternalServerError, err.Error())
        return
    }

    response.Created(w, res)
}
```

### 6. 注册路由

在 `internal/api/routes/routes.go` 中添加路由：

```go
// internal/api/routes/routes.go
func (r *Router) setupRoutes() {
    // ... 现有路由
    
    yourHandler := handler.NewYourHandler(service.NewYourService(r.db))
    
    r.router.Group(func(r chi.Router) {
        r.Use(middleware.RequireAuth)
        r.Post("/your-resources", yourHandler.CreateYourResource)
        r.Get("/your-resources", yourHandler.ListYourResources)
    })
}
```

## 如何添加数据库查询

### sqlc 工作流

1. **在 `db/queries/*.sql` 中编写查询**：
```sql
-- db/queries/your_table.sql
-- name: GetYourData :one
SELECT * FROM your_table WHERE id = $1;
```

2. **运行 sqlc generate**：
```bash
~/go/bin/sqlc generate
```

3. **在服务中使用生成的代码**：
```go
// internal/service/your_service.go
func (s *YourService) GetYourData(ctx context.Context, id int64) (*db.YourData, error) {
    return s.db.GetYourData(ctx, id)
}
```

### 迁移工作流

1. **在 `db/schema.sql` 中编辑数据库模式**：
```sql
-- db/schema.sql
CREATE TABLE your_table (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

2. **运行 sqlc 生成类型安全的 Go 代码**：
```bash
~/go/bin/sqlc generate
```

数据库模式在应用启动时自动从嵌入的 schema.sql 执行。

## 如何添加前端页面

### 1. 创建路由文件

使用基于文件的路由创建 SvelteKit 路由：

```svelte
<!-- web/src/routes/your-feature/+page.svelte -->
<script lang="ts">
    import { api } from '$lib/api/client';
    import { onMount } from 'svelte';
    
    let items = [];
    let loading = false;
    let error = null;
    
    onMount(async () => {
        loading = true;
        try {
            items = await api.get('/your-resources')();
        } catch (err) {
            error = err.message;
        } finally {
            loading = false;
        }
    });
</script>

<h1>Your Feature</h1>

{#if loading}
    <p>Loading...</p>
{:else if error}
    <p class="error">{error}</p>
{:else}
    <ul>
        {#each items as item (item.id)}
            <li>{item.name}</li>
        {/each}
    </ul>
{/if}
```

### 2. 使用 API 客户端

使用 `$lib/api/client.ts` 中的包装 API 客户端：

```typescript
// 使用自动 401 处理的通用 API 调用
const data = await api.get<T>(path)();
const created = await api.post<T>(path)(data);
const updated = await api.put<T>(path)(data);
const deleted = await api.delete(path)();
```

### 3. 添加 i18n 翻译

更新翻译文件：

```json
// web/messages/en.json
{
    "yourFeature": {
        "title": "Your Feature",
        "loading": "Loading...",
        "error": "Failed to load data"
    }
}
```

```json
// web/messages/zh.json
{
    "yourFeature": {
        "title": "您的功能",
        "loading": "加载中...",
        "error": "加载数据失败"
    }
}
```

### 4. 在组件中使用 i18n

使用翻译函数：

```svelte
<h1>{t('yourFeature', 'title')}</h1>
<p>{t('yourFeature', loading ? 'loading' : 'error')}</p>
```

## 如何添加探测类型

### 1. 创建探测实现

在 `internal/service/probe/your_probe.go` 中实现 `Prober` 接口：

```go
// internal/service/probe/your_probe.go
type YourProbe struct {
    // 添加探测特定配置
}

func (p *YourProbe) Probe(ctx context.Context, target string, timeout time.Duration) (*ProbeResult, error) {
    ctx, cancel := context.WithTimeout(ctx, timeout)
    defer cancel()
    
    // 实现您的探测逻辑
    // 返回带有状态、持续时间和错误的 ProbeResult
    return &ProbeResult{
        Status:   ProbeStatusSuccess,
        Duration: time.Since(start),
        Output:   "Probe output",
    }, nil
}
```

### 2. 在心跳服务中注册

更新 `internal/service/heartbeat.go` 中的 `GetProber()` 开关：

```go
// internal/service/heartbeat.go
func (h *HeartbeatService) GetProber(method string) (Prober, error) {
    switch method {
    case "icmp":
        return NewICMPProber(h.config.ICMPTimeout), nil
    case "tcp":
        return NewTCPProber(h.config.TCPTimeout), nil
    case "http":
        return NewHTTPProber(h.config.HTTPTimeout), nil
    case "snmp":
        return NewSNMPProber(h.config.SNMPCommunity), nil
    case "your-probe":
        return &YourProbe{}, nil
    default:
        return nil, fmt.Errorf("unknown probe method: %s", method)
    }
}
```

### 3. 更新配置

在配置中添加探测类型：

```yaml
# configs/config.example.yaml
heartbeat:
  probes:
    - name: "your-probe"
      method: "your-probe"
      target: "your-target.example.com"
      interval: 30
      timeout: 10
```

## 如何添加扫描器协议（v2 引擎）

v2 扫描器是插件式的：新增一个协议（例如 MQTT 检测）只需一对**分类器 + 处理器**，启动时注册即可。编排层和持久化层无需改动。

### 1. 添加 ProbeSource（若协议需要主动探测）

若新协议无法从既有 TCP/banner 探针识别，在 `internal/service/scannerv2/probe/` 添加一个 `ProbeSource`：

```go
// internal/service/scannerv2/probe/mqtt.go
type MQTTProbe struct{}
func (p *MQTTProbe) Name() string { return "active:mqtt" }
func (p *MQTTProbe) Probe(ctx context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
    // 连接 1883 端口，发 CONNECT 包，产出 Evidence{Kind:"mqtt_banner",...}
}
```
在 `probe.DefaultProbeSources()` 注册。若协议仅靠既有 banner 证据即可识别，跳过本步。

### 2. 添加 ServiceClassifier

在 `internal/service/scannerv2/classify/mqtt.go` 创建纯函数分类器，看到匹配证据时产出 `ServiceIdentity`：

```go
type MQTTClassifier struct{}
func (MQTTClassifier) Service() string { return "mqtt" }
func (MQTTClassifier) Classify(ev []scannerv2.Evidence) []scannerv2.ServiceIdentity {
    // 扫描 ev 中 kind=="banner" 且含 MQTT 魔术字节的 → 产出 identity
}
```
在 `classify.DefaultClassifiers()` 注册。

### 3. 添加 ServiceHandler（可选，用于心跳/enrich）

若该服务需要定制心跳或设备字段补充，在 `internal/service/scannerv2/handler/mqtt.go` 实现 `GenerateHeartbeat`、`Collect`（可返回 `Trigger` 触发级联）、`EnrichDevice`。在 `handler.DefaultHandlers()` 注册。若仅需检测（无需心跳/enrich），跳过本步。

### 4. 测试

单元测试与源码同目录（`*_test.go`），探针用 `net.Listen` / `httptest` mock，分类器为纯函数测试。运行 `go test ./internal/service/scannerv2/...`。

## 测试规范

### 测试设置

使用 `testify/require` 断言和内存 SQLite：

```go
// tests/integration/your_test.go
package integration

import (
    "testing"
    "github.com/stretchr/testify/require"
    
    "github.com/Mi-Bee-Studio/MiBeeSteward/internal/service"
)

func TestYourService_CreateYourResource(t *testing.T) {
    // 设置内存 SQLite
    db, err := sql.Open("sqlite", ":memory:")
    require.NoError(t, err)
    defer db.Close()
    
    // 设置测试数据库
    db := testutil.SetupTestDBFromSchema()
    
    // 创建服务
    svc := service.NewYourService(db)
    
    // 测试
    req := domain.CreateYourResourceRequest{
        Name:        "Test Resource",
        Description: "Test description",
    }
    
    res, err := svc.CreateYourResource(context.Background(), req)
    require.NoError(t, err)
    require.NotZero(t, res.ID)
}
```

### 使用 httptest.Server 的集成测试

```go
func TestYourHandler_CreateYourResource(t *testing.T) {
    // 设置测试服务器
    server := httptest.NewServer(router.Setup())
    defer server.Close()
    
    // 测试客户端
    client := server.Client()
    
    // 测试数据
    req := domain.CreateYourResourceRequest{
        Name:        "Test Resource",
        Description: "Test description",
    }
    
    // 发送 HTTP 请求
    resp, err := client.Post(server.URL+"/your-resources", "application/json", 
        bytes.NewReader(jsonEncode(req)))
    require.NoError(t, err)
    defer resp.Body.Close()
    
    // 验证响应
    require.Equal(t, http.StatusCreated, resp.StatusCode)
    
    var res domain.YourResourceResponse
    require.NoError(t, jsonDecode(resp.Body, &res))
    require.NotZero(t, res.ID)
}
```

### 测试助手

为测试助手使用 `t.Helper()`：

```go
func requireJSONResponse(t *testing.T, resp *http.Response, expectedStatus int) {
    t.Helper()
    require.Equal(t, expectedStatus, resp.StatusCode)
    
    if expectedStatus >= 200 && expectedStatus < 300 {
        var body map[string]interface{}
        require.NoError(t, jsonDecode(resp.Body, &body))
    } else {
        var errResp map[string]string
        require.NoError(t, jsonDecode(resp.Body, &errResp))
        require.Contains(t, errResp, "error")
    }
}
```

## 代码风格与反模式

### 关键反模式

**永远不要编辑 `internal/db/*.go`** — 它们是 sqlc 生成的。编辑 `db/queries/*.sql` 然后重新生成。

**永远不要使用 CGO_ENABLED=1** — 使用 modernc.org/sqlite。

**永远不要从处理器中调用仓储** — 始终使用服务层。

**永远不要在 `routes/routes.go` 之外注册路由** — 保持路由集中化。

**永远不要绕过身份验证中间件** 用于受保护的端点。

**永远不要在 .ts 文件中使用 `$state` 运算符** — 只在 .svelte 文件中使用。

**永远不要硬编码 API URL** — 使用 `PUBLIC_API_URL` 环境变量。

### 请求 DTO 模式

**CreateXRequest**（必需字段）：
```go
type CreateUserRequest struct {
    Username string `json:"username" validate:"required,min:3,max:255"`
    Email    string `json:"email" validate:"required,email"`
    Password string `json:"password" validate:"required,min:8"`
}
```

**UpdateXRequest**（用于部分更新的指针字段）：
```go
type UpdateUserRequest struct {
    Username *string `json:"username"`
    Email    *string `json:"email"`
    Password *string `json:"password"`
}
```

### 错误处理

服务返回类型化错误：
```go
func (s *YourService) YourMethod(ctx context.Context, id int64) error {
    // ...
    if notFound {
        return domain.ErrYourResourceNotFound
    }
    // ...
}
```

处理器转换为 HTTP 状态码：
```go
func (h *YourHandler) YourMethod(w http.ResponseWriter, r *http.Request) {
    // ...
    if errors.Is(err, domain.ErrYourResourceNotFound) {
        response.Error(w, http.StatusNotFound, "Resource not found")
        return
    }
    // ...
}
```

### 响应格式

始终使用 JSON，snake_case 字段和 ISO 8601 时间戳：

```json
{
    "id": 123,
    "name": "Resource Name",
    "created_at": "2026-01-15T10:30:00Z",
    "updated_at": "2026-01-15T10:30:00Z"
}
```

### 测试技巧

- 使用 `t.Cleanup()` 进行资源清理
- 同时测试成功和错误情况
- 使用 `httptest.Server` 进行集成测试
- 遵循 `testify/require` 断言模式

## 开发命令

```bash
# 开发
make dev                    # 启动前端 + 后端并热重载

# 构建
make build                 # 先构建前端，然后构建后端
make build-all             # 交叉编译（linux amd64 + arm64）

# 测试
go test ./...              # 运行所有测试
make test                  # 运行集成测试

# 数据库
~/go/bin/sqlc generate    # 查询更改后重新生成 sqlc 代码

# 仅前端
cd web && npm run dev     # 启动前端开发
cd web && npm run build   # 构建生产环境前端
```

## 安全说明

- 通过 `auth.initial_admin_password` 设置强管理员密码 — **生产环境必须设置**
- 使用 `.env` 文件存储密钥，永远不要提交它们
- SQLite 使用 WAL 模式以获得更好的性能
- 所有功能测试必须在测试服务器（your-test-server）上执行

## 贡献工作流

1. Fork 仓库
2. 创建功能分支
3. 遵循这些约定进行更改
4. 为新功能添加测试
5. 运行 `make test` 确保一切正常
6. 提交 pull request

## 获取帮助

- 阅读 [AGENTS.md](../../AGENTS.md) 文件获取详细的项目知识
- 查看现有代码了解模式和约定
- 在仓库问题中提问