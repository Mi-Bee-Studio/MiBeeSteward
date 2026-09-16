# RELEASE.md — 发布流程 Checklist

> 适用范围：`v*` 版本发布（GitHub Release，由 `.github/workflows/release.yml` 构建产物）。
> 本文件是流程契约，不是代码 —— 改流程先改这里。

## 背景：历史 tag 的祖先断裂（只防未来，不可修复）

`v0.1.0`–`v0.5.0` 全部 5 个 tag **都不是 `main` 的祖先**（`git merge-base --is-ancestor <tag> main`
逐一失败；v0.5.0 指向的提交与 main 上的 36ee36e 是「同树异提交」双生）。后果：从 main 视角
`git describe` 拿不到任何 tag。历史 tag 已随 Release 发布、**不能移动**——唯一正确动作是
今后不再产生新的断裂 tag（见下面第 3 步的规矩）。

## Checklist（按序执行）

1. **CHANGELOG 定稿**
   - `## [Unreleased]` 重命名为 `## [x.y.z] - YYYY-MM-DD`；
   - 自查类型归位：新能力在 Added、行为变化在 Changed、修复在 Fixed——不要把特性压进
     Fixed 的合并尾行（反例见 #362）；
   - 大特性的 PR（尤其合并提交里带长描述的）逐个核对是否都有条目——历史上 #344 曾整段缺失。

2. **main 上 CI 全绿**
   - `gh pr checks` 确认最后一个合入 PR 的 8 项检查全绿（前端构建 + go vet +
     golangci-lint + go test -race + sqlc verify + windows-build + docker-build + docs）。

3. **tag 打在 main 的精确 SHA 上（强制规矩）**
   ```bash
   git fetch origin && git checkout main && git pull
   SHA=$(git rev-parse origin/main)
   git tag vX.Y.Z "$SHA"          # 绝不对本地分支头/双生提交打 tag
   git push origin vX.Y.Z
   # 或：gh release create vX.Y.Z --target <main 的 SHA> --title ... --notes-file ...
   ```
   - 打完自检：`git merge-base --is-ancestor vX.Y.Z main && echo OK`（必须 OK）。

4. **release.yml 产物核对**
   - 等 Release 构建完成，逐项核对 Assets 与发布说明一致（当前：linux amd64/arm64
     服务器二进制 + GHCR 镜像；OpenWrt 三形态包见 #359，落地后补进本清单）；
   - 每个 artifact 的 SHA256 与本地交叉编译结果抽查一致。

5. **部署验证（真机，不是 is-active）**
   - 按部署流程升级一台真机（如 62.40），然后验证三件事：
     ```bash
     systemctl show mibee-steward -p NRestarts      # 必须为 0
     curl -s http://<host>:8080/api/v1/health        # 版本串 == 刚发的 tag
     journalctl -u mibee-steward --since "-5min" | grep -i error
     ```
   - 历史教训：一个 setsid 启动的幽灵进程占住 8080 时 systemd 崩溃循环，`is-active`
     照样显示 active——**必须**核对 NRestarts 与 /health 实际应答的版本串。

6. **发布后收尾**
   - GitHub Release 页面贴 CHANGELOG 该版本段落；公告/文档按需同步；
   - `git describe --tags` 在 main 上应能解析出新 tag（第 3 步的回归验证）。
