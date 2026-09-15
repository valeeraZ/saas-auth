# saas-auth

身份与授权服务仓库。平台使用 Keycloak 完成认证，Auth 拥有用户映射、租户、成员、邀请和业务角色事实。

当前为 AUTH-02 用户与租户阶段：在机器身份基础上实现用户映射、租户/成员/邀请、角色授权、会话撤销及持久私有任务。20 个契约操作已接入服务；Portal BFF 和生产部署另行集成。

- [用户与租户阶段范围](docs/USER-TENANCY.md)

- [当前运行范围与限制](docs/SERVICE-FOUNDATION.md)
- [跨仓库契约检查](docs/CROSS-REPO-REVIEW.md)
- [本地启动与测试](docs/LOCAL-DEVELOPMENT.md)

- [平台边界 ADR](docs/adr/0001-platform-boundaries.md)
- [Keycloak 决策](docs/adr/0002-identity-provider.md)
- [Auth 契约语义](docs/AUTH-CONTRACT.md)
- [OpenAPI](contracts/openapi.json)
- [租户生命周期事件](contracts/events/tenant-lifecycle.schema.json)

快速启动（Docker Compose）：

```sh
uv sync --frozen
uv run python scripts/prepare_local.py
docker compose up --build -d
curl --fail http://127.0.0.1:58000/health/ready
```

本地随机凭据不会提交；服务许可配置和 uv 验证命令见启动文档。Compose 默认提供机器接口联调；用户 OIDC 协议测试使用独立 HTTPS Keycloak，不代表 Portal 浏览器 UI 或 MFA 已验收。源仓库保持只读；不发布公共包、不部署生产。
