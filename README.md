# saas-auth

身份与授权服务仓库。平台使用 Keycloak 完成认证，Auth 拥有用户映射、租户、成员、邀请和业务角色事实。

当前为 AUTH-02 第一阶段：可运行的机器身份与角色 API，使用 PostgreSQL、FastAPI、Keycloak 签名验证及事务 outbox。完整候选契约的用户/邀请/会话流程仍待实现。

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
python3 scripts/prepare_local.py
docker compose up --build -d
curl --fail http://127.0.0.1:58000/health/ready
```

本地随机凭据不会提交；服务许可配置和 uv 验证命令见启动文档。机器身份测试不代表用户 OIDC、MFA、会话及邀请流程已验收。源仓库保持只读；不发布公共包、不部署生产。
