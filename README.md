# saas-auth

身份与授权服务仓库。平台使用 Keycloak 完成认证，Auth 拥有用户映射、租户、成员、邀请和业务角色事实。

当前交付为 AUTH-01 契约草案，尚无运行中的身份服务。Keycloak 选型及平台部署/应用接入方向已由用户确认；OpenAPI 与事件需跨仓库评审后冻结。

- [平台边界 ADR](docs/adr/0001-platform-boundaries.md)
- [Keycloak 决策](docs/adr/0002-identity-provider.md)
- [Auth 契约语义](docs/AUTH-CONTRACT.md)
- [OpenAPI](contracts/openapi.json)
- [租户生命周期事件](contracts/events/tenant-lifecycle.schema.json)

验证：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-contracts.txt
.venv/bin/python scripts/validate_contracts.py
```

静态校验不代表真实 PostgreSQL、OIDC、MFA、会话撤销或跨租户授权测试通过。下一步为跨仓库契约评审及 AUTH-02 服务实现；不发布公共包、不部署生产。
