# ADR-0002：身份组件选型

状态：已接受。用户选择平台托管 Keycloak，接受 Operator 运维并继续提供 Helm；不锁定具体发布版本。

| 维度 | Keycloak | ZITADEL |
| --- | --- | --- |
| 自助登录与恢复 | 注册、邮件验证、密码恢复可配置 | 提供登录及身份管理能力 |
| 企业身份与 MFA | OIDC/SAML 身份代理、OTP/WebAuthn 等 | OIDC/SAML、OTP/Passkeys 等 |
| Kubernetes | 官方 Operator；数据库需独立提供 | 官方 Helm 部署文档，需明确代理 HTTP/2/h2c 配置 |
| 平台组织模型 | 不将 realm/上游组织直接等同业务租户 | 不将供应商 organization 直接等同业务租户 |
| 本项目适配成本（判断） | 需提供 Operator 生命周期与 Helm 编排说明 | 需映射其组织/项目模型，评估现有 API 耦合 |

采用 Keycloak：由平台运维成熟身份服务，Auth 持有自己的稳定 user_id 与业务组织模型，用 issuer + subject 映射上游身份。密码、MFA 凭据、恢复流程交给组件，SDK/业务数据库不存密码。

平台提供 Helm 不等于所有依赖必须以第三方 chart 管理：若选择 Keycloak，Helm 管理平台资源及 Keycloak CR，Operator/CRD、数据库备份与升级由明确的基础设施流水线管理。不得把官方 Operator 描述为官方 Helm chart。

候选登录范围：开放注册 + 邮箱验证 + OIDC；管理员要求 MFA；SAML 作为后续企业需求候选，尚未获用户确认。具体会话时效、供应商版本、地区与邮件配置尚未冻结。

来源（2026-09-13 阅读）：
- https://www.keycloak.org/docs/latest/server_admin/
- https://www.keycloak.org/operator/basic-deployment
- https://zitadel.com/docs
- https://zitadel.com/docs/self-hosting/deploy/kubernetes

AUTH-02 上线前验证：真实 IdP 注册/验证/恢复/MFA，OIDC code + PKCE/state/nonce，退出与撤销，多副本会话恢复，Helm 渲染与升级回滚；当前仅文档对比，未完成上述运行验收。


OIDC 采用标准 code + PKCE。BFF 使用同 realm 的标准 token exchange V2 获取 audience=saas-auth 的下游 token；仅启用允许的 client/scopes，配置 downscope 策略，禁止使用旧预览 impersonation 接口。机器身份单独使用 client_credentials；Auth 通过已配置的 client allowlist、主体类型和 scopes 区分，不能让客户端自报 actor。

来源：https://www.keycloak.org/securing-apps/token-exchange 。具体镜像版本、realm 配置导出和升级测试属于 AUTH-02，不使用 latest 镜像直接上线。
