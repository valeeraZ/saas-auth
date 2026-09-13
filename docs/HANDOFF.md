# Auth 工作交接

源仓库保持只读，固定来源提交 8cdc9ae56381dcbde8b8d3c965a75a918897896c。SDK 已完成独立抽取、通用 SaaS 命名迁移并合并；新接口不得恢复旧专有命名。

已确认：平台托管，提供 Helm/CI/CD，开放注册；外部应用需审核，每次更新审核，平台控制上线；业务应用同域自定义 suffix，共享浏览器信任边界。用户已选择 Keycloak，接受 Kubernetes Operator，平台继续提供 Helm。

当前分支 codex/auth-01-contracts。ADR、Auth 语义契约、OpenAPI、事件 schema 与静态校验脚本已经编写；仍是候选契约，不是运行中的服务。执行脚本见 README，静态验证范围见 docs/CONTRACT-VALIDATION.md。

首发 SAML 尚无需求承诺；先实现 OIDC。地区、域名、邮件服务和生产镜像精确版本在部署任务中确定，不阻塞当前契约设计。平台管理员 MFA 为建议安全默认，产品上线前验证恢复路径。

下一步对候选契约进行跨仓库评审；再执行 AUTH-02，先服务身份与持久角色 API、数据库迁移和 outbox，再完成用户登录/组织流程。真实 OIDC、数据库、授权隔离及 Helm 验收尚未执行。禁止公开发布包或生产部署，除非用户另行授权。
