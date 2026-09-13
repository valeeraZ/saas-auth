# Auth 工作交接

源仓库保持只读，固定来源提交 8cdc9ae56381dcbde8b8d3c965a75a918897896c。SDK 已完成独立抽取、通用 SaaS 命名迁移并合并；新接口不得恢复旧专有命名。

已确认：平台托管，提供 Helm/CI/CD，开放注册；外部应用需审核，每次更新审核，平台控制上线；业务应用同域自定义 suffix，共享浏览器信任边界。用户已选择 Keycloak，接受 Kubernetes Operator，平台继续提供 Helm。

当前分支 codex/auth-02-service-foundation，基于已合并 Auth PR #3（30642ad）。跨仓库检查见 docs/CROSS-REPO-REVIEW.md。第一阶段实现机器身份、租户快照、角色列表/创建/删除、PostgreSQL 迁移、受限 bootstrap、审计和 outbox；完整 20 操作仍是候选契约，未全部实现。运行范围见 docs/SERVICE-FOUNDATION.md，启动见 docs/LOCAL-DEVELOPMENT.md。

首发 SAML 尚无需求承诺；先实现 OIDC。地区、域名、邮件服务和生产镜像精确版本在部署任务中确定，不阻塞当前契约设计。平台管理员 MFA 为建议安全默认，产品上线前验证恢复路径。

下一步评审本阶段实现及 lifecycleSequence / authorization-changed 契约补充，再完成用户 OIDC 会话、租户/成员/邀请流程和最后 owner 竞争。真实 PostgreSQL、机器身份 Keycloak、角色授权隔离与 outbox 已有集成测试；用户登录/会话、邮件、Helm/Operator 和 Admin/Portal 消费尚未验收。禁止公开发布包或生产部署，除非用户另行授权。

## 租户模型约定

用户明确只保留 Tenant（租户）概念。租户直接拥有成员、邀请和租户角色，不增加公司、部门或其他中间层级。一个用户可加入多个租户；Membership 关联 user_id 与 tenant_id。当前 API/字段/事件均使用 tenant 命名。
