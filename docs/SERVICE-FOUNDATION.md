# AUTH-02 第一阶段：服务身份与角色 API

本文保留第一阶段交付记录；当前新增用户与租户能力见 [USER-TENANCY.md](USER-TENANCY.md)。下述未实现列表描述第一阶段时点。

本阶段提供可运行的 Auth 基础服务，不宣称 AUTH-02 全部完成。

| 操作 | 运行范围 |
| --- | --- |
| GET /v1/tenants/{tenantId} | 受限机器身份读取快照和删除墓碑；返回 lifecycleSequence 与 authorizationVersion |
| GET /v1/tenants/{tenantId}/apps/{appId}/roles | 当前客户端、租户、应用许可和 roles:read scope；签名游标默认 50、最大 100 |
| POST 同一路径 | roles:write；事务内幂等创建、审计、授权版本与 outbox |
| DELETE 上述路径/{roleId} | roles:write；If-Match；删除同租户同应用角色及关联授权，事务内递增授权版本 |
| /health/live、/health/ready | 进程存活；数据库与迁移就绪 |

其余候选 API 尚未实现。用户 owner 的令牌不能调用这一阶段的机器 API；授权用户操作在后续阶段实现。运行时 /openapi.json 只列实现路径，完整候选契约在 contracts/openapi.json。

## 身份与数据库

仅接受 RS256、固定 issuer、audience=saas-auth、有效期不超过 300 秒的 Keycloak Bearer access token。服务主体必须精确匹配数据库中的 issuer + subject + client_id（azp）；还需签名 scope 和当前数据库许可。不能用 X-User-ID、Cookie 或客户端自报 tenantId 伪装身份。JWKS 地址由固定 Keycloak issuer 构造，不读取 token 中的 URL；缓存 60 秒，冷缓存获取失败拒绝请求。HTTPS 默认要求，本地模式显式放行回环地址和 Compose 的 keycloak 主机。

迁移提供 users、external_identities、tenants、memberships、role_definitions、role_assignments、service principals/grants、idempotency、audit、outbox。复合外键禁止把其他租户的成员或角色写入授权关联。迁移有顺序、校验和及事务锁；API 启动不自动修改 schema。迁移/运维凭据应在部署时与运行时 DML 权限分开；Compose 使用同一数据库所有者，不代表生产权限已验收。

API 固定锁顺序为服务主体 → 许可 → 租户。写操作锁租户行，在同一事务中检查去重、修改角色、递增版本、写审计/outbox 并保存响应。已提交的禁用/许可撤回/租户暂停对之后开始的请求生效，包括幂等重放。成功响应按客户端、租户、method、规范化 route、key 保存；摘要包括 If-Match。当前不清理去重记录，保留期超过 24 小时；后续清理任务必须满足至少 24 小时契约。

bootstrap 仅是运维 CLI，要求数据库访问、SAAS_ENABLE_BOOTSTRAP=true 和 SAAS_OPERATOR_ID，不暴露 HTTP 管理入口、不创建密码、不授予平台全局管理员。它建立指定 issuer+subject 的初始租户 owner，不把邮箱标记为已验证。正常开放注册不使用 bootstrap。重复租户/slug 会事务回滚，不能覆盖已有身份。

## outbox

租户 bootstrap 原子写入 tenant.created；角色变更写入 tenant.authorization_changed。两类事件分属 lifecycle/authorization 流，各自有序，避免角色修改造成生命周期序号缺口。快照的 lifecycleSequence 供生命周期恢复；authorizationVersion 供授权缓存恢复。删除角色同时删除关联授权。事件不包含令牌、邮箱或邀请密钥。

worker 使用 SKIP LOCKED 领取每个租户每条流的队首，以 30 秒租约和 lease_id 防止过期 worker 确认新租约。HTTP 投递发生在数据库事务之外；失败指数退避（上限 256 秒），记录保留并可恢复。请求 Idempotency-Key 为稳定 eventId，X-Saas-Event-Stream 标明流；仅 2xx 确认，拒绝跟随重定向。崩溃或响应丢失会再次投递，接收者必须持久按 eventId 去重。未完成 Admin 消费者。

设置 SAAS_OUTBOX_ENDPOINT（HTTPS）、SAAS_OUTBOX_SECRET（至少 32 字符）和 SAAS_DATABASE_URL 后运行 `saas-auth outbox-worker`；`outbox-once` 适合任务调度。当前是 HTTP 投递适配器；接收方契约、队列告警、保留/重放管理仍待 Admin 联调。

## 验证与未完成项

自动测试连接真实 PostgreSQL，拒绝没有 `_test` 后缀的数据库；会清空该测试库业务表。覆盖并发幂等、冲突和 ETag、事务回滚、复合外键、跨租户/应用参数、签名/issuer/audience/期限、机器与用户主体区分、撤权后重放拒绝、JWKS 故障、outbox 租约竞争/崩溃恢复/HTTP 重试。真实 Keycloak 测试单独标记，缺少配置会 skip，不应把 skip 报为通过。

未完成：用户注册/登录/验证/找回/退出及 token exchange、会话持久撤销、租户/成员/邀请管理端点、最后 owner 竞争、业务邀请邮件、Admin/Portal 联调、生产 Helm/Operator/数据库权限与部署。局部测试不替代这些验收。

实现依据：[Psycopg 事务](https://www.psycopg.org/psycopg3/docs/basic/transactions.html)、[连接池](https://www.psycopg.org/psycopg3/docs/advanced/pool.html)、[PyJWT API](https://pyjwt.readthedocs.io/en/stable/api.html)、[Keycloak 容器](https://www.keycloak.org/server/containers)。
