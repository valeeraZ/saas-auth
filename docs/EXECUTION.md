# 执行清单

## AUTH-01 固定身份与租户 API 契约

为 Admin、Portal 和 SDK 定义服务端契约；先确认身份提供组件与会话策略，再实现身份流程。

基线： https://github.com/valeeraZ/portal-multiapps/tree/8cdc9ae56381dcbde8b8d3c965a75a918897896c

## 验收标准

- [ ] 提交身份组件决策对比与 ADR，覆盖独立登录、OIDC、MFA、找回和部署要求；SAML 按需求安排
- [ ] 定义 User、ExternalIdentity、Tenant、Membership、RoleDefinition、RoleAssignment 的唯一键和作用域
- [ ] OpenAPI 定义 current-user、租户选择、成员、角色管理与权限响应；事件 schema 定义租户生命周期
- [ ] 定义服务身份、用户委托、错误码、幂等键、分页、撤销策略与 API 版本；不信任浏览器租户声明
- [ ] 明确无租户和租户 provisioning 状态；与 Admin 数据所有权保持一致

完成时提交实现、执行过的验证及剩余限制；不得把模拟服务验收写成真实服务验收。

## AUTH-02 实现持久身份与租户授权基础服务

依赖 AUTH-01。交付真实 Auth 服务，取代 fixture；身份协议使用选定成熟组件。

基线： https://github.com/valeeraZ/portal-multiapps/tree/8cdc9ae56381dcbde8b8d3c965a75a918897896c

## 验收标准

- [ ] 独立数据库及迁移、健康检查、Docker/本地启动、受限 bootstrap 管理员
- [ ] 先交付可供 Admin 调用的服务身份与幂等角色 API，再交付注册/登录/验证/找回/退出
- [ ] 租户、成员、邀请与角色持久化；关键撤权、跨租户伪造、直接 API 越权测试通过
- [ ] outbox 事件幂等可恢复，身份审计与邮件任务由本服务负责
- [ ] 真实 PostgreSQL 集成测试、会话测试及启动文档通过

完成时提交实现、执行过的验证及剩余限制；不得把模拟服务验收写成真实服务验收。

## GitHub Issues

- [AUTH-01 固定身份与租户 API 契约](https://github.com/valeeraZ/saas-auth/issues/1)
- [AUTH-02 实现持久身份与租户授权基础服务](https://github.com/valeeraZ/saas-auth/issues/2)

## 当前候选产物

见 docs/adr、docs/AUTH-CONTRACT.md、contracts/openapi.json 与 contracts/events。Keycloak 选择已确认。跨仓库检查见 docs/CROSS-REPO-REVIEW.md；补充 lifecycleSequence 和独立授权事件。

## AUTH-02 第一阶段进度

- [x] PostgreSQL 迁移、连接池、健康检查、Docker/本地启动、受限运维 bootstrap
- [x] 机器身份与租户/应用许可、幂等角色列表/创建/删除和租户快照
- [x] 原子审计/outbox、租约重试、角色撤销和跨租户/应用隔离测试
- [x] 真实 PostgreSQL、真实 Keycloak client_credentials、独立打包与本地 Docker 构建验证
- [ ] 用户登录/注册/验证/找回/退出、token exchange 和会话撤销
- [ ] 租户/成员/邀请 API、最后 owner 竞争与业务邮件
- [ ] Admin/Portal 真实消费、生产 Helm/Operator 与完整 AUTH-02 验收

完整 Issue 的复选框保持未完成，不用机器身份阶段替代用户流程验收。详见 docs/SERVICE-FOUNDATION.md。
