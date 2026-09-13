# 执行清单

## AUTH-01 固定身份与租户 API 契约

为 Admin、Portal 和 SDK 定义服务端契约；先确认身份提供组件与会话策略，再实现身份流程。

基线： https://github.com/valeeraZ/portal-multiapps/tree/8cdc9ae56381dcbde8b8d3c965a75a918897896c

## 验收标准

- [ ] 提交身份组件决策对比与 ADR，覆盖独立登录、OIDC、MFA、找回和部署要求；SAML 按需求安排
- [ ] 定义 User、ExternalIdentity、Organization、Membership、RoleDefinition、RoleAssignment 的唯一键和作用域
- [ ] OpenAPI 定义 current-user、组织选择、成员、角色管理与权限响应；事件 schema 定义组织生命周期
- [ ] 定义服务身份、用户委托、错误码、幂等键、分页、撤销策略与 API 版本；不信任浏览器组织声明
- [ ] 明确无组织和组织 provisioning 状态；与 Admin 数据所有权保持一致

完成时提交实现、执行过的验证及剩余限制；不得把模拟服务验收写成真实服务验收。

## AUTH-02 实现持久身份与组织授权基础服务

依赖 AUTH-01。交付真实 Auth 服务，取代 fixture；身份协议使用选定成熟组件。

基线： https://github.com/valeeraZ/portal-multiapps/tree/8cdc9ae56381dcbde8b8d3c965a75a918897896c

## 验收标准

- [ ] 独立数据库及迁移、健康检查、Docker/本地启动、受限 bootstrap 管理员
- [ ] 先交付可供 Admin 调用的服务身份与幂等角色 API，再交付注册/登录/验证/找回/退出
- [ ] 组织、成员、邀请与角色持久化；关键撤权、跨组织伪造、直接 API 越权测试通过
- [ ] outbox 事件幂等可恢复，身份审计与邮件任务由本服务负责
- [ ] 真实 PostgreSQL 集成测试、会话测试及启动文档通过

完成时提交实现、执行过的验证及剩余限制；不得把模拟服务验收写成真实服务验收。

## GitHub Issues

- [AUTH-01 固定身份与租户 API 契约](https://github.com/valeeraZ/saas-auth/issues/1)
- [AUTH-02 实现持久身份与组织授权基础服务](https://github.com/valeeraZ/saas-auth/issues/2)

## 当前候选产物

见 docs/adr、docs/AUTH-CONTRACT.md、contracts/openapi.json 与 contracts/events。静态验证通过，尚待契约评审；不把检查框等同于服务实现验收。Keycloak 选择已确认。
