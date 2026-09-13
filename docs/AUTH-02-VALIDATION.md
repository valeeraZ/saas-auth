# AUTH-02 第一阶段验证（2026-09-13）

## 已执行

- Ruff：通过。
- 候选 OpenAPI：20 操作、两个事件 schema、示例/反例及事件流分离检查通过。
- 完整 pytest：**34 passed**，无 skip。使用独立 PostgreSQL 17 容器，以及 Keycloak 26.7.3 的真实 client_credentials / JWKS；其余签名反例使用临时 RSA 密钥和本地 JWKS HTTP 服务，不替代真实 IdP 测试。
- PostgreSQL：并发幂等、重启后重放、版本冲突、事务回滚、跨租户复合外键、角色级联撤销、主体/许可/租户状态撤回后的拒绝、游标绑定均通过。
- outbox：队首并发领取、租约到期恢复、旧 worker 确认拒绝、HTTP 失败重试和稳定 eventId 通过。
- `uv build`：独立 wheel/sdist 构建成功；wheel 包含 SQL 迁移，不含本地凭据或 Python 缓存。
- Docker 构建和完整 Compose 启动：通过；迁移退出成功，API readiness 返回成功。按照文档运行 bootstrap/configure-service 后，通过真实 Keycloak 令牌完成 HTTP create/replay/list/delete。

依赖测试工具输出两条弃用提示（Starlette TestClient 的 httpx 和 anyio 兼容接口），不影响上述结果。CI 工作流已添加；此记录不声称远端 CI 已执行。

## 范围限制

只有机器快照和角色四个操作已实现；不是完整 20 操作验收。用户会话/开放注册/邮箱验证/恢复/邀请、最后 owner、Admin 消费者、生产数据库最小权限、Helm/Operator 均未在本阶段完成。

本地测试容器、开发凭据和打包产物不提交；不发布公共包、镜像或生产部署。固定源仓库未被本次实现修改。
