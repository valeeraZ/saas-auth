# AUTH-02 用户与租户阶段

本阶段基于服务基础阶段，增加迁移 002，不修改既有迁移。用户按唯一 issuer/subject 映射，绝不以邮箱自动合并账户。仅启用明确配置的用户客户端，用户客户端禁止 service account；每次用户请求校验签名、audience、sid 并在线 introspection。认证提供方异常时拒绝授权。

## 服务范围

20 个契约操作均有运行路由：当前用户、租户列表/创建/选择/状态、成员管理、邀请创建/列表/撤销/接受、业务角色定义与分配、权限查询和当前会话退出。成员权限从数据库读取，浏览器传入的 tenantId 不是授权依据。租户暂停、成员撤销和角色撤销即时影响授权。Admin 的安装与订阅许可仍由 Admin 判断。

创建租户和接受邀请要求邮箱已验证。邀请默认 7 天有效，仅授予普通成员；保存令牌哈希，原令牌仅存在加密邮件任务。接受时核对已验证邮箱、租户状态及既有成员状态。已撤销/暂停成员不能通过邀请重新进入。最后一个 owner 不能退出或降级，并发变更由事务和锁保护。

本地会话按首次 Auth 观察计 8 小时绝对期限、30 分钟空闲期限；Keycloak realm 同时限制其 SSO 会话 8 小时/30 分钟。退出事务立即撤销本地 sid，并持久记录上游撤销任务。签名仍有效且本地已知的会话，可在 introspection 故障时退出；冷启动且无法取得签名密钥时仍会失败。

## 私有任务运维

启用用户 API 需要 `SAAS_USER_CLIENTS`、`SAAS_INTROSPECTION_CLIENT`、`SAAS_INTROSPECTION_SECRET`、`SAAS_TASK_KEY`。任务密钥为 Fernet 密钥，须持久保管；不能随进程启动随机更换，否则已有任务无法解密。

独立进程运行 `saas-auth private-tasks-worker`；单次领取用 `private-tasks-once`。任务使用租约、领取标识、重试和完成后清除密文。上游撤销使用独立 `SAAS_SESSION_WORKER_CLIENT` / `SAAS_SESSION_WORKER_SECRET`；测试 realm 授予其 Keycloak `manage-users`，该凭据不可交给 Portal 或浏览器，生产需独立管理和审计。

邀请邮件需 `SAAS_INVITATION_URL`（HTTPS、无查询/fragment）、`SAAS_SMTP_HOST`、`SAAS_SMTP_PORT`、`SAAS_SMTP_FROM`，可选用户名/密码。默认 STARTTLS。仅显式本地配置可对 localhost/mailpit 使用明文 SMTP。链接令牌放入 URL fragment，后续 Portal 页面需读取、立即清除并通过 BFF 提交接受请求；该页面尚未实现。

邮件按至少一次投递，SMTP 确认丢失可能导致重复邮件。撤销邀请时已在发送中的邮件也可能到达，但令牌不能再接受。事件 outbox 不包含邀请原令牌或私有任务密文。

## 验证与后续

测试覆盖真实 PostgreSQL 上的用户映射、事务回滚、幂等、并发邀请与最后 owner、越权/撤权、会话期限和任务租约；本地 SMTP 捕获测试覆盖发送失败后重试。真实 Keycloak 测试通过 HTTP 协议驱动注册、验证、密码重置、授权码/PKCE、token exchange 和会话撤销；其结果以本分支 CI 为准。

未包含 Portal BFF/session cookie/邀请页面、浏览器 UI 联调、生产 SMTP、MFA 恢复、Helm/Operator、Admin 消费和完整租户删除协调器。AUTH-02 保持未关闭。无公共软件包发布或生产部署。
