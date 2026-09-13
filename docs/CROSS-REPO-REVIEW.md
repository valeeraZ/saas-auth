# 跨仓库契约检查（2026-09-13）

检查基点为已合并的 Auth `30642ad`、Admin `b02d141`、Portal `9df85bf`；SDK PR #3 已在此前合并。此次为文档和契约一致性检查，不代表 Admin/Portal 的真实服务联调。

| 边界 | 检查结论 |
| --- | --- |
| Tenant | 三仓库只保留租户；Auth OpenAPI 的四处说明仍有旧缩写，本次修正 |
| 数据所有权 | Auth 管身份/成员/角色；Admin 管开通/部署/权益；Portal 组合导航，不复制授权事实 |
| 机器身份 | Admin 使用 Keycloak client_credentials；本阶段增加按客户端、租户、应用的许可表，不提供通配符授权 |
| 用户身份 | Portal BFF 的 OIDC code+PKCE 与 token exchange 仍待用户流程阶段，不由机器 API 冒充实现 |
| 事件恢复 | 原租户快照缺生命周期序号；补充 lifecycleSequence。authorizationVersion 独立演进，不能当生命周期序号 |
| 同域路径 | suffix 是应用路径；Tenant ID 是请求上下文；共享浏览器信任前提一致 |

Admin/Portal 文档仍引用合并前候选分支；该提交已包含于 Auth 主分支，因此内容未分叉。后续各仓库实施时更新到审定的契约提交，不维护另一份 OpenAPI。

AUTH-01 保持候选状态：完整的 20 个操作并未全部实现。本阶段只验证机器调用的 4 个操作。新增的 lifecycleSequence 和授权事件 schema 需随本次改动评审。

下一阶段：实现经过 Keycloak 验证的用户映射和会话撤销，然后实现租户、成员、邀请、用户角色操作，并验证最后 owner 竞争、邀请单次接受和用户跨租户隔离。Admin/Portal 的真实消费、Helm/Operator、邮件和生产部署单独验收。
