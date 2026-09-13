# Auth 契约草案

状态：draft，不可作为已批准的生产 API；Keycloak 已获用户确认；契约等待跨仓库评审，不标记 AUTH-01 已发布。

## 数据模型

| 实体 | 唯一键 | 作用域与约束 |
| --- | --- | --- |
| User | UUID id | 平台全局；邮箱用于联络，不能仅凭相同邮箱自动合并身份 |
| ExternalIdentity | (issuer, subject) | 绑定唯一 user_id；认证恢复与关联必须重新验证，不允许跨组织邮箱隐式关联 |
| Organization | UUID id；规范化 slug | Auth 管理生命周期；slug 可改，引用和审计使用不可变 ID |
| Membership | (organization_id, user_id) | active/suspended/revoked；最后一名 owner 不可被移除或降级 |
| RoleDefinition | (organization_id, app_id, key) | 应用角色限组织作用域；平台管理员资格不可由组织管理员创建 |
| RoleAssignment | (organization_id, user_id, role_id) | role 与 member 必须属于同组织；组织内不能引用别的租户角色 |
| Invitation | UUID id；活动邀请按 (org, normalized email) 去重 | 到期与一次性消费；接受时验证当前身份邮箱，不能由邀请参数直接授予平台权限 |

业务组织、成员与角色以 Auth 数据库为事实源，身份提供方只提供身份认证。Admin 通过受限服务身份请求应用角色定义，不写 Auth 库。

## 会话与服务身份

公开浏览器登录/回调由 Portal BFF 使用标准 OIDC code + PKCE；不得实现自定义密码交换。Auth API 的 access token 必须校验 issuer/audience/signature/expiry。机器调用和用户委托令牌须可区分；机器调用不能仅附 user_id header 假冒用户。采用 Keycloak 同 realm 标准 token exchange V2，受限 audience/scopes，不使用 impersonation；Auth 仍逐请求查询业务授权事实。

OpenAPI 中 userAccess 与 serviceAccess 是不同授权上下文的 bearer 文档表示，不表示仅凭 token 外形就能区分身份。userAccess 必须包含可验证最终用户；serviceAccess 必须包含受限 client identity 与 scopes。组织路径和请求 body 只做选择，不做授权依据。

用户管理操作要求 active membership 和 owner/admin 能力；新建组织要求已验证邮箱。服务角色管理仅允许 Admin 指定客户端与 app 范围，不能借组织管理员入口授予平台管理员身份。权限查询只能查询调用者自身，除非具备明确委托授权。

撤销草案：角色/成员/组织变更递增授权版本；关键写入和权限决策读取当前状态，撤销提交之后开始的新决策不能接受旧缓存；事件仅负责清理派生缓存，不替代权威状态检查。请求已在撤销前提交的事务通过审计界定，不承诺跨服务事务回滚。普通展示缓存时效待 Portal ADR 固定。

## 状态与跨服务边界

无组织用户的 /v1/me 返回 organizations=[]，允许创建组织或接受邀请，不默认获得应用权限。组织创建后 Auth 身份生命周期为 active，但 Admin 的开通状态可仍为 provisioning；Auth 不存储第二份 Admin readiness 状态。UI 的 provisioning 来自 Admin，导航需同时满足成员授权、READY 部署、有效 installation 与 entitlement。

组织停用/删除先在 Auth 拒绝新授权，再发出生命周期事件，由 Admin 异步清理开通资源。删除先进入 deleting，最终 deleted 需可恢复的协调流程；不通过级联删除跨服务数据库记录。

## 通用约定

/v1 为服务版本，与 npm 版本独立。UUID 标识符；UTC date-time；游标分页默认 50、最大 100，游标绑定调用者、过滤条件与组织。拒绝未知跨租户引用。

所有 POST/PATCH/DELETE 写请求携带 Idempotency-Key；服务端以 (actor/client, organization, method, canonical route, key) 持久去重，保存请求摘要与结果至少 24 小时。相同 key 不同载荷返回 409；并发同请求返回同一结果，不重复发事件。修改资源需要 If-Match，版本冲突返回 412；实际事务中校验版本，不能只在网关比较。

错误响应携带稳定 code、requestId、message。401 未认证，403 能力不足/成员失效，404 资源不存在或需隐藏的跨租户对象，409 幂等冲突/最后 owner/重复身份，412 版本冲突，422 输入无效，429 限流，503 依赖不可用。不得在 message 中回传 token、密码、邀请密钥。

事件使用事务 outbox：至少一次投递，以 eventId 去重，以 organizationId + sequence 排序；消费者忽略已应用的旧版本，发现缺口回查权威快照。删除事件保留墓碑，失败进入可重试队列。事件只包含最小组织生命周期元数据，不含用户 token。

## AUTH-02 验收前置

必须补齐并运行真实 PostgreSQL 唯一性/事务/outbox 测试；跨组织 role/member 参数伪造；最后 owner 竞争；幂等响应丢失；撤权版本；邀请重复接受；IdP 故障与会话撤销。Schema 验证不是上述集成验收。


## 会话技术默认值（可配置、待联调验证）

access token 上限 5 分钟；BFF 会话空闲 30 分钟、绝对上限 8 小时；刷新由服务端执行。Portal 的随机会话标识只引用服务器会话记录，Auth 将可信 Keycloak sid 映射为可撤销的认证上下文。Auth API 不接受仅有 Cookie 的直接浏览器认证。关键请求检查当前会话/成员状态，JWT 尚未过期不代表撤销后仍可访问。

开放注册先在 Keycloak 邮箱验证，Auth 以受信 issuer+subject 创建用户映射；未验证邮箱可读取自身基本状态，不可新建组织/接受邀请。供应商凭据、验证与恢复邮件由 Keycloak 管理；业务邀请邮件由 Auth outbox 管理，两者不得重复发送同类恢复任务。

标准应用入口保持同域自定义 suffix。BFF 登录、回调与登出在保留平台路径，Keycloak 管理 API/console 只通过运维网络暴露；同域审核应用拥有共享浏览器信任，不能通过 Cookie 属性声称相互隔离。


组织状态机：active → suspended → active，active/suspended → deleting → deleted。deleting/deleted 不可由公开 PATCH 恢复；最终删除由可恢复协调流程完成。suspensionSource 为服务端字段，只有 owner 发起的暂停允许 owner 恢复；平台暂停不能被租户管理接口撤销。Admin 的 organizations:read 服务 scope 可读取组织快照和删除墓碑用于事件缺口回查，不允许读取成员或凭据。
