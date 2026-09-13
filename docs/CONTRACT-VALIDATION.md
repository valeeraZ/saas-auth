# AUTH-01 静态验证

OpenAPI 3.1：20 个操作，通过 openapi-spec-validator 0.7.2；操作 ID 唯一、操作授权说明存在、写操作幂等键存在、路径资源修改的 If-Match 存在。

组织生命周期 JSON Schema 2020-12 通过 schema 检查；两个正向样例通过；五类反例被拒绝：非法组织 UUID、非正序列、未知版本、额外凭据字段、事件类型/状态不匹配。

命令：python scripts/validate_contracts.py。依赖见 requirements-contracts.txt。本次在独立 Python venv 执行。此记录不意味着实现了服务端权限、撤销、事务、幂等或并发控制；这些是 AUTH-02 的真实集成测试要求。

Keycloak 选型已获用户确认。API 保持 0.1.0-draft 供跨仓库评审；不把 AUTH-01 的远程 Issue 标记已完成或已发布。生产版本、邮件、区域及 SAML 首发需求未在此验证。
