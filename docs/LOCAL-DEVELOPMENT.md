# 本地启动与测试

Python >=3.11、uv 0.11.7、Docker Compose。依赖在 uv.lock 固定；PostgreSQL 17、Keycloak 26.7.3 和 Python 基础镜像固定摘要。

## Docker Compose

```sh
uv sync --frozen
uv run python scripts/prepare_local.py
docker compose up --build -d
curl --fail http://127.0.0.1:58000/health/ready
```

prepare_local 生成随机本地数据库、游标和客户端密钥，保存到忽略的 .env、.local/saas-local-realm.json，拒绝覆盖已有文件。.local 是私有目录，单文件只读挂载给 Keycloak。API 58000、Keycloak 58080、PostgreSQL 55433 仅绑定 127.0.0.1。迁移先于 API 执行。

Compose 默认仅启用 Auth 机器身份接口。生成的 realm 已允许注册和邮件找回密码，但交互协议测试必须使用下述独立 HTTPS 环境，以保证 Secure cookie 正常工作。Keycloak 使用临时开发存储；重建后重新导入，业务数据库存于 auth-db volume。issuer 固定为 http://keycloak:8080/realms/saas-local，供 Auth 容器内部获取 JWKS；宿主机请求 token 使用 127.0.0.1:58080。

API 默认无租户许可。用运维 CLI 建立本地测试租户，再赋予 saas-admin 对该租户及应用的范围：

```sh
docker compose run --rm -e SAAS_ENABLE_BOOTSTRAP=true -e SAAS_OPERATOR_ID=local-dev auth \
  saas-auth bootstrap-tenant --issuer http://keycloak:8080/realms/saas-local \
  --subject local-owner --email owner@example.test --name Demo --slug demo \
  --tenant-id 00000000-0000-4000-8000-000000000001
docker compose run --rm -e SAAS_ENABLE_BOOTSTRAP=true -e SAAS_OPERATOR_ID=local-dev auth \
  saas-auth configure-service --issuer http://keycloak:8080/realms/saas-local \
  --subject 00000000-0000-4000-8000-000000000010 --client-id saas-admin \
  --tenant-id 00000000-0000-4000-8000-000000000001 \
  --app-id 00000000-0000-4000-8000-000000000002 \
  --scope tenants:read --scope roles:read --scope roles:write
```

local-owner 是 bootstrap 测试身份，不是可登录账户。正式运维必须核对真实 issuer/subject。configure-service 只管理指定租户/应用许可，不接受通配符；省略 scope 会撤回对应许可，禁用主体不能通过该命令重新启用。完成后退出运维环境，不给 API 设置 SAAS_ENABLE_BOOTSTRAP。

从 .env 读取 SAAS_LOCAL_CLIENT_SECRET，用 client_credentials 向 Keycloak 的 /realms/saas-local/protocol/openid-connect/token 请求令牌；将 access_token 放入 Authorization: Bearer 头访问 API。不要将令牌或密钥贴入日志。创建角色需要至少 16 字符 Idempotency-Key；删除使用列表返回的 version 构造强 ETag（例如 `If-Match: "1"`），或使用创建响应的 ETag。

停止：`docker compose down`，保留数据库。生产不使用 start-dev、本地 owner 或 Compose 凭据；生产 Keycloak Operator/Helm 后续验收。

## 宿主机运行

```sh
uv sync --frozen
export SAAS_DATABASE_URL='postgresql://USER:PASSWORD@127.0.0.1:55433/saas_auth'
export SAAS_OIDC_ISSUER='https://YOUR-KEYCLOAK/realms/YOUR-REALM'
export SAAS_CURSOR_SECRET='YOUR-RANDOM-SECRET-AT-LEAST-32-CHARACTERS'
uv run alembic upgrade head
uv run uvicorn saas_auth.api:create_app --factory --port 8000
```

本地 Keycloak 使用回环 HTTP 时，还需 SAAS_ALLOW_INSECURE_LOCAL=true；issuer 必须是宿主机可访问地址，不能复用 Compose 的内部 hostname。数据库 URL 和私钥材料通过环境注入，不能提交。

## 集成测试和打包

使用专用空库，数据库名称必须以 `_test` 结尾。测试会清空业务表；不允许指向业务数据库。

```sh
uv sync --frozen
export SAAS_TEST_DATABASE_URL='postgresql://USER:PASSWORD@127.0.0.1:5432/saas_auth_test'
uv run ruff check src tests scripts/prepare_local.py scripts/realm_users.py scripts/local_tls.py
uv run python scripts/validate_contracts.py
uv run pytest -q -m 'not keycloak'
uv build
docker build -t saas-auth:local .
```

真实 Keycloak 用户测试使用独立 HTTPS 容器，完整启动命令见 `.github/workflows/validate.yml`：生成配置后挂载 realm、tls.crt、tls.key，映射 58443:8443，设置 hostname=https://127.0.0.1:58443，并添加 host.docker.internal:host-gateway。测试启动 58025 端口上的本地 SMTP 捕获器，不向外部邮箱投递。证书有效期 7 天；到期后明确删除旧本地配置再生成，勿覆盖生产凭据。

```sh
set -a
. ./.env
set +a
SSL_CERT_FILE="$PWD/.local/tls.crt" \
  SAAS_TEST_KEYCLOAK_SECRET="$SAAS_LOCAL_CLIENT_SECRET" \
  SAAS_TEST_KEYCLOAK_ISSUER=https://127.0.0.1:58443/realms/saas-local \
  uv run pytest -q -m keycloak --tb=short
```

需同时配置上述专用测试数据库。覆盖真实机器令牌、免邮件验证注册及邮件找回密码、PKCE、token exchange 和上游会话撤销；不是 Portal 浏览器验收。不要把 SSL_CERT_FILE 设置为全局环境变量，以免影响访问公共依赖源。用户 API 与私有任务配置见 USER-TENANCY.md。

CI 执行契约、静态检查、PostgreSQL、真实 Keycloak、wheel/sdist 和 Docker 构建；没有 publish 或 deploy 步骤。
