# User/application platform (SAA-11)

The platform owns user identity, sessions and direct user/application grants. Applications own their business data and decide which records are private or shared. There is no tenant, membership, tenant owner, installation by tenant or implicit application access.

## Protocol

Auth `GET /v1/me` returns the verified user only. `GET /v1/apps/{appId}/permissions` evaluates the current user's direct grant online. Operators manage grants through separately authenticated `/v1/operator/apps/{appId}/grants` and list mapped users through `/v1/operator/users`; a human login or a client-provided user ID never grants operator access. The operator key is injected only into Auth and the authenticated Admin console server, never browser responses. Console audit identity comes from its verified OIDC subject.

Admin owns globally reviewed application definitions, deployments and publications. A publication has one current deployment, enabled/entitled/expiry conditions, and does not itself authorize a user. The catalog intersects these facts with live Auth user grants. Replacement and revocation retain their existing immutable build namespace and compatibility deadline rules.

Portal serves `/` as the application directory and `/apps/{mount}/...` as protected application routes. Its original opaque login session, CSRF, bounded request bodies, request signature binding, replay checks and response redirect/Cookie filtering remain required. The SDK receives verified user/app/deployment/roles and display preferences; these contain no tenant context.

Portal and SDK use the same Shell navigation contract. The same-origin authenticated Portal navigation API supplies all accessible applications across catalog pages, including empty filtered pages. The browser's Portal cookie is used only by the Portal BFF; it is never forwarded to application servers. Application names/descriptions are business data; UI labels use centralized zh/en resources. No application receives a service credential or private deployment origin.

## Migration

Existing checksummed Auth migrations remain immutable. A new migration moves former tenant tables into a private `legacy_tenancy` archive, retains identities/sessions, and creates empty direct app grants. Admin archives old installations and creates empty app publications. These archives are migration evidence, not active domain models. Old API routes are removed and do not map to a hidden default tenant.

Do not flatten former tenant roles into global permissions or merge application records across former tenants automatically. Review each user/app grant and application-specific data mapping explicitly. New isolated databases and the new end-to-end harness are the acceptance environment. Existing user databases and application data are not reset by development work. Archive removal is a separate explicit operator decision after backup and review.
