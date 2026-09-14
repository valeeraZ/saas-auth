"""Disposable user-flow configuration; never import these accounts into production."""

import secrets

from cryptography.fernet import Fernet


def user_scopes():
    def mapper(name, attribute, claim, kind="String"):
        return {
            "name": name,
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-property-mapper",
            "config": {
                "user.attribute": attribute,
                "claim.name": claim,
                "jsonType.label": kind,
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true",
                "introspection.token.claim": "true",
            },
        }

    return [
        {
            "name": "basic",
            "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "false"},
            "protocolMappers": [
                {
                    "name": "subject",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-sub-mapper",
                    "config": {"access.token.claim": "true", "introspection.token.claim": "true"},
                }
            ],
        },
        {
            "name": "profile",
            "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "true"},
            "protocolMappers": [
                mapper("username", "username", "preferred_username"),
                {
                    "name": "full-name",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-full-name-mapper",
                    "config": {
                        "id.token.claim": "true",
                        "access.token.claim": "true",
                        "userinfo.token.claim": "true",
                    },
                },
            ],
        },
        {
            "name": "email",
            "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "true"},
            "protocolMappers": [
                mapper("email", "email", "email"),
                mapper("email-verified", "emailVerified", "email_verified", "boolean"),
            ],
        },
    ]


def add_users(realm):
    realm["clientScopes"].extend(user_scopes())
    portal_secret, auth_secret, worker_secret, user_password = (
        secrets.token_urlsafe(32) for _ in range(4)
    )
    realm.update(
        registrationAllowed=True,
        verifyEmail=True,
        resetPasswordAllowed=True,
        ssoSessionIdleTimeout=1800,
        ssoSessionMaxLifespan=28800,
        smtpServer={
            "host": "host.docker.internal",
            "port": "58025",
            "from": "noreply@example.com",
            "auth": "false",
            "starttls": "false",
        },
    )
    realm["clients"].extend(
        [
            {
                "clientId": "saas-portal",
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "secret": portal_secret,
                "standardFlowEnabled": True,
                "directAccessGrantsEnabled": False,
                "serviceAccountsEnabled": False,
                "fullScopeAllowed": False,
                "redirectUris": ["http://127.0.0.1:58999/callback"],
                "attributes": {
                    "pkce.code.challenge.method": "S256",
                    "standard.token.exchange.enabled": "true",
                },
                "defaultClientScopes": ["basic", "profile", "email", "auth-api"],
            },
            {
                "clientId": "saas-auth",
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "secret": auth_secret,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "serviceAccountsEnabled": False,
            },
            {
                "clientId": "saas-session-worker",
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "secret": worker_secret,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "serviceAccountsEnabled": True,
                "fullScopeAllowed": True,
                "protocolMappers": [
                    {
                        "name": "session-permission",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-usermodel-client-role-mapper",
                        "config": {
                            "usermodel.clientRoleMapping.clientId": "realm-management",
                            "claim.name": "resource_access.realm-management.roles",
                            "jsonType.label": "String",
                            "multivalued": "true",
                            "access.token.claim": "true",
                        },
                    }
                ],
            },
        ]
    )
    realm["clientScopes"].append(
        {
            "name": "auth-api",
            "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "true"},
            "protocolMappers": [
                {
                    "name": "auth-audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "config": {
                        "included.custom.audience": "saas-auth",
                        "access.token.claim": "true",
                    },
                }
            ],
        }
    )
    realm["users"].extend(
        [
            {
                "id": "00000000-0000-4000-8000-000000000020",
                "username": "service-account-saas-session-worker",
                "enabled": True,
                "serviceAccountClientId": "saas-session-worker",
                "clientRoles": {"realm-management": ["manage-users"]},
            },
            {
                "id": "00000000-0000-4000-8000-000000000030",
                "username": "local-user",
                "enabled": True,
                "email": "local-user@example.com",
                "emailVerified": True,
                "firstName": "Local",
                "lastName": "User",
                "credentials": [{"type": "password", "value": user_password, "temporary": False}],
            },
        ]
    )
    return {
        "SAAS_LOCAL_PORTAL_SECRET": portal_secret,
        "SAAS_INTROSPECTION_SECRET": auth_secret,
        "SAAS_SESSION_WORKER_SECRET": worker_secret,
        "SAAS_LOCAL_USER_PASSWORD": user_password,
        "SAAS_TASK_KEY": Fernet.generate_key().decode(),
    }
