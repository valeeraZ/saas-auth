# Application roles and access requests

Auth owns the roles, direct grants and access request history. Admin owns application metadata and publication eligibility. A published app does not imply user access. Portal's home and the SDK sidebar continue consuming the authorized catalog; `/more-apps` consumes the separate authenticated discovery endpoint, which includes every active, ready, unexpired publication without exposing origins or deployment data.

An operator defines up to 100 roles per app with a stable key, display name, description and active flag. There are no built-in viewer/user/admin roles. Migration 004 imports the role keys from existing explicit grants without creating grants or changing user access. An app with no roles can be discovered but cannot receive access requests. Apply migration 004 before starting the API; readiness fails until it is present.

Role definitions use an expected version and an idempotency key. Removing, renaming or disabling a role removes it from active grants; a grant with no remaining roles is disabled. Reintroducing a role never resurrects disabled access. Existing pending requests remain visible, but cannot be approved if any requested role is no longer active. Reject them with a comment and let the user submit a new selection.

Authenticated users can select multiple roles and supply an optional reason. User identity is derived from a verified human token and current local session, never from a request body. There is at most one pending request per user/app. Already granted roles cannot be requested alone. A rejection permits a new request; prior requests and decisions remain in the database.

Approval and rejection require the private operator key and the verified console actor. Comments are required. Approval validates all requested roles, merges them with the user's currently enabled roles, writes the grant and final request state, and records both audit events in one transaction. A disabled grant does not contribute its old roles. App locks serialize role updates and grant decisions, and request row locks ensure only one reviewer succeeds. Identical retries return the stored decision; a second decision with another key returns 409. Rejecting never modifies the grant. Suspended users cannot be approved.

## API

- `GET /v1/apps/{appId}/roles`: active role definitions for authenticated users.
- `GET /v1/apps/{appId}/requests`: the user's latest 20 requests for that app.
- `POST /v1/apps/{appId}/requests`: `{roles, reason}` and `Idempotency-Key`.
- `GET|PUT /v1/operator/apps/{appId}/roles`: operator configuration `{version, roles}`.
- `GET /v1/operator/requests`: UUID cursor and optional pending/approved/rejected status; 20 per page.
- `PUT /v1/operator/requests/{requestId}`: `{decision: approved|rejected, comment}` and `Idempotency-Key`.

The request table preserves requested role keys and review history. Role display names remain current app business data. The SDK forwards approved keys in its verified context; each app implements their business meaning. Granting an app's `admin` role never grants access to the platform Admin console.

## Console and refresh

The Admin app editor saves registry metadata and Auth role definitions as separate idempotent writes. These databases do not share a transaction. If the second write fails, the UI explicitly reports that metadata may already have saved and instructs the operator to reopen and retry; no role or grant change is assumed. Approval itself is fully transactional within Auth.

Portal BFF checks app publication eligibility before accepting user submissions and protects mutations with exact origin and CSRF checks. The browser never receives operator credentials or upstream user tokens. More apps polls pending requests every 10 seconds while visible. The shared SDK shell polls its authorized navigation every 15 seconds while visible, also refreshing on focus and local grant-change events. Returning to home reloads the authorized catalog. The proxy still checks permissions on each protected app request, independent of these display refresh intervals.

Rollout order: merge/deploy the SAA-11 user/app platform changes first, then apply Auth migration 004 and deploy Auth, Admin discovery/console, and the updated SDK UI/shell and Portal. Validate in disposable databases. Existing trial databases and volumes are not reset.
