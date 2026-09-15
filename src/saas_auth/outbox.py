from uuid import uuid4

import httpx


def claim(pool):
    """Lease a stream head in a short transaction, never hold a DB lock during HTTP."""
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT o.* FROM outbox o WHERE o.delivered_at IS NULL AND o.available_at<=now() "
            "AND (o.lease_until IS NULL OR o.lease_until<now()) AND NOT EXISTS "
            "(SELECT 1 FROM outbox older WHERE older.tenant_id=o.tenant_id AND older.stream=o.stream "
            "AND older.sequence<o.sequence AND older.delivered_at IS NULL) "
            "ORDER BY o.created_at,o.event_id FOR UPDATE OF o SKIP LOCKED LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        lease = uuid4()
        return conn.execute(
            "UPDATE outbox SET lease_id=%s,lease_until=now()+interval '30 seconds',attempts=attempts+1 "
            "WHERE event_id=%s RETURNING *",
            (lease, row["event_id"]),
        ).fetchone()


def finish(pool, row, success):
    with pool.connection() as conn:
        return (
            conn.execute(
                "UPDATE outbox SET delivered_at=CASE WHEN %s THEN now() ELSE NULL END, "
                "available_at=now()+make_interval(secs => %s),lease_id=NULL,lease_until=NULL "
                "WHERE event_id=%s AND lease_id=%s AND lease_until>now() RETURNING event_id",
                (success, min(300, 2 ** min(row["attempts"], 8)), row["event_id"], row["lease_id"]),
            ).fetchone()
            is not None
        )


def deliver_once(pool, endpoint, secret):
    row = claim(pool)
    if row is None:
        return False
    try:
        response = httpx.post(
            endpoint,
            json=row["payload"],
            timeout=5,
            headers={
                "Authorization": f"Bearer {secret}",
                "Idempotency-Key": str(row["event_id"]),
                "X-Saas-Event-Stream": row["stream"],
            },
            follow_redirects=False,
        )
        success = 200 <= response.status_code < 300
    except httpx.HTTPError:
        success = False
    finish(pool, row, success)
    return True
