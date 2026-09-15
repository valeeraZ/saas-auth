import threading
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from saas_auth.outbox import claim, deliver_once, finish


def test_leases_ordering_retry_and_fencing(env, headers):
    env.client.post(env.path, headers=headers, json={"key": "viewer", "description": ""})
    with ThreadPoolExecutor(max_workers=4) as executor:
        rows = [r for r in executor.map(lambda _: claim(env.pool), range(4)) if r]
    # The two independent streams may progress in parallel, but not two events in one stream.
    assert len(rows) == 2
    assert {r["stream"] for r in rows} == {"lifecycle", "authorization"}
    old = next(r for r in rows if r["stream"] == "authorization")
    with env.pool.connection() as conn:
        conn.execute(
            "UPDATE outbox SET lease_until=now()-interval '1 second' WHERE event_id=%s",
            (old["event_id"],),
        )
    new = claim(env.pool)
    assert new["event_id"] == old["event_id"]
    assert new["lease_id"] != old["lease_id"]
    assert finish(env.pool, old, True) is False
    assert finish(env.pool, new, False) is True
    assert claim(env.pool) is None
    with env.pool.connection() as conn:
        conn.execute("UPDATE outbox SET available_at=now() WHERE event_id=%s", (old["event_id"],))
    retry = claim(env.pool)
    assert retry["event_id"] == old["event_id"]
    assert finish(env.pool, retry, True)
    following = claim(env.pool)
    assert following["stream"] == "authorization"
    assert following["sequence"] == retry["sequence"] + 1


def test_http_delivery_uses_stable_event_id_and_retries_non_success(env):
    received = []
    state = {"status": 503}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(
                (
                    self.headers["Idempotency-Key"],
                    self.rfile.read(int(self.headers["Content-Length"])),
                )
            )
            self.send_response(state["status"])
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}/events"
        assert deliver_once(env.pool, endpoint, "test-secret")
        first_id = received[0][0]
        with env.pool.connection() as conn:
            assert (
                conn.execute(
                    "SELECT delivered_at FROM outbox WHERE event_id=%s", (first_id,)
                ).fetchone()["delivered_at"]
                is None
            )
            conn.execute(
                "UPDATE outbox SET available_at=now()-interval '1 second' WHERE event_id=%s",
                (first_id,),
            )
        state["status"] = 204
        assert deliver_once(env.pool, endpoint, "test-secret")
        assert received[1] == received[0]
        with env.pool.connection() as conn:
            assert (
                conn.execute(
                    "SELECT delivered_at FROM outbox WHERE event_id=%s", (first_id,)
                ).fetchone()["delivered_at"]
                is not None
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
