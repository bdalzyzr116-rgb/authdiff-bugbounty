"""Intentionally vulnerable Flask lab for AuthDiff demos.

DO NOT deploy this anywhere reachable. It exists solely so you can run AuthDiff
end-to-end locally and watch a BOLA / mass-assignment / race be proven.

Users:  alice (token "alice-token"), bob (token "bob-token")
Run:    python testlab/app.py    # serves on http://127.0.0.1:5000
"""

from __future__ import annotations

import threading
import time

from flask import Flask, jsonify, request

app = Flask(__name__)

TOKENS = {"alice-token": "alice", "bob-token": "bob"}
PROFILES: dict[str, dict[str, str]] = {"alice": {"bio": ""}, "bob": {"bio": ""}}
COUPON = {"remaining": 1}
_lock = threading.Lock()


def _who() -> str | None:
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    return TOKENS.get(token)


@app.get("/api/profile/<user>")
def get_profile(user: str):
    # VULNERABLE: no ownership check — any authenticated user reads any profile.
    if _who() is None:
        return jsonify(error="unauthenticated"), 401
    if user not in PROFILES:
        return jsonify(error="not found"), 404
    return jsonify(user=user, **PROFILES[user])


@app.put("/api/profile")
def put_profile():
    # VULNERABLE to mass assignment: blindly merges the JSON body.
    me = _who()
    if me is None:
        return jsonify(error="unauthenticated"), 401
    PROFILES[me].update(request.get_json(force=True) or {})
    return jsonify(user=me, **PROFILES[me])


@app.post("/api/coupon/redeem")
def redeem():
    # VULNERABLE race: check-then-act without atomicity (sleep widens the window).
    if _who() is None:
        return jsonify(error="unauthenticated"), 401
    if COUPON["remaining"] > 0:
        time.sleep(0.05)
        COUPON["remaining"] -= 1
        return jsonify(status="redeemed")
    return jsonify(status="exhausted"), 409


if __name__ == "__main__":  # pragma: no cover
    app.run(host="127.0.0.1", port=5000)
