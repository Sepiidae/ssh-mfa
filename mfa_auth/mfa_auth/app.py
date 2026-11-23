"""Flask application: the SSH MFA authentication server.

Endpoints
---------
API (used by the CLI / watcher, JSON):

* ``POST /api/v1/challenges``  — prepare a login; binds username+pubkey, returns
  the challenge id and the SAML URL to open.
* ``GET  /api/v1/challenges/<id>`` — poll a challenge's state.
* ``DELETE /api/v1/challenges/<id>`` — cancel a challenge.

SAML (followed by the browser):

* ``GET  /saml/login``  — begin SSO, carrying the challenge id as RelayState.
* ``POST /saml/acs``    — IdP callback; validates the assertion, then grants the
  challenge's (username, pubkey) in the shared store if the IdP subject is
  allowed, and redirects the browser to a result page.
* ``GET  /saml/metadata`` — this SP's metadata (for registering with the IdP).

The grant decision is pluggable via ``AUTHZ`` in config: by default any
authenticated identity whose username matches the challenge is allowed; a
deployment can restrict to an allowlist of identities.
"""

from __future__ import annotations

import time

from flask import Flask, jsonify, request, redirect, render_template_string

from .challenge import ChallengeStore, State, ChallengeError
from .sp import SamlSP, SamlError
from .store_bridge import get_store, write_approval, list_approvals, revoke_approval
from .pages import PREPARE_HTML, RESULT_HTML


def _pubkey_from_request(payload: dict) -> str:
    pk = (payload.get("pubkey") or "").strip()
    if not pk:
        raise ChallengeError("pubkey is required")
    parts = pk.split()
    if len(parts) < 2 or not parts[0].startswith("ssh-") and not parts[0].startswith("ecdsa-"):
        raise ChallengeError("pubkey must be an SSH public key (ssh-ed25519 / ssh-rsa / ecdsa-*)")
    return " ".join(parts[:2]) + (f" {parts[2]}" if len(parts) > 2 else "")


def create_app(config: dict) -> Flask:
    app = Flask(__name__)
    app.config["MFA"] = config
    challenges = ChallengeStore(ttl_seconds=int(config.get("challenge_ttl", 300)))
    try:
        sp = SamlSP(config) if config.get("saml", {}).get("enabled", True) else None
    except SamlError as exc:
        # SAML library missing or misconfigured: keep the API running so the
        # store/challenge logic still works; SAML endpoints will report 503.
        app.logger.warning("SAML unavailable, disabling SSO: %s", exc)
        sp = None
    store = get_store(config)
    app.extensions["mfa"] = {
        "challenges": challenges, "sp": sp, "store": store,
    }

    def allow_identity(identity: str, username: str) -> bool:
        authz = config.get("authz", {})
        allow = authz.get("allow_identities")
        if allow:
            return identity in allow
        # Default: the IdP subject's local part must match the target username.
        local = identity.split("@")[0] if identity else ""
        return local == username or identity == username

    @app.post("/api/v1/challenges")
    def api_prepare():
        payload = request.get_json(silent=True) or {}
        try:
            username = (payload.get("username") or "").strip()
            if not username:
                raise ChallengeError("username is required")
            pubkey = _pubkey_from_request(payload)
        except ChallengeError as exc:
            return jsonify({"error": str(exc)}), 400

        from mfa_store.base import _key_fingerprint
        fp = _key_fingerprint(pubkey)
        ch = challenges.create(username, pubkey, fp)
        req = {"scheme": request.scheme, "host": request.host,
               "script_name": request.script_root, "path": request.path}
        saml_url = None
        if sp is not None:
            try:
                saml_url = sp.login_url(req, relay_state=ch.id)
            except SamlError as exc:
                return jsonify({"error": f"SAML unavailable: {exc}"}), 503
        return jsonify({
            "challenge_id": ch.id,
            "username": username,
            "fingerprint": fp,
            "state": ch.state.value,
            "saml_url": saml_url,
            "expires_at": ch.expires_at,
        })

    @app.get("/api/v1/challenges/<cid>")
    def api_status(cid):
        ch = challenges.get(cid)
        if ch is None:
            return jsonify({"error": "unknown or expired challenge"}), 404
        return jsonify(ch.to_json())

    @app.get("/api/v1/approvals")
    def api_approvals():
        """Approvals granted since ?since=<epoch> — consumed by the watcher."""

        since = float(request.args.get("since", 0) or 0)
        # The auth server is itself the source of truth here; it re-reads its
        # own store so the watcher can replicate to target hosts.
        try:
            rows = store.list_since(since)
        except Exception:
            rows = []
        return jsonify({
            "server_time": time.time(),
            "approvals": [a.to_json() for a in rows],
        })

    @app.delete("/api/v1/challenges/<cid>")
    def api_cancel(cid):
        ch = challenges.get(cid)
        if ch is None:
            return jsonify({"error": "unknown or expired challenge"}), 404
        if ch.state in (State.APPROVED,):
            return jsonify({"error": "already approved; cannot cancel"}), 409
        challenges.transition(cid, State.FAILED, error="cancelled")
        return jsonify({"status": "cancelled"})

    @app.get("/saml/login")
    def saml_login():
        if sp is None:
            return "SAML disabled", 503
        cid = request.args.get("cid", "")
        ch = challenges.get(cid)
        if ch is None:
            return "unknown or expired challenge", 400
        req = {"scheme": request.scheme, "host": request.host,
               "script_name": request.script_root, "path": request.path}
        try:
            url = sp.login_url(req, relay_state=cid)
        except SamlError as exc:
            return f"SAML error: {exc}", 500
        return redirect(url, code=302)

    @app.post("/saml/acs")
    def saml_acs():
        if sp is None:
            return "SAML disabled", 503
        try:
            result = sp.process_response({
                "scheme": request.scheme, "host": request.host,
                "script_name": request.script_root, "path": request.path,
            })
        except SamlError as exc:
            return render_template_string(RESULT_HTML, ok=False,
                                          title="Authentication failed",
                                          message=str(exc)), 403
        identity = result["identity"]
        cid = result["relay_state"]
        ch = challenges.get(cid) if cid else None
        if ch is None:
            return render_template_string(RESULT_HTML, ok=False,
                                          title="No pending challenge",
                                          message="This login session expired or was not started here."), 400
        if not allow_identity(identity, ch.username):
            challenges.transition(cid, State.FAILED, identity=identity,
                                  error="identity not authorized")
            return render_template_string(RESULT_HTML, ok=False,
                                          title="Not authorized",
                                          message=f"{identity} may not log in as {ch.username}."), 403
        # SAML succeeded for an authorized identity: record the approval in the
        # shared store so the target host grants this pubkey.
        ttl = int(config.get("approval_ttl", 86400))
        write_approval(store, ch, identity, ttl, source=request.host)
        challenges.transition(cid, State.APPROVED, identity=identity)
        return render_template_string(RESULT_HTML, ok=True,
                                      title="Authentication successful",
                                      message=(f"Welcome, {identity}. "
                                               f"You may now complete your SSH login as {ch.username}."))

    @app.get("/saml/metadata")
    def saml_metadata():
        if sp is None:
            return "SAML disabled", 503
        from onelogin.saml2.settings import OneLogin_Saml2_Settings
        settings = OneLogin_Saml2_Settings(sp._settings.get_settings())
        return settings.get_sp_metadata(), 200, \
            {"Content-Type": "application/saml2-metadata+xml"}

    @app.get("/")
    def index():
        return render_template_string(PREPARE_HTML)

    @app.errorhandler(ChallengeError)
    def _ce(exc):
        return jsonify({"error": str(exc)}), 400

    return app
