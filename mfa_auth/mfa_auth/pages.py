"""Minimal HTML pages served by the auth server."""

PREPARE_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>SSH MFA</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;line-height:1.5}
code{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px}</style></head>
<body>
<h1>SSH MFA authentication server</h1>
<p>This server grants time-limited SSH access after SAML authentication.</p>
<p>It is normally driven by the <code>mfa-ssh</code> CLI, not visited by hand.</p>
<p>API: <code>/api/v1/challenges</code> &middot; SAML: <code>/saml/login</code>, <code>/saml/acs</code></p>
</body></html>"""

RESULT_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>{{ title }}</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;line-height:1.5}
.ok{color:#0a5a2a}.bad{color:#8a1a1a}.card{padding:1.5rem;border-radius:8px;background:#f7f7f7}</style></head>
<body><div class="card">
<h1 class="{{ 'ok' if ok else 'bad' }}">{{ title }}</h1>
<p>{{ message }}</p>
{% if ok %}<p>You can close this tab and retry <code>ssh</code>.</p>{% endif %}
</div></body></html>"""
