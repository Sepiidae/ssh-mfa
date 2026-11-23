# Auth server (SAML Service Provider) for SSH MFA.
#
# Runs ONCE, behind a TLS-terminating reverse proxy (nginx). The SAML ACS
# endpoint requires https, so the proxy terminates TLS and forwards plain HTTP
# to this container on 8443.
#
# Python is pinned to 3.12: python-saml (via its xmlsec dependency) needs to
# build a C extension and does not build on newer interpreters such as 3.14.
FROM python:3.12-slim

# python-saml -> xmlsec needs libxml2 + xmlsec1 headers to compile.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libxml2-dev libxmlsec1-dev libxmlsec1-openssl pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user.
RUN groupadd --system mfa && useradd --system --gid mfa --create-home mfa

WORKDIR /app

# Install the shared store first (mfa_auth depends on it), then the auth server.
COPY mfa_store /app/mfa_store
COPY mfa_auth /app/mfa_auth
RUN pip install --no-cache-dir ./mfa_store ./mfa_auth

# Default config. Override by mounting your own at /etc/ssh-mfa/mfa.yaml
# (or set MFA_AUTH_CONFIG); the baked copy just makes the image runnable as-is.
COPY config/mfa.yaml /etc/ssh-mfa/mfa.yaml
ENV MFA_AUTH_CONFIG=/etc/ssh-mfa/mfa.yaml

RUN mkdir -p /var/lib/ssh-mfa /var/log/ssh-mfa \
    && chown -R mfa:mfa /var/lib/ssh-mfa /var/log/ssh-mfa /app

USER mfa
EXPOSE 8443

# The SQLite store (default backend) lives here; mount a volume to persist it.
# Redis/Postgres backends don't need local state.
VOLUME ["/var/lib/ssh-mfa"]

# Liveness: the root page is always served (even when SAML is unavailable).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; \
r=urllib.request.urlopen('http://127.0.0.1:8443/'); \
sys.exit(0 if r.status == 200 else 1)"

CMD ["mfa-auth", "--host", "0.0.0.0", "--port", "8443"]
