"""SAML 2.0 Service Provider.

Wraps ``python-saml`` (onelogin) to:

  * build an AuthnRequest and return the redirect URL the browser should open;
  * process the IdP's POSTed SAML Response at the ACS endpoint, verifying the
    signature against the IdP certificate, checking audience and validity
    windows, and extracting the authenticated identity.

The IdP is **not** hard-coded. Configure it in ``config/mfa.yaml`` either by
pointing at the IdP's metadata document (preferred):

    saml:
      idp:
        metadata_url: https://idp.example.org/idp.xml

or a federation metadata aggregate (select the IdP with ``entity_id``):

    saml:
      idp:
        federation_metadata_url: https://idp.example.org/federation.xml
        entity_id: https://idp.example.org/idp

or with explicit values:

    saml:
      idp:
        entity_id: https://idp.example.org/saml
        sso_url: https://idp.example.org/sso
        slo_url: https://idp.example.org/slo
        x509cert: |
          -----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----

Metadata is fetched once at startup and parsed with the standard library; the
extracted signing certificate is pinned into the SP settings so assertion
signatures are verified against it. Explicit values always override metadata.
"""

from __future__ import annotations

import urllib.request
import xml.etree.ElementTree as ET
from typing import Optional

from .challenge import State

# onelogin_saml2 is an optional runtime dependency; import lazily so the rest
# of the package (challenge store, API) still works without it installed.
try:  # pragma: no cover - exercised only when python-saml is installed
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.settings import OneLogin_Saml2_Settings
    _HAVE_SAML = True
except Exception:  # noqa: BLE001  # pragma: no cover
    _HAVE_SAML = False


class SamlError(Exception):
    pass


SAML_MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
HTTP_POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
HTTP_REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _find_idp_descriptor(scope: ET.Element) -> Optional[ET.Element]:
    for el in scope.iter():
        if _localname(el.tag) == "IDPSSODescriptor":
            return el
    return None


def _extract_signing_cert(idp: ET.Element) -> str:
    fallback = ""
    for kd in idp:
        if _localname(kd.tag) != "KeyDescriptor":
            continue
        use = kd.get("use")
        if use == "encryption":
            continue
        for cert in kd.iter():
            if _localname(cert.tag) == "X509Certificate" and cert.text:
                cand = "".join(cert.text.split())
                if use == "signing":
                    return cand
                fallback = fallback or cand
    return fallback


def parse_idp_metadata(xml_text: str, entity_id: Optional[str] = None) -> dict:
    """Extract IdP connection details from a SAML metadata document.

    Accepts a single-IdP ``EntityDescriptor`` or a federation
    ``EntitiesDescriptor`` (in which case ``entity_id`` selects the entry, else
    the sole IdP must be unambiguous). Returns
    ``{entity_id, sso_url, slo_url, x509cert}``.
    """

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise SamlError(f"invalid IdP metadata XML: {exc}") from exc

    candidates = []
    for ent in root.iter():
        if _localname(ent.tag) != "EntityDescriptor":
            continue
        idp = _find_idp_descriptor(ent)
        if idp is None:
            continue
        eid = ent.get("entityID")
        if entity_id and eid and eid != entity_id:
            continue
        candidates.append((eid, idp))
    if not candidates:
        raise SamlError("no IDPSSODescriptor found in IdP metadata")
    if entity_id is None and len(candidates) > 1:
        raise SamlError(
            "metadata contains multiple IdPs; set idp.entity_id to select one")

    eid, idp = candidates[0]
    sso_url = slo_url = None
    for svc in idp:
        name = _localname(svc.tag)
        binding = svc.get("Binding")
        if name == "SingleSignOnService" and binding == HTTP_POST_BINDING:
            sso_url = svc.get("Location")
        elif name == "SingleLogoutService" and binding == HTTP_REDIRECT_BINDING:
            slo_url = svc.get("Location")
    if sso_url is None:  # fall back to any SSO binding if POST wasn't advertised
        for svc in idp:
            if _localname(svc.tag) == "SingleSignOnService":
                sso_url = svc.get("Location")
                break

    return {
        "entity_id": eid or "",
        "sso_url": sso_url or "",
        "slo_url": slo_url or "",
        "x509cert": _extract_signing_cert(idp),
    }


def fetch_idp_metadata(url: str, timeout: float = 20.0) -> str:
    """Fetch a metadata document over HTTPS."""

    req = urllib.request.Request(url, headers={"User-Agent": "ssh-mfa/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def _resolve_idp(cfg: dict) -> dict:
    """Fill in IdP settings from metadata, letting explicit values win."""

    idp = dict(cfg.get("idp", {}))
    meta_url = idp.get("metadata_url") or idp.get("federation_metadata_url")
    if meta_url:
        try:
            xml_text = fetch_idp_metadata(meta_url)
        except Exception as exc:  # noqa: BLE001
            raise SamlError(f"cannot fetch IdP metadata from {meta_url}: {exc}") from exc
        parsed = parse_idp_metadata(xml_text, entity_id=idp.get("entity_id"))
        for key in ("entity_id", "sso_url", "slo_url", "x509cert"):
            idp[key] = idp.get(key) or parsed.get(key) or ""
    return idp


def settings_from_config(cfg: dict) -> dict:
    """Build an ``onelogin`` settings dict from application config."""

    idp = _resolve_idp(cfg)
    sp = cfg.get("sp", {})
    if not idp.get("sso_url"):
        raise SamlError(
            "no IdP configured: set idp.metadata_url / idp.federation_metadata_url "
            "or explicit idp.sso_url, idp.entity_id, idp.x509cert")
    return {
        "strict": True,
        "debug": bool(cfg.get("debug", False)),
        "sp": {
            "entityId": sp.get("entity_id"),
            "assertionConsumerService": {
                "url": sp.get("acs_url"),
                "binding": HTTP_POST_BINDING,
            },
            "singleLogoutService": {
                "url": sp.get("sls_url"),
                "binding": HTTP_REDIRECT_BINDING,
            },
            "NameIDFormat": sp.get("name_id_format",
                                   "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"),
            "x509cert": sp.get("x509cert", ""),
            "privateKey": sp.get("private_key", ""),
        },
        "idp": {
            "entityId": idp.get("entity_id"),
            "singleSignOnService": {
                "url": idp.get("sso_url"),
                "binding": HTTP_POST_BINDING,
            },
            "singleLogoutService": {
                "url": idp.get("slo_url"),
                "binding": HTTP_REDIRECT_BINDING,
            },
            "x509cert": idp.get("x509cert", ""),
        },
        "security": {
            "authnRequestsSigned": bool(sp.get("authn_signed", False)),
            "logoutRequestSigned": False,
            "logoutResponseSigned": False,
            "wantMessagesSigned": bool(cfg.get("want_messages_signed", True)),
            "wantAssertionsSigned": bool(cfg.get("want_assertions_signed", True)),
            "wantAssertionsEncrypted": bool(cfg.get("want_assertions_encrypted", False)),
            "wantNameId": True,
            "signMetadata": False,
            "requestedAuthnContext": False,
            # Accept the IdP's own cert as the assertion signer (many IdPs sign
            # with the same cert that appears in their metadata).
            "rejectDeprecatedAlgorithm": True,
        },
        "contactPerson": cfg.get("contact", {}),
        "organization": cfg.get("organization", {}),
    }


class SamlSP:
    """Thin wrapper around onelogin_saml2 for the SSH MFA flow."""

    def __init__(self, cfg: dict, base_path: Optional[str] = None):
        if not _HAVE_SAML:
            raise SamlError(
                "python-saml (onelogin_saml2) is required for SAML; "
                "pip install python-saml"
            )
        self._settings = OneLogin_Saml2_Settings(settings_from_config(cfg),
                                                  custom_base_path=base_path)
        self._cfg = cfg

    def _request_info(self, request: dict) -> dict:
        """Normalise a framework request into onelogin's expected shape."""

        if "https" in request:
            return request
        # Flask-style request adaptation
        return {
            "https": "on" if request.get("scheme") == "https" else "off",
            "http_host": request.get("host", ""),
            "server_port": request.get("port", ""),
            "script_name": request.get("script_name", "") or "",
            "path_info": request.get("path", "") or "",
            "query_string": request.get("query_string", "") or "",
        }

    def login_url(self, request: dict, relay_state: str) -> str:
        """Return the IdP SSO URL the browser should be redirected to."""

        auth = OneLogin_Saml2_Auth(self._request_info(request),
                                   custom_base_path=self._settings)
        return auth.login(relay_state)

    def process_response(self, request: dict) -> dict:
        """Validate the IdP response and return ``{identity, attributes, relay_state}``.

        Raises :class:`SamlError` on any validation failure — an unauthenticated
        response must never result in an approval.
        """

        auth = OneLogin_Saml2_Auth(self._request_info(request),
                                   custom_base_path=self._settings)
        auth.process_response()
        errors = auth.get_errors()
        if errors:
            reason = auth.get_last_error_reason()
            raise SamlError(f"SAML validation failed: {errors} {reason}")
        if not auth.is_authenticated():
            raise SamlError("SAML response was not authenticated")
        relay_state = auth.get_relay_state() or ""
        nameid = auth.get_nameid()
        attributes = auth.get_attributes()
        # Prefer a useful identity: eduPersonPrincipalName if present, else NameID.
        identity = (attributes.get("urn:oid:1.3.6.1.4.1.5923.1.1.1.6", [None])[0]
                    or nameid or "")
        return {"identity": identity, "attributes": attributes,
                "relay_state": relay_state}

    def logout_url(self, request: dict) -> str:
        auth = OneLogin_Saml2_Auth(self._request_info(request),
                                   custom_base_path=self._settings)
        return auth.logout()
