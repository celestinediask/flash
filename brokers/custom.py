"""Custom broker: any broker server that speaks the Dhan v2 order/position/fund API and offers an API key + secret
browser login (consent, approve page, redirect back, token exchange). You give the app its URL, client ID, app name,
API key and secret in the page. Everything except the login and the instrument list is inherited from DhanBroker.
"""
import json
import os
from urllib.parse import quote

import requests

from .base import BrokerError
from .dhan import DhanBroker


class CustomBroker(DhanBroker):
    name = "custom"
    display_name = "Custom broker"
    config_fields = ({"name": "base_url", "label": "Broker URL", "env": "CUSTOM_BROKER_URL", "kind": "url"},
                     {"name": "client_id", "label": "Client ID", "env": "CUSTOM_CLIENT_ID"})
    auth_kinds = ("oauth",)
    oauth_label = "API key"
    oauth_help = ("Enter the broker URL and client ID under Settings, then the app name, API key and API secret your broker gave you. "
                  "Save, then log in on the broker's page that opens. The broker sends you back to the redirect URL below "
                  "and the app verifies the login.")
    verify_requires_login = True  # the key is only proven by completing a login
    supports_super_orders = False
    supports_postback = False
    token_msg = "Custom broker login missing/expired - log in again from the broker credentials section"
    instrument_file = "custom-instruments.json"

    def __init__(self, config=None, token_provider=None):
        super().__init__(config, token_provider)
        self.url = self.config["base_url"].rstrip("/")
        self.base = self.url + "/v2"

    def env_token(self):
        return ""

    def _get(self, method, path, api_key, api_secret, **kw):
        try:
            r = requests.request(method, self.url + path, headers={"app_id": api_key, "app_secret": api_secret}, timeout=10, **kw)
            return r.status_code, r.json()
        except requests.RequestException:
            raise BrokerError(f"could not reach the broker at {self.url}", 502)
        except ValueError:
            raise BrokerError("the broker sent an unreadable answer", 502)

    def oauth_start(self, api_key, api_secret):
        code, j = self._get("POST", "/auth/consent", api_key, api_secret, params={"client_id": self.client_id})
        cid = j.get("consentAppId") if isinstance(j, dict) else None
        if not cid:
            raise BrokerError(f"the broker rejected the client ID / API key / secret: {j.get('message') if isinstance(j, dict) else code}", 400)
        return f"{self.url}/auth/login?consentAppId={quote(cid, safe='')}", cid

    def oauth_finish(self, api_key, api_secret, params):
        code, j = self._get("GET", "/auth/consume", api_key, api_secret, params={"tokenId": params.get("tokenId", "")})
        try:
            return j["accessToken"], float(j["expiryTime"])
        except (KeyError, TypeError, ValueError):
            raise BrokerError("the broker did not return a token", 502)

    def load_instruments(self, cache_dir, refresh=False):
        """The broker's own stock list (GET /instruments, a JSON list). Fetched when asked ("Download latest") and also
        once automatically when there is no saved copy yet; otherwise read from the saved copy."""
        path = os.path.join(cache_dir, self.instrument_file)
        if refresh or not os.path.exists(path):
            try:
                r = requests.get(self.url + "/instruments", timeout=10)
                r.raise_for_status()
                rows = r.json()
            except (requests.RequestException, ValueError):
                if refresh:
                    raise BrokerError("could not download the instrument list from the broker", 502)
                rows = None
            if rows:
                with open(path + ".tmp", "w") as f:
                    json.dump(rows, f)
                os.replace(path + ".tmp", path)
        try:
            with open(path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return []
