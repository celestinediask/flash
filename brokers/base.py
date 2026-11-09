"""Broker adapter interface.

Every method that talks to the broker returns ``(http_status, body)``. Bodies use the
broker-neutral schema below; each adapter translates its broker's native payloads to and from it,
so nothing outside ``brokers/`` knows a broker's field names.

Neutral schema (all keys snake_case)
  status    : PENDING | PARTIAL | FILLED | CANCELLED | REJECTED
  side      : BUY | SELL;  order_type: MARKET | LIMIT;  product: CNC | INTRADAY | MARGIN | MTF
  exchange  : NSE_EQ | BSE_EQ
  funds     : {available}
  position  : {symbol, security_id, exchange, product, net_qty, buy_qty, sell_qty, buy_avg, sell_avg,
               avg_price, realized_pnl, unrealized_pnl, last_price}   (last_price may be None)
  order     : {order_id, status, symbol, side, order_type, product, qty, price, time, message,
               security_id, exchange}
  trade     : {order_id, trade_id, time, symbol, side, qty, price}
  super order: {order_id, legs: [{leg, status}]}  (only legs that can still be cancelled)
  place/cancel result: {order_id, status}
  instrument: {symbol, name, security_id, exchange, tick}
  errors    : {error: str}; if the credentials were rejected also {token_invalid: True, detail: str}
"""
import os
from abc import ABC, abstractmethod

OPEN_STATUSES = ("PENDING", "PARTIAL")


class BrokerError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class Broker(ABC):
    name = ""            # registry key, matched against the BROKER env var / UI selector
    display_name = ""
    # Non-secret settings the user enters in the UI, e.g. [{"name": "client_id", "label": "Client ID", "env": "X_CLIENT_ID"}].
    # A value saved in the UI wins over the (optional) environment variable.
    config_fields = ()

    def __init__(self, config=None, token_provider=None):
        config = config or {}
        self.config = {f["name"]: str(config.get(f["name"]) or os.environ.get(f.get("env", ""), "")) for f in self.config_fields}
        self.token_provider = token_provider or self.env_token

    @classmethod
    def is_configured(cls, config):
        return all(config.get(f["name"]) or os.environ.get(f.get("env", "")) for f in cls.config_fields)

    # --- credentials -----------------------------------------------------------------------
    # "token": a pasted access token.  "oauth": API key/secret + browser login that mints a token.
    auth_kinds = ()
    token_label = "Access token"
    oauth_label = "API key"
    oauth_help = ""      # shown above the API key form (e.g. which URLs to register)

    def env_token(self):
        """Token supplied through the environment, if the broker has one."""
        return ""

    def oauth_start(self, api_key, api_secret):
        """Begin the login. Returns (login_url, pending_id). Raises BrokerError."""
        raise BrokerError("OAuth login not supported by this broker", 501)

    def oauth_finish(self, api_key, api_secret, params):
        """Finish the login from the redirect's query params. Returns (token, expiry_unix). Raises BrokerError."""
        raise BrokerError("OAuth login not supported by this broker", 501)

    # --- postbacks -------------------------------------------------------------------------
    supports_postback = False

    def parse_postback(self, data):
        """Validate a pushed order update and return a neutral order dict (see schema) plus
        ``filled_qty``. Raises BrokerError (status 403 for a foreign account, 400 for junk)."""
        raise BrokerError("postbacks not supported by this broker", 501)

    # --- trading ---------------------------------------------------------------------------
    @abstractmethod
    def make_order(self, *, side, exchange, product, order_type, security_id, qty,
                   price=0.0, correlation_id="", validity="DAY"):
        """Build the broker-native order payload."""

    @abstractmethod
    def place_order(self, order): ...

    @abstractmethod
    def cancel_order(self, order_id): ...

    @abstractmethod
    def get_order(self, order_id): ...

    @abstractmethod
    def orders(self): ...

    @abstractmethod
    def positions(self): ...

    @abstractmethod
    def funds(self, token=None): ...

    @abstractmethod
    def trades(self, from_date, to_date, page=0): ...

    @abstractmethod
    def trades_today(self): ...

    @abstractmethod
    def load_instruments(self, cache_dir):
        """Return a list of instrument dicts (see module docstring)."""

    # Optional: bracket/super orders.
    supports_super_orders = False

    def super_orders(self):
        return 501, {"error": "super orders not supported by this broker"}

    def cancel_super_leg(self, order_id, leg):
        return 501, {"error": "super orders not supported by this broker"}

    def cancel_entry_leg(self, order_id):
        return self.cancel_super_leg(order_id, "ENTRY_LEG")
