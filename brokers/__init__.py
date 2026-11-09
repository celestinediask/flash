"""Broker registry. Several brokers can be configured at once; the active one is chosen in the UI
(first run: the BROKER env var, default dhan).

To add a broker: subclass brokers.base.Broker, then register it in REGISTRY below.
"""
import json
import os

from .base import Broker, BrokerError, OPEN_STATUSES  # noqa: F401
from .dhan import DhanBroker

REGISTRY = {DhanBroker.name: DhanBroker}


def load_saved_config(root, name):
    """Non-secret settings saved from the UI: <root>/creds/<name>/config.json."""
    try:
        with open(os.path.join(root, "creds", name, "config.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def available(root):
    """[{name, label, configured}] for every registered broker."""
    out = []
    for n, c in REGISTRY.items():
        out.append({"name": n, "label": c.display_name or n, "configured": c.is_configured(load_saved_config(root, n))})
    return out


def get_broker(name=None, config=None, **kw):
    name = (name or os.environ.get("BROKER") or "dhan").lower()
    if name not in REGISTRY:
        raise SystemExit(f"Unknown BROKER '{name}'. Available: {', '.join(sorted(REGISTRY))}")
    return REGISTRY[name](config=config or {}, **kw)
