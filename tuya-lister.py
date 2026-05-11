#!/usr/bin/env python3
"""
Tuya Cloud Device Lister
Reads devices from Tuya Cloud API and displays them in a sorted, pretty table.
Credentials are loaded from a .config file with NAME=VALUE format.
"""

import hashlib
import hmac
import os
import sys
import time
from configparser import ConfigParser
from urllib.parse import quote

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

try:
    from prettytable import PrettyTable
except ImportError:
    sys.exit("Missing dependency: pip install prettytable")


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

CONFIG_FILE = ".config"
TUYA_BASE_URL = "https://openapi.tuyaus.com"  # Change region as needed


def load_config(path: str = CONFIG_FILE) -> dict:
    """Parse a simple NAME=VALUE config file (no section headers required)."""
    if not os.path.exists(path):
        sys.exit(f"Config file not found: {path}")

    # Prepend a dummy section so ConfigParser can handle headerless files
    with open(path) as f:
        content = "[default]\n" + f.read()

    parser = ConfigParser()
    parser.read_string(content)

    cfg = dict(parser["default"])
    # Normalise keys to upper-case
    return {k.upper(): v for k, v in cfg.items()}


# ---------------------------------------------------------------------------
# Tuya Cloud client
# ---------------------------------------------------------------------------

class TuyaCloud:
    def __init__(self, access_id: str, access_key: str, base_url: str = TUYA_BASE_URL):
        self.access_id = access_id
        self.access_key = access_key
        self.base_url = base_url.rstrip("/")
        self._token: str | None = None
        self._token_expiry: float = 0
        self._uid: str = ""

    # ---- auth helpers -------------------------------------------------------

    def _sign(self, method: str, path: str, body: str = "", token: str = "") -> tuple[str, str]:
        """Return (timestamp_ms, signature) for a request."""
        ts = str(int(time.time() * 1000))
        content_hash = hashlib.sha256(body.encode()).hexdigest()
        string_to_sign = "\n".join([method.upper(), content_hash, "", path])
        sign_str = self.access_id + token + ts + string_to_sign
        signature = hmac.new(
            self.access_key.encode(),
            sign_str.encode(),
            hashlib.sha256,
        ).hexdigest().upper()
        return ts, signature

    def _headers(self, method: str, path: str, body: str = "", token: str = "") -> dict:
        ts, sig = self._sign(method, path, body, token)
        headers = {
            "client_id": self.access_id,
            "t": ts,
            "sign": sig,
            "sign_method": "HMAC-SHA256",
            "Content-Type": "application/json",
        }
        if token:
            headers["access_token"] = token
        return headers

    def _get_token(self) -> str:
        if self._token and time.time() < self._token_expiry:
            return self._token

        path = "/v1.0/token?grant_type=1"
        headers = self._headers("GET", path)
        r = requests.get(self.base_url + path, headers=headers, timeout=10)
        r.raise_for_status()
        data = r.json()
        if not data.get("success"):
            sys.exit(f"Token error: {data.get('msg', data)}")

        self._token = data["result"]["access_token"]
        self._uid = data["result"].get("uid", "")
        # expire 1 minute before actual expiry
        self._token_expiry = time.time() + data["result"]["expire_time"] - 60
        return self._token

    # ---- API calls ----------------------------------------------------------

    def _get(self, path: str, params: dict | None = None) -> dict:
        token = self._get_token()
        # Build canonical query string with sorted keys (required by Tuya signing spec)
        if params:
            sorted_qs = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in sorted(params.items()))
            signed_path = f"{path}?{sorted_qs}"
        else:
            signed_path = path
        headers = self._headers("GET", signed_path, token=token)
        url = self.base_url + signed_path
        r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        return r.json()

    def get_devices(self) -> list[dict]:
        """Fetch all devices for the account using the best available endpoint."""
        # Ensure token (and uid) are loaded
        self._get_token()

        if self._uid:
            devices = self._get_devices_by_uid(self._uid)
            if devices:
                return devices
            print(f"  (uid endpoint returned 0 devices, falling back to iot-01 endpoint)")

        return self._get_devices_iot01()

    def _get_devices_by_uid(self, uid: str) -> list[dict]:
        """
        /v1.0/users/{uid}/devices — supports true page_no/page_size pagination,
        up to 100 per page, and typically returns all device types.
        """
        devices = []
        page_no, page_size = 1, 100

        while True:
            data = self._get(f"/v1.0/users/{uid}/devices",
                             params={"page_no": page_no, "page_size": page_size})
            if not data.get("success"):
                print(f"  Warning: uid-based endpoint error: {data.get('msg', data)}")
                return []

            result = data.get("result", {})
            if isinstance(result, list):
                batch = result
                total = len(result)
            else:
                batch = result.get("devices", result.get("list", []))
                total = result.get("total", 0)

            devices.extend(batch)
            print(f"  Page {page_no}: got {len(batch)} device(s)  (running total: {len(devices)}"
                  + (f" / {total}" if total else "") + ")")

            if len(batch) < page_size:
                break
            if total and len(devices) >= total:
                break
            page_no += 1

        return devices

    def _get_devices_iot01(self) -> list[dict]:
        """
        /v1.0/iot-01/associated-users/devices — cursor-based pagination via
        last_row_key; hard-limited to 20 per page by Tuya regardless of page_size.
        """
        devices = []
        last_row_key = ""
        page_size = 20  # Tuya enforces this max for this endpoint

        while True:
            params: dict = {"page_size": page_size}
            if last_row_key:
                params["last_row_key"] = last_row_key  # _get will quote it

            data = self._get("/v1.0/iot-01/associated-users/devices", params=params)
            if not data.get("success"):
                sys.exit(f"Device list error: {data.get('msg', data)}")

            result = data.get("result", {})
            batch = result.get("devices", result.get("list", []))
            devices.extend(batch)

            last_row_key = result.get("last_row_key", "")
            has_more = result.get("has_more", False)

            print(f"  Cursor page: got {len(batch)} device(s)  (running total: {len(devices)})")

            if not has_more or not last_row_key or len(batch) == 0:
                break

        return devices

    def get_device_status(self, device_id: str) -> dict:
        """Return {code: value} status map for a device."""
        path = f"/v1.0/devices/{device_id}/status"
        data = self._get(path)
        if not data.get("success"):
            return {}
        return {item["code"]: item["value"] for item in data.get("result", [])}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def online_label(online: bool | None) -> str:
    if online is True:
        return "✓ online"
    if online is False:
        return "✗ offline"
    return "unknown"


def status_summary(status: dict) -> str:
    """Build a compact, human-readable status string from status codes."""
    if not status:
        return "—"

    priority = ["switch", "switch_1", "power", "bright_value", "temp_value",
                "colour_data", "work_mode", "countdown", "humidity_value",
                "temp_current", "va_temperature", "va_humidity"]

    parts = []
    seen = set()

    # Show priority keys first
    for key in priority:
        if key in status:
            parts.append(f"{key}={status[key]}")
            seen.add(key)

    # Then the rest (up to a total of 5 entries)
    for k, v in status.items():
        if k not in seen:
            parts.append(f"{k}={v}")
        if len(parts) >= 5:
            break

    return "  |  ".join(parts) if parts else "—"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    cfg = load_config()

    access_id = cfg.get("TUYA_ACCESS_ID", "").strip()
    access_key = cfg.get("TUYA_ACCESS_KEY", "").strip()

    if not access_id or not access_key:
        sys.exit("TUYA_ACCESS_ID and TUYA_ACCESS_KEY must be set in .config")

    base_url = cfg.get("TUYA_BASE_URL", TUYA_BASE_URL).strip()

    print(f"Connecting to Tuya Cloud  ({base_url}) …")
    cloud = TuyaCloud(access_id, access_key, base_url)

    print("Fetching device list …")
    devices = cloud.get_devices()

    if not devices:
        print("No devices found.")
        return

    print(f"Found {len(devices)} device(s). Fetching status …\n")

    rows = []
    for dev in devices:
        dev_id = dev.get("id", "")
        name = dev.get("name", "") or dev.get("local_key", dev_id)
        category = dev.get("category", "")
        product_name = dev.get("product_name", "")
        ip = dev.get("ip", "")
        online = dev.get("online")

        status = cloud.get_device_status(dev_id)

        rows.append({
            "Name": name,
            "ID": dev_id,
            "Category": category,
            "Product": product_name,
            "IP": ip,
            "Connection": online_label(online),
            "Status": status_summary(status),
        })

    # Sort by friendly name (case-insensitive)
    rows.sort(key=lambda r: r["Name"].lower())

    headers = ["Name", "ID", "Category", "Product", "IP", "Connection", "Status"]

    table = PrettyTable(headers)
    table.align = "l"
    table.align["Connection"] = "c"
    for r in rows:
        table.add_row([r[h] for h in headers])

    print(table)
    print(f"\nTotal: {len(rows)} device(s)")


if __name__ == "__main__":
    main()