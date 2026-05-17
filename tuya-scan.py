#!/usr/bin/env python3
"""
Tuya Cloud Device Scanner
Lists all devices grouped by home → room, with outlet names for multi-outlet
devices. Credentials are loaded from a .config file with NAME=VALUE format.
"""

import argparse
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
# Config
# ---------------------------------------------------------------------------

CONFIG_FILE   = ".config"
TUYA_BASE_URL = "https://openapi.tuyaus.com"


def load_config(path: str = CONFIG_FILE) -> dict:
    if not os.path.exists(path):
        sys.exit(f"Config file not found: {path}")
    with open(path) as f:
        content = "[default]\n" + f.read()
    parser = ConfigParser()
    parser.read_string(content)
    return {k.upper(): v for k, v in dict(parser["default"]).items()}


# ---------------------------------------------------------------------------
# Tuya Cloud client
# ---------------------------------------------------------------------------

class TuyaCloud:
    def __init__(self, access_id: str, access_key: str, base_url: str = TUYA_BASE_URL):
        self.access_id  = access_id
        self.access_key = access_key
        self.base_url   = base_url.rstrip("/")
        self._token: str | None = None
        self._token_expiry: float = 0
        self._uid: str = ""        # project/token UID (not device-owner)
        self._owner_uid: str = ""  # extracted from device records after first fetch

    def _sign(self, method: str, path: str, body: str = "", token: str = "") -> tuple[str, str]:
        ts = str(int(time.time() * 1000))
        content_hash = hashlib.sha256(body.encode()).hexdigest()
        string_to_sign = "\n".join([method.upper(), content_hash, "", path])
        sign_str = self.access_id + token + ts + string_to_sign
        signature = hmac.new(
            self.access_key.encode(), sign_str.encode(), hashlib.sha256,
        ).hexdigest().upper()
        return ts, signature

    def _headers(self, method: str, path: str, body: str = "", token: str = "") -> dict:
        ts, sig = self._sign(method, path, body, token)
        h = {"client_id": self.access_id, "t": ts, "sign": sig,
             "sign_method": "HMAC-SHA256", "Content-Type": "application/json"}
        if token:
            h["access_token"] = token
        return h

    def _get_token(self) -> str:
        if self._token and time.time() < self._token_expiry:
            return self._token
        path = "/v1.0/token?grant_type=1"
        r = requests.get(self.base_url + path, headers=self._headers("GET", path), timeout=10)
        r.raise_for_status()
        data = r.json()
        if not data.get("success"):
            sys.exit(f"Token error: {data.get('msg', data)}")
        self._token       = data["result"]["access_token"]
        self._uid         = data["result"].get("uid", "")
        self._token_expiry = time.time() + data["result"]["expire_time"] - 60
        return self._token

    def _get(self, path: str, params: dict | None = None) -> dict:
        token = self._get_token()
        if params:
            qs = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in sorted(params.items()))
            signed_path = f"{path}?{qs}"
        else:
            signed_path = path
        r = requests.get(self.base_url + signed_path,
                         headers=self._headers("GET", signed_path, token=token), timeout=10)
        r.raise_for_status()
        return r.json()

    # ---- device listing -------------------------------------------------------

    def get_devices(self) -> list[dict]:
        """
        Fetch all devices.  Uses iot-01 (cursor-based) on the first call to
        discover the device-owner UID, then switches to the faster paginated
        /v1.0/users/{owner_uid}/devices endpoint on any subsequent call.
        """
        self._get_token()

        # If we already know the owner UID, use the faster paginated endpoint
        if self._owner_uid:
            return self._get_devices_by_uid(self._owner_uid)

        # First call: use iot-01 to discover devices and extract owner UID
        devices = self._get_devices_iot01()
        owner_uid = next((d.get("uid", "") for d in devices if d.get("uid")), "")
        if owner_uid:
            self._owner_uid = owner_uid
            print(f"  Owner UID: {owner_uid}")
        return devices

    def _get_devices_by_uid(self, uid: str) -> list[dict]:
        devices, page_no, page_size = [], 1, 100
        while True:
            data = self._get(f"/v1.0/users/{uid}/devices",
                             params={"page_no": page_no, "page_size": page_size})
            if not data.get("success"):
                return []
            result = data.get("result", {})
            batch = result if isinstance(result, list) else result.get("devices", result.get("list", []))
            total = 0 if isinstance(result, list) else result.get("total", 0)
            devices.extend(batch)
            print(f"  Page {page_no}: {len(batch)} device(s)  (total so far: {len(devices)}"
                  + (f"/{total}" if total else "") + ")")
            if len(batch) < page_size or (total and len(devices) >= total):
                break
            page_no += 1
        return devices

    def _get_devices_iot01(self) -> list[dict]:
        devices, last_row_key, page_size = [], "", 20
        while True:
            params: dict = {"page_size": page_size}
            if last_row_key:
                params["last_row_key"] = last_row_key
            data = self._get("/v1.0/iot-01/associated-users/devices", params=params)
            if not data.get("success"):
                sys.exit(f"Device list error: {data.get('msg', data)}")
            result = data.get("result", {})
            batch  = result.get("devices", result.get("list", []))
            devices.extend(batch)
            last_row_key = result.get("last_row_key", "")
            if not result.get("has_more") or not last_row_key or not batch:
                break
        return devices

    # ---- home / room management -----------------------------------------------

    def get_homes(self) -> list[dict]:
        """
        Returns list of home dicts {home_id, name, ...}.
        Uses the device-owner UID discovered during get_devices(); call
        get_devices() first.
        """
        uid = self._owner_uid or self._uid
        data = self._get(f"/v1.0/users/{uid}/homes")
        if not data.get("success"):
            return []
        return data.get("result", [])

    def get_home_rooms(self, home_id) -> list[dict]:
        """Returns list of {room_id, name} dicts for a home."""
        data = self._get(f"/v1.0/homes/{home_id}/rooms")
        if not data.get("success"):
            return []
        result = data.get("result", {})
        # API returns rooms nested inside the home object
        if isinstance(result, dict):
            return result.get("rooms", [])
        return result

    def get_home_device_ids(self, home_id) -> set[str]:
        """IDs of all devices in a home. Returns empty set if not permitted."""
        data = self._get(f"/v1.0/homes/{home_id}/devices")
        if not data.get("success"):
            return set()
        result = data.get("result", {})
        devs = result if isinstance(result, list) else result.get("devices", result.get("list", []))
        return {d["id"] for d in devs if "id" in d}

    def get_room_device_ids(self, home_id, room_id) -> list[str]:
        """Returns device IDs assigned to a room."""
        data = self._get(f"/v1.0/homes/{home_id}/rooms/{room_id}/devices")
        if not data.get("success"):
            return []
        result = data.get("result", {})
        devs = result if isinstance(result, list) else result.get("devices", result.get("list", []))
        return [d["id"] for d in devs if "id" in d]

    # ---- outlet names ---------------------------------------------------------

    def get_outlet_names(self, device_id: str) -> list[dict]:
        """
        Returns [{identifier, name}, ...] for a multi-outlet device, excluding 'main'.
        Uses GET /v1.0/devices/{id}/multiple-names.
        """
        data = self._get(f"/v1.0/devices/{device_id}/multiple-names")
        if not data.get("success"):
            return []
        return [e for e in data.get("result", []) if e.get("identifier") != "main"]

    # ---- per-device status (fallback if not in listing) -----------------------

    def get_device_status(self, device_id: str) -> dict:
        data = self._get(f"/v1.0/devices/{device_id}/status")
        if not data.get("success"):
            return {}
        return {item["code"]: item["value"] for item in data.get("result", [])}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def status_from_listing(dev: dict) -> dict:
    """Extract inline status from device listing record (avoids extra API calls)."""
    raw = dev.get("status", [])
    if isinstance(raw, list):
        return {item["code"]: item["value"] for item in raw if "code" in item}
    return {}


def is_multi_outlet(status: dict) -> bool:
    """True if the device has switch_2 or higher (i.e. it's a multi-outlet device)."""
    return any(k.startswith("switch_") and k != "switch_1" for k in status)


def extract_temp_f(status: dict) -> float | None:
    for key in ("temp_value", "temp_current", "va_temperature"):
        if key in status:
            raw = status[key]
            if isinstance(raw, (int, float)):
                temp_c = raw / 10.0 if raw > 60 else float(raw)
                return temp_c * 9.0 / 5.0 + 32.0
    return None


def status_summary(status: dict) -> str:
    if not status:
        return "—"
    priority = ["switch", "switch_1", "switch_2", "switch_3", "switch_4",
                "bright_value", "temp_value", "temp_current", "va_temperature",
                "va_humidity", "humidity_value"]
    parts, seen = [], set()
    for key in priority:
        if key in status:
            parts.append(f"{key}={status[key]}")
            seen.add(key)
    for k, v in status.items():
        if k not in seen:
            parts.append(f"{k}={v}")
        if len(parts) >= 6:
            break
    return "  |  ".join(parts) if parts else "—"


def outlets_summary(outlets: list[dict]) -> str:
    """Compact string of outlet names, e.g. 'sw1:MBR Nano3s  sw3:Sensibo Ma'."""
    if not outlets:
        return ""
    parts = []
    for o in outlets:
        code = o.get("identifier", "")
        name = o.get("name", "")
        short = code.replace("switch_", "sw")
        parts.append(f"{short}:{name}" if name else short)
    return "  ".join(parts)


def build_room_map(cloud: TuyaCloud, homes: list[dict]) -> dict[str, tuple[str, str]]:
    """
    Build {device_id: (home_name, room_name)} by iterating homes → rooms → devices.
    Devices not assigned to any room will be absent from the map.
    """
    mapping: dict[str, tuple[str, str]] = {}
    for home in homes:
        home_id   = home.get("home_id") or home.get("id")
        home_name = home.get("name", "")
        rooms = cloud.get_home_rooms(home_id)
        for room in rooms:
            room_id   = room.get("room_id") or room.get("id")
            room_name = room.get("name", "")
            for did in cloud.get_room_device_ids(home_id, room_id):
                mapping[did] = (home_name, room_name)
    return mapping


def home_sort_key(homes: list[dict]) -> dict[str, int]:
    """Return {home_name: sort_index} preserving API order."""
    return {h.get("name", ""): i for i, h in enumerate(homes)}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Tuya Cloud Device Scanner")
    parser.add_argument("--no-status", action="store_true",
                        help="Suppress the Status column and temperature summary")
    parser.add_argument("--home", default=None,
                        help="Restrict output to devices in this home (case-insensitive name)")
    args = parser.parse_args()

    cfg = load_config()
    access_id  = cfg.get("TUYA_ACCESS_ID", "").strip()
    access_key = cfg.get("TUYA_ACCESS_KEY", "").strip()
    base_url   = cfg.get("TUYA_BASE_URL", TUYA_BASE_URL).strip()

    if not access_id or not access_key:
        sys.exit("TUYA_ACCESS_ID and TUYA_ACCESS_KEY must be set in .config")

    print(f"Connecting to {base_url} …")
    cloud = TuyaCloud(access_id, access_key, base_url)

    # ---- devices --------------------------------------------------------------
    print("\nFetching device list …")
    devices = cloud.get_devices()
    if not devices:
        sys.exit("No devices found.")
    print(f"  {len(devices)} device(s) found.")

    # ---- homes + room mapping -------------------------------------------------
    print("\nFetching homes and room assignments …")
    homes = cloud.get_homes()
    if not homes:
        print("  (Home management API not available; devices will list without home/room grouping)")

    if args.home:
        name_to_home = {h.get("name", "").strip().lower(): h for h in homes}
        home_entry = name_to_home.get(args.home.strip().lower())
        if not home_entry:
            avail = ", ".join(f'"{h.get("name","")}"' for h in homes) or "none"
            sys.exit(f'Home "{args.home}" not found. Available: {avail}')
        home_id = home_entry.get("home_id") or home_entry.get("id")
        home_device_ids = cloud.get_home_device_ids(home_id)
        devices = [d for d in devices if d.get("id") in home_device_ids]
        homes = [home_entry]
        print(f'  Filtered to home "{home_entry.get("name","")}": {len(devices)} device(s).')

    room_map    = build_room_map(cloud, homes)   # {device_id: (home_name, room_name)}
    home_order  = home_sort_key(homes)           # {home_name: index} for sort stability
    print(f"  {len(homes)} home(s), {len(room_map)} device(s) assigned to rooms.")

    # ---- outlet names for multi-outlet devices --------------------------------
    print("\nFetching outlet names for multi-outlet devices …")
    outlet_names: dict[str, list[dict]] = {}   # {device_id: [{identifier, name}, ...]}
    multi_count = 0
    for dev in devices:
        status = status_from_listing(dev)
        if is_multi_outlet(status):
            names = cloud.get_outlet_names(dev["id"])
            if names:
                outlet_names[dev["id"]] = names
                multi_count += 1
    print(f"  {multi_count} multi-outlet device(s) with named outlets.")

    # ---- build rows -----------------------------------------------------------
    rows = []
    for dev in devices:
        dev_id   = dev.get("id", "")
        name     = dev.get("name", "") or dev_id
        category = dev.get("category", "")
        ip       = dev.get("ip", "")
        online   = dev.get("online")
        model    = dev.get("model", "") or dev.get("product_name", "")

        home_name, room_name = room_map.get(dev_id, ("", ""))

        status   = status_from_listing(dev)
        temp_f   = extract_temp_f(status)
        stat_str = status_summary(status)
        if temp_f is not None:
            stat_str += f"  |  {temp_f:.1f}°F"

        outlets_str = outlets_summary(outlet_names.get(dev_id, []))

        online_str = {True: "online", False: "OFFLINE", None: "?"}.get(online, "?")

        rows.append({
            "home":       home_name,
            "room":       room_name,
            "name":       name,
            "cat":        category,
            "model":      model,
            "ip":         ip,
            "online":     online_str,
            "outlets":    outlets_str,
            "status":     stat_str,
            "_home_idx":  home_order.get(home_name, 999),
            "_temp_f":    temp_f,
        })

    # ---- sort: home (API order) → room name → device name --------------------
    rows.sort(key=lambda r: (r["_home_idx"], r["room"].lower(), r["name"].lower()))

    # ---- output ---------------------------------------------------------------
    headers = ["Home", "Room", "Name", "Cat", "Online", "Outlets"]
    if not args.no_status:
        headers.append("Status")
    table = PrettyTable(headers)
    table.align = "l"
    table.align["Cat"]    = "c"
    table.align["Online"] = "c"

    for i, row in enumerate(rows):
        is_last_in_home = (i == len(rows) - 1) or (rows[i + 1]["_home_idx"] != row["_home_idx"])
        cells = [
            row["home"] or "(no home)",
            row["room"] or "(no room)",
            row["name"],
            row["cat"],
            row["online"],
            row["outlets"],
        ]
        if not args.no_status:
            cells.append(row["status"])
        table.add_row(cells, divider=is_last_in_home)

    print(table)

    # ---- temperature summary --------------------------------------------------
    if not args.no_status:
        temp_rows = [r for r in rows if r["_temp_f"] is not None]
        if temp_rows:
            print(f"\n{'─' * 80}")
            print("Temperature readings:")
            for r in sorted(temp_rows, key=lambda x: x["_temp_f"], reverse=True):
                home = r["home"] or "(no home)"
                room = r["room"] or "(no room)"
                print(f"  {r['_temp_f']:5.1f}°F   {r['name']:<40}  {home} / {room}")

    print(f"\n{'─' * 80}")
    home_label = f'home "{args.home}"' if args.home else f"{len(homes)} home(s)"
    print(f"Total: {len(rows)} device(s) across {home_label}.")


if __name__ == "__main__":
    main()
