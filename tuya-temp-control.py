#!/usr/bin/env python3
"""
Tuya Cloud Temperature Control Script

Reads a temperature/humidity sensor and conditionally controls a switch or
a named outlet on a multi-outlet power strip, all by friendly name.

Examples
--------
# Control the whole device (single-outlet plug):
  ./tuya-temp-control.py --sensor "Downstairs T&H Sensor" --device "DR Avalon Mini" --threshold 75 --state off

# Control a named outlet on a power strip by outlet friendly name:
  ./tuya-temp-control.py --sensor "Downstairs T&H Sensor" --device "Living Room Strip" --outlet "Coffee Maker" --threshold 75 --state off

# Control by raw switch code (backward-compatible):
  ./tuya-temp-control.py --sensor "Downstairs T&H Sensor" --device "Living Room Strip" --outlet switch_2 --threshold 75 --state off

# Two rules in one run (replaces two separate cron jobs):
  ./tuya-temp-control.py --sensor "Downstairs T&H Sensor" --device "DR Avalon Mini" \
      --rule lt:72:on --rule gt:74:off

# List all outlets on a device:
  ./tuya-temp-control.py --device "Living Room Strip" --list-outlets

# Dry run with debug output:
  ./tuya-temp-control.py --sensor "Downstairs T&H Sensor" --device "DR Avalon Mini" --threshold 75 --state off --dry-run --debug
"""

import sys
import os
import argparse
import logging
import time
import json
import hashlib
import hmac
import smtplib
import threading
from datetime import datetime
from configparser import ConfigParser
from difflib import get_close_matches
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional
from urllib.parse import quote

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

try:
    from email_config import SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM, EMAIL_TO
except ImportError:
    SMTP_SERVER = SMTP_PORT = SMTP_USERNAME = SMTP_PASSWORD = EMAIL_FROM = EMAIL_TO = None


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CONFIG_FILE = ".config"
TUYA_BASE_URL = "https://openapi.tuyaus.com"


def load_config(path: str = CONFIG_FILE) -> dict:
    if not os.path.exists(path):
        sys.exit(f"Config file not found: {path}")
    with open(path) as f:
        content = "[default]\n" + f.read()
    parser = ConfigParser()
    parser.read_string(content)
    return {k.upper(): v for k, v in dict(parser["default"]).items()}


def _config_parser(path: str):
    """Return a case-preserving ConfigParser loaded from path, with a synthetic [default] header."""
    with open(path) as f:
        content = "[default]\n" + f.read()
    parser = ConfigParser()
    parser.optionxform = str  # preserve key case for device/outlet/room names
    parser.read_string(content)
    return parser


def _parse_list(value: str) -> list[str]:
    """Split a comma- or newline-separated config value into a stripped list."""
    items = []
    for part in value.replace("\n", ",").split(","):
        part = part.strip()
        if part:
            items.append(part)
    return items


def load_outlet_mappings(path: str = CONFIG_FILE) -> dict:
    """
    Read local outlet name mappings from [outlets:DEVICE_NAME] sections in .config.

    Example:
        [outlets:Geeni WW119 4 Outlet Smart Wall Tap]
        MBR Nano3s = switch_1
        Living Room = switch_2

    Returns {device_name_lower: [{"name": ..., "identifier": ...}]}.
    """
    if not os.path.exists(path):
        return {}
    parser = _config_parser(path)
    default_keys = set(parser.defaults().keys())
    mappings: dict = {}
    for section in parser.sections():
        if section.lower().startswith("outlets:"):
            device_key = section[len("outlets:"):].strip().lower()
            outlets = [
                {"name": k, "identifier": v.strip()}
                for k, v in parser.items(section)
                if k not in default_keys and v.strip()
            ]
            if outlets:
                mappings[device_key] = outlets
    return mappings


def load_home_mappings(path: str = CONFIG_FILE) -> dict:
    """
    Read home and room device groupings from .config.

    Example:
        [home:153 Genesee Ave]
        rooms = Master Bedroom, Living Room

        [room:Master Bedroom]
        home = 153 Genesee Ave
        devices = SI MBR T & H Sensor, Geeni WW119 4 Outlet Smart Wall Tap

    Returns:
        {
            "homes": {name_lower: {"name": str, "rooms": [...], "devices": [...]}},
            "rooms": {name_lower: {"name": str, "home": str|None, "devices": [...]}}
        }

    Used as fallback when the Tuya home-management API is not accessible.
    """
    result: dict = {"homes": {}, "rooms": {}}
    if not os.path.exists(path):
        return result
    parser = _config_parser(path)
    default_keys = set(parser.defaults().keys())
    for section in parser.sections():
        sl = section.lower()
        items = {k: v for k, v in parser.items(section) if k not in default_keys}
        if sl.startswith("home:"):
            name = section[len("home:"):].strip()
            result["homes"][name.lower()] = {
                "name": name,
                "rooms":   _parse_list(items.get("rooms",   "")),
                "devices": _parse_list(items.get("devices", "")),
            }
        elif sl.startswith("room:"):
            name = section[len("room:"):].strip()
            result["rooms"][name.lower()] = {
                "name":    name,
                "home":    items.get("home", "").strip() or None,
                "devices": _parse_list(items.get("devices", "")),
            }
    return result


# ---------------------------------------------------------------------------
# Tuya Cloud client
# ---------------------------------------------------------------------------

class TuyaCloud:
    def __init__(self, access_id: str, access_key: str, base_url: str = TUYA_BASE_URL):
        self.access_id = access_id
        self.access_key = access_key
        self.base_url = base_url.rstrip("/")
        self._token: Optional[str] = None
        self._token_expiry: float = 0
        self._uid: str = ""        # project/token UID
        self._owner_uid: str = ""  # device-owner UID, set after first device fetch
        self._session = requests.Session()
        self._lock = threading.Lock()

    # ---- signing ------------------------------------------------------------

    def _sign(self, method: str, path: str, body: str = "", token: str = "") -> tuple[str, str]:
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
        h = {
            "client_id": self.access_id,
            "t": ts,
            "sign": sig,
            "sign_method": "HMAC-SHA256",
            "Content-Type": "application/json",
        }
        if token:
            h["access_token"] = token
        return h

    # ---- token --------------------------------------------------------------

    def _get_token(self) -> str:
        with self._lock:
            if self._token and time.time() < self._token_expiry:
                return self._token
            path = "/v1.0/token?grant_type=1"
            headers = self._headers("GET", path)
            r = self._session.get(self.base_url + path, headers=headers, timeout=10)
            r.raise_for_status()
            data = r.json()
            if not data.get("success"):
                sys.exit(f"Token error: {data.get('msg', data)}")
            self._token = data["result"]["access_token"]
            self._uid = data["result"].get("uid", "")
            self._token_expiry = time.time() + data["result"]["expire_time"] - 60
            return self._token

    # ---- HTTP helpers -------------------------------------------------------

    def _get(self, path: str, params: dict = None) -> dict:
        token = self._get_token()
        if params:
            sorted_qs = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in sorted(params.items()))
            signed_path = f"{path}?{sorted_qs}"
        else:
            signed_path = path
        headers = self._headers("GET", signed_path, token=token)
        r = self._session.get(self.base_url + signed_path, headers=headers, timeout=10)
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, body: dict) -> dict:
        token = self._get_token()
        body_str = json.dumps(body, separators=(",", ":"))
        headers = self._headers("POST", path, body=body_str, token=token)
        r = self._session.post(self.base_url + path, headers=headers, data=body_str, timeout=10)
        r.raise_for_status()
        return r.json()

    # ---- device listing -----------------------------------------------------

    def get_devices(self) -> list[dict]:
        self._get_token()
        if self._owner_uid:
            return self._get_devices_by_uid(self._owner_uid)
        devices = self._get_devices_iot01()
        owner_uid = next((d.get("uid", "") for d in devices if d.get("uid")), "")
        if owner_uid:
            self._owner_uid = owner_uid
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
                return []
            result = data.get("result", {})
            batch = result.get("devices", result.get("list", []))
            devices.extend(batch)
            last_row_key = result.get("last_row_key", "")
            has_more = result.get("has_more", False)
            if not has_more or not last_row_key or not batch:
                break
        return devices

    # ---- home / room management ---------------------------------------------

    def get_homes(self) -> list[dict]:
        """
        List homes for the device owner. Uses _owner_uid set by get_devices();
        call get_devices() first. Returns [] on failure.
        """
        uid = self._owner_uid or self._uid
        data = self._get(f"/v1.0/users/{uid}/homes")
        logging.debug(f"get_homes ({uid}): {data}")
        if not data.get("success"):
            logging.debug(f"get_homes failed: {data.get('msg', data)}")
            return []
        return data.get("result", [])

    def get_home_rooms(self, home_id) -> list[dict]:
        """List rooms in a home. Returns [] if not permitted."""
        data = self._get(f"/v1.0/homes/{home_id}/rooms")
        logging.debug(f"get_home_rooms {home_id}: {data}")
        if not data.get("success"):
            return []
        return data.get("result", [])

    def get_home_device_ids(self, home_id) -> set[str]:
        """IDs of all devices in a home. Returns empty set if not permitted."""
        data = self._get(f"/v1.0/homes/{home_id}/devices")
        logging.debug(f"get_home_devices {home_id}: {data}")
        if not data.get("success"):
            return set()
        result = data.get("result", {})
        devs = result if isinstance(result, list) else result.get("devices", result.get("list", []))
        return {d["id"] for d in devs if "id" in d}

    def get_room_device_ids(self, home_id, room_id) -> set[str]:
        """IDs of all devices in a room. Returns empty set if not permitted."""
        data = self._get(f"/v1.0/homes/{home_id}/rooms/{room_id}/devices")
        logging.debug(f"get_room_devices {home_id}/{room_id}: {data}")
        if not data.get("success"):
            return set()
        result = data.get("result", {})
        devs = result if isinstance(result, list) else result.get("devices", result.get("list", []))
        return {d["id"] for d in devs if "id" in d}

    # ---- status / control ---------------------------------------------------

    def get_device_status(self, device_id: str) -> dict:
        data = self._get(f"/v1.0/devices/{device_id}/status")
        if not data.get("success"):
            return {}
        return {item["code"]: item["value"] for item in data.get("result", [])}

    def set_device(self, device_id: str, code: str, value) -> dict:
        return self._post(
            f"/v1.0/devices/{device_id}/commands",
            {"commands": [{"code": code, "value": value}]},
        )

    # ---- outlet name resolution ---------------------------------------------

    def get_outlet_names(self, device_id: str) -> list[dict]:
        """
        Retrieve friendly outlet names for a multi-outlet device.

        Uses GET /v1.0/devices/{id}/multiple-names.

        Returns a list of {"identifier": "switch_1", "name": "MBR Nano3s"} dicts,
        excluding the "main" entry (which is the device itself).
        Returns [] if the device has no named outlets or the call fails.
        """
        data = self._get(f"/v1.0/devices/{device_id}/multiple-names")
        logging.debug(f"multiple-names response for {device_id}: {data}")
        if not data.get("success"):
            logging.debug(f"multiple-names failed for {device_id}: {data.get('msg', data)}")
            return []
        result = data.get("result", [])
        # Filter out the "main" entry — that represents the device itself
        return [entry for entry in result if entry.get("identifier") != "main"]

    def resolve_outlet_code(self, device_id: str, outlet: str,
                            local_outlets: list | None = None) -> tuple[str, str | None]:
        """
        Resolve an outlet specifier to a switch code.

        The `outlet` argument may be:
          - A raw switch code already  ("switch_1", "switch_2", …)  → returned as-is
          - A friendly outlet name     ("Coffee Maker")              → looked up via API,
            then local_outlets, then treated as raw

        Returns (resolved_code, friendly_name_or_None).
        Exits with an error if the name cannot be matched.
        """
        # If it already looks like a raw code, skip the API call
        if outlet.lower().startswith("switch") or outlet.lower() in ("usb", "all"):
            return outlet, None

        outlets = self.get_outlet_names(device_id)
        if not outlets and local_outlets:
            logging.debug(
                f"API returned no outlet names for {device_id}; "
                f"using {len(local_outlets)} local mapping(s) from .config"
            )
            outlets = local_outlets
        if not outlets:
            logging.warning(
                f"No outlet names returned for device {device_id}. "
                f"Treating '{outlet}' as a raw switch code. "
                f"Run with --list-outlets --debug to see raw API responses, "
                f"or add [outlets:DEVICE_NAME] to .config for local name mappings."
            )
            return outlet, None

        # Build lookup maps (exact + case-insensitive)
        name_to_id: dict[str, str] = {o["name"]: o["identifier"] for o in outlets}
        lower_map: dict[str, str] = {k.lower(): k for k in name_to_id}

        if outlet in name_to_id:
            return name_to_id[outlet], outlet

        if outlet.lower() in lower_map:
            canonical = lower_map[outlet.lower()]
            return name_to_id[canonical], canonical

        # Fuzzy fallback
        suggestions = get_close_matches(outlet, name_to_id.keys(), n=3, cutoff=0.4)
        msg = f'Outlet name not found: "{outlet}"'
        if suggestions:
            msg += "\n  Did you mean: " + ", ".join(f'"{s}"' for s in suggestions)
        outlet_list = ", ".join(f"{o['name']} ({o['identifier']})" for o in outlets)
        msg += f"\n  Available outlets: {outlet_list}"
        sys.exit(msg)


# ---------------------------------------------------------------------------
# Email notification
# ---------------------------------------------------------------------------

def send_state_change_email(sensor_name, temp_f, switch_name, new_state, resp=None):
    if not all([SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM, EMAIL_TO]):
        logging.warning("Email config not set, skipping email notification.")
        return
    subject = f"Tuya Device State Changed: {switch_name} is now {new_state}"
    html = f"""
    <html><body>
        <h2>Tuya Device State Changed</h2>
        <p><b>Sensor:</b> {sensor_name}</p>
        <p><b>Temperature:</b> {temp_f:.1f}°F</p>
        <p><b>Switch:</b> {switch_name}</p>
        <p><b>New State:</b> <span style='color:{"green" if new_state == "ON" else "red"}'>{new_state}</span></p>
        {f'<pre>Response: {json.dumps(resp, indent=2)}</pre>' if resp else ''}
        <p><i>Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i></p>
    </body></html>
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO
    msg.attach(MIMEText(html, "html"))
    try:
        with smtplib.SMTP(SMTP_SERVER, int(SMTP_PORT)) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        logging.info(f"Sent state change email to {EMAIL_TO}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(logfile=None, debug=False):
    level = logging.DEBUG if debug else logging.INFO
    handlers = [logging.StreamHandler(sys.stdout)]
    if logfile:
        handlers.append(logging.FileHandler(logfile))
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=handlers)


# ---------------------------------------------------------------------------
# Temperature helpers
# ---------------------------------------------------------------------------

TEMP_KEYS = ["temp_value", "temp_current", "va_temperature"]


def extract_temperature_f(status: dict) -> tuple[float | None, float | None, str | None]:
    """
    Extract temperature from a status dict and convert to Fahrenheit.
    Returns (temp_c, temp_f, key_used).
    Many Tuya sensors report tenths of °C (e.g. 235 = 23.5 °C).
    """
    for key in TEMP_KEYS:
        if key in status:
            raw = status[key]
            temp_c = raw / 10.0 if isinstance(raw, (int, float)) and raw > 60 else float(raw)
            temp_f = temp_c * 9.0 / 5.0 + 32.0
            return temp_c, temp_f, key
    return None, None, None


def status_summary(status: dict) -> str:
    priority = ["switch", "switch_1", "power", "bright_value", "temp_value",
                "colour_data", "work_mode", "countdown", "humidity_value",
                "temp_current", "va_temperature", "va_humidity"]
    parts, seen = [], set()
    for key in priority:
        if key in status:
            parts.append(f"{key}={status[key]}")
            seen.add(key)
    for k, v in status.items():
        if k not in seen:
            parts.append(f"{k}={v}")
        if len(parts) >= 5:
            break
    return "  |  ".join(parts) if parts else "—"


# ---------------------------------------------------------------------------
# --list-outlets helper
# ---------------------------------------------------------------------------

def cmd_list_outlets(cloud: TuyaCloud, devices: list[dict], device_name: str,
                     local_outlets: list | None = None) -> None:
    """Print all named outlets for a device and exit."""
    dev = next((d for d in devices if d.get("name", "").strip().lower() == device_name.strip().lower()), None)
    if not dev:
        sys.exit(f'Device "{device_name}" not found.')

    outlets = cloud.get_outlet_names(dev["id"])
    source = "Tuya API"
    if not outlets and local_outlets:
        outlets = local_outlets
        source = ".config local mapping"
    if not outlets:
        print(f'No named outlets found for "{device_name}".')
        print("Possible causes:")
        print("  • Outlet names not set in the Tuya/Geeni app for this device")
        print("  • Device category does not support the device.multiple-name action")
        print("  • API key missing the 'Device name' permission in the Tuya developer console")
        print("Re-run with --debug to see raw API responses and diagnose further.")
        print()
        print(f"To define outlet names locally, add to .config:")
        print(f"  [outlets:{device_name}]")
        print(f"  My Outlet Name = switch_1")
        sys.exit(0)

    print(f'\nOutlets for "{device_name}" (id: {dev["id"]})  [{source}]\n')
    col = max(len(o["name"]) for o in outlets) + 2
    print(f'  {"Outlet Name":<{col}}  Switch Code')
    print(f'  {"-" * col}  -----------')
    for o in outlets:
        print(f'  {o["name"]:<{col}}  {o["identifier"]}')
    print()
    sys.exit(0)


# ---------------------------------------------------------------------------
# Home / room location filter
# ---------------------------------------------------------------------------

def resolve_location_filter(
    cloud: TuyaCloud,
    devices: list[dict],
    home_name: str | None,
    room_name: str | None,
    home_map: dict,
) -> list[dict]:
    """
    Return the subset of devices that belong to the specified home and/or room.

    Tries the Tuya home-management API first; falls back to [home:] / [room:]
    sections in .config when the API is unavailable (e.g. permission 1106).
    """
    if not home_name and not room_name:
        return devices

    homes_api = cloud.get_homes()
    if homes_api:
        return _filter_via_api(cloud, devices, homes_api, home_name, room_name)
    return _filter_via_config(devices, home_map, home_name, room_name)


def _filter_via_api(
    cloud: TuyaCloud,
    devices: list[dict],
    homes_api: list[dict],
    home_name: str | None,
    room_name: str | None,
) -> list[dict]:
    def _home_id(h):
        return h.get("home_id") or h.get("id")
    def _room_id(r):
        return r.get("room_id") or r.get("id")

    name_to_home = {h.get("name", "").strip().lower(): h for h in homes_api}

    if home_name:
        home = name_to_home.get(home_name.strip().lower())
        if not home:
            avail = ", ".join(f'"{h.get("name","")}"' for h in homes_api)
            sys.exit(f'Home "{home_name}" not found. Available: {avail}')
        hid = _home_id(home)

        if room_name:
            rooms = cloud.get_home_rooms(hid)
            room = next((r for r in rooms
                         if r.get("name","").strip().lower() == room_name.strip().lower()), None)
            if not room:
                avail = ", ".join(f'"{r.get("name","")}"' for r in rooms) or "none"
                sys.exit(f'Room "{room_name}" not found in home "{home_name}". Available: {avail}')
            device_ids = cloud.get_room_device_ids(hid, _room_id(room))
        else:
            device_ids = cloud.get_home_device_ids(hid)

    else:
        # --room only: search across all homes
        device_ids = set()
        found_home = None
        for h in homes_api:
            hid_search = _home_id(h)
            rooms = cloud.get_home_rooms(hid_search)
            room = next((r for r in rooms
                         if r.get("name","").strip().lower() == room_name.strip().lower()), None)
            if room:
                device_ids = cloud.get_room_device_ids(hid_search, _room_id(room))
                found_home = h.get("name", "")
                break
        if not found_home:
            all_rooms = []
            for h in homes_api:
                all_rooms += [r.get("name","") for r in cloud.get_home_rooms(_home_id(h))]
            avail = ", ".join(f'"{n}"' for n in all_rooms) or "none found"
            sys.exit(f'Room "{room_name}" not found in any home. Available rooms: {avail}')

    label = " / ".join(filter(None, [home_name, room_name]))
    filtered = [d for d in devices if d["id"] in device_ids]
    logging.info(f'Location filter "{label}": {len(filtered)} device(s) [Tuya API]')
    return filtered


def _filter_via_config(
    devices: list[dict],
    home_map: dict,
    home_name: str | None,
    room_name: str | None,
) -> list[dict]:
    device_names: set[str] = set()

    if room_name:
        entry = home_map["rooms"].get(room_name.strip().lower())
        if not entry:
            sug = get_close_matches(room_name.lower(), list(home_map["rooms"].keys()), n=3, cutoff=0.5)
            msg = f'Room "{room_name}" not found in API or .config.'
            if sug:
                msg += "  Did you mean: " + ", ".join(f'"{home_map["rooms"][s]["name"]}"' for s in sug)
            msg += f'\nAdd to .config:\n  [room:{room_name}]\n  home = YOUR_HOME\n  devices = Device1, Device2'
            sys.exit(msg)
        if home_name and entry["home"] and entry["home"].strip().lower() != home_name.strip().lower():
            sys.exit(f'Room "{room_name}" belongs to home "{entry["home"]}" in .config, not "{home_name}".')
        device_names = set(entry["devices"])

    elif home_name:
        entry = home_map["homes"].get(home_name.strip().lower())
        if not entry:
            sug = get_close_matches(home_name.lower(), list(home_map["homes"].keys()), n=3, cutoff=0.5)
            msg = f'Home "{home_name}" not found in API or .config.'
            if sug:
                msg += "  Did you mean: " + ", ".join(f'"{home_map["homes"][s]["name"]}"' for s in sug)
            msg += f'\nAdd to .config:\n  [home:{home_name}]\n  rooms = Room1, Room2'
            sys.exit(msg)
        device_names = set(entry["devices"])
        for rname in entry["rooms"]:
            r = home_map["rooms"].get(rname.strip().lower())
            if r:
                device_names.update(r["devices"])

    if not device_names:
        label = " / ".join(filter(None, [home_name, room_name]))
        logging.warning(f'No devices defined for "{label}" in .config; running without location filter.')
        return devices

    name_lower = {n.strip().lower() for n in device_names}
    filtered = [d for d in devices if d.get("name", "").strip().lower() in name_lower]
    label = " / ".join(filter(None, [home_name, room_name]))
    logging.info(f'Location filter "{label}": {len(filtered)} device(s) [.config]')
    if not filtered:
        logging.warning("Location filter matched no known devices — check names in .config.")
    return filtered


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Tuya temperature-controlled switch script with outlet name support.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--sensor",     default="Downstairs T & H Sensor",
                        help="Friendly name of the temperature/humidity sensor")
    parser.add_argument("--device",  default="Avalon Mini",
                        help=(
                            "Friendly name of the device to control. "
                            "Outlet can be appended with a colon: 'Strip:Coffee Maker'. "
                            "Use --devices to specify multiple targets."
                        ))
    parser.add_argument("--devices", nargs="+", default=None, metavar="DEVICE",
                        help=(
                            "One or more devices to control (space-separated, quoted if needed). "
                            "Each may include an outlet: 'Strip:Outlet'. "
                            "Supersedes --device when provided."
                        ))
    parser.add_argument("--outlet",  default=None,
                        help=(
                            "Outlet applied to all targets that don't embed one via 'DEVICE:OUTLET'. "
                            "Accepts a friendly name or raw switch code (e.g. switch_2)."
                        ))
    parser.add_argument("--threshold",  type=float, default=75.0,
                        help="Temperature threshold in °F (default: 75)")
    parser.add_argument("--state",      choices=["on", "off"], default="off",
                        help="Desired switch state when threshold is crossed (default: off)")
    parser.add_argument("--direction",  choices=["gt", "ge", "lt", "le"], default="gt",
                        help="gt=>  ge>= lt<  le<=  (default: gt)")
    parser.add_argument("--rule", action="append", metavar="DIR:TEMP:STATE",
                        help=(
                            "Condition as DIRECTION:THRESHOLD:STATE, e.g. 'lt:72:on'. "
                            "Repeatable. When used, --threshold/--state/--direction are ignored."
                        ))
    parser.add_argument("--home",        default=None,
                        help="Restrict device lookup to this home (Tuya app name or .config [home:NAME])")
    parser.add_argument("--room",        default=None,
                        help="Restrict device lookup to this room (Tuya app name or .config [room:NAME])")
    parser.add_argument("--list-outlets", action="store_true",
                        help="List all named outlets for --device and exit")
    parser.add_argument("--log",        default=None, help="Log file path")
    parser.add_argument("--dry-run",    action="store_true",
                        help="Show what would happen without sending commands")
    parser.add_argument("--debug",      action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    # Build unified device-spec list: [(device_name, outlet_or_None), ...]
    # --devices supersedes --device; strip stray commas users may include as separators
    raw = [s.strip().strip(",") for s in (args.devices or [args.device])]
    device_specs: list[tuple[str, str | None]] = []
    for spec in raw:
        if not spec:
            continue
        if ":" in spec:
            dname, oname = spec.split(":", 1)
            device_specs.append((dname.strip(), oname.strip() or None))
        else:
            device_specs.append((spec, None))

    setup_logging(args.log, args.debug)

    cfg = load_config()
    access_id  = cfg.get("TUYA_ACCESS_ID",  "").strip()
    access_key = cfg.get("TUYA_ACCESS_KEY", "").strip()
    base_url   = cfg.get("TUYA_BASE_URL", TUYA_BASE_URL).strip()

    if not access_id or not access_key:
        sys.exit("TUYA_ACCESS_ID and TUYA_ACCESS_KEY must be set in .config")

    outlet_map = load_outlet_mappings()
    home_map   = load_home_mappings()

    cloud = TuyaCloud(access_id, access_key, base_url)

    logging.info("Fetching device list…")
    devices = cloud.get_devices()
    logging.info(f"Found {len(devices)} device(s)")

    # ---- home / room filter -------------------------------------------------
    if args.home or args.room:
        devices = resolve_location_filter(cloud, devices, args.home, args.room, home_map)

    # ---- --list-outlets shortcut --------------------------------------------
    if args.list_outlets:
        for dev_name, _ in device_specs:
            local = outlet_map.get(dev_name.strip().lower())
            cmd_list_outlets(cloud, devices, dev_name, local_outlets=local)

    # ---- debug: dump all devices + status -----------------------------------
    if args.debug:
        print("\nAll devices (sorted by name):")
        for dev in sorted(devices, key=lambda d: d.get("name", "").lower()):
            st = cloud.get_device_status(dev.get("id", ""))
            print(f"  {dev.get('name',''):<40}  {dev.get('id','')}  {status_summary(st)}")
        print()

    # ---- helpers ------------------------------------------------------------
    def find(name: str):
        match = next((d for d in devices if d.get("name", "").strip().lower() == name.strip().lower()), None)
        if not match:
            names = [d.get("name", "") for d in devices]
            suggestions = get_close_matches(name, names, n=3, cutoff=0.5)
            msg = f'Device "{name}" not found.'
            if suggestions:
                msg += "  Did you mean: " + ", ".join(f'"{s}"' for s in suggestions)
            sys.exit(msg)
        return match

    def resolve_target(dev_name: str, outlet_spec: str | None):
        """Return (device_dict, switch_code, outlet_display) for one target spec."""
        target_dev = find(dev_name)
        effective_outlet = outlet_spec or args.outlet
        if effective_outlet:
            local_outlets = outlet_map.get(dev_name.strip().lower())
            switch_code, outlet_label = cloud.resolve_outlet_code(
                target_dev["id"], effective_outlet, local_outlets=local_outlets
            )
            display = f'"{outlet_label}" ({switch_code})' if outlet_label else switch_code
        else:
            probe = cloud.get_device_status(target_dev["id"])
            switch_code = "switch" if "switch" in probe else "switch_1"
            display = switch_code
        return target_dev, switch_code, display

    # ---- locate sensor ------------------------------------------------------
    sensor_dev = find(args.sensor)

    # ---- read temperature (once for all targets) ----------------------------
    sensor_status = cloud.get_device_status(sensor_dev["id"])
    temp_c, temp_f, temp_key = extract_temperature_f(sensor_status)
    if temp_f is None:
        sys.exit(f"No temperature found in sensor '{args.sensor}' status: {sensor_status}")

    humidity = sensor_status.get("va_humidity") or sensor_status.get("humidity_value")
    humidity_str = f"  humidity: {humidity / 10:.1f}%" if humidity is not None else ""
    logging.info(
        f"Sensor : '{args.sensor}'  (id: {sensor_dev['id']})\n"
        f"         Reading : {temp_c:.1f}°C / {temp_f:.1f}°F{humidity_str}  (key: {temp_key})"
    )

    # ---- build rules list ---------------------------------------------------
    direction_labels = {"gt": ">", "ge": ">=", "lt": "<", "le": "<="}
    if args.rule:
        rules: list[tuple[str, float, str]] = []
        for r in args.rule:
            parts = r.split(":")
            if len(parts) != 3:
                sys.exit(f"Invalid --rule '{r}': expected DIRECTION:THRESHOLD:STATE (e.g. lt:72:on)")
            direction, threshold_str, state = parts
            if direction not in direction_labels:
                sys.exit(f"Invalid direction '{direction}' in --rule '{r}': must be gt, ge, lt, or le")
            if state not in ("on", "off"):
                sys.exit(f"Invalid state '{state}' in --rule '{r}': must be on or off")
            rules.append((direction, float(threshold_str), state))
    else:
        rules = [(args.direction, args.threshold, args.state)]

    # ---- evaluate each rule and act -----------------------------------------
    for direction, threshold, state in rules:
        op_str        = direction_labels[direction]
        trigger       = {"gt": temp_f > threshold, "ge": temp_f >= threshold,
                         "lt": temp_f < threshold, "le": temp_f <= threshold}[direction]
        desired_on    = state == "on"
        state_str     = "ON" if desired_on else "OFF"
        condition_str = f"{temp_f:.1f}°F {op_str} {threshold}°F"
        logging.info(f"Rule {direction}:{threshold}:{state}  →  {condition_str}  →  {'TRIGGERED' if trigger else 'not triggered'}")

        if not trigger:
            continue

        for dev_name, outlet_spec in device_specs:
            target_dev, switch_code, outlet_display = resolve_target(dev_name, outlet_spec)
            target_label = f"'{dev_name}' {outlet_display}"

            target_status = cloud.get_device_status(target_dev["id"])
            is_on = target_status.get(switch_code)
            logging.info(f"Target {target_label}  (id: {target_dev['id']})  current state: {'ON' if is_on else 'OFF'}")

            if is_on == desired_on:
                logging.info(f"No action needed — {target_label} is already {state_str}")
            else:
                logging.info(f"Condition met ({condition_str}): setting {target_label} → {state_str}")
                if args.dry_run:
                    logging.info("(dry-run) Command not sent.")
                else:
                    resp = cloud.set_device(target_dev["id"], switch_code, desired_on)
                    logging.info(f"Command response: {resp}")
                    if resp.get("success"):
                        send_state_change_email(
                            args.sensor, temp_f,
                            f"{dev_name} {outlet_display}",
                            state_str, resp,
                        )
                    else:
                        logging.error(f"Command failed: {resp.get('msg', resp)}")


if __name__ == "__main__":
    main()