#!/usr/bin/env python3
"""
Tuya Cloud Temperature Control Script
- Turns off 'DR Avalon Mini' if 'Downstairs T&H sensor' temperature > 75°F.
- Uses friendly names, logs all actions and statuses.
- Flexible CLI for cron: supports --threshold, --sensor, --switch, --log, --dry-run, --debug, etc.
"""

import sys
import os
import argparse
import logging
import time
from datetime import datetime
import json
from typing import Optional

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

# --- TuyaCloud class (from tuya-lister.py, trimmed for brevity) ---
import hashlib
import hmac
from configparser import ConfigParser
from urllib.parse import quote

CONFIG_FILE = ".config"
TUYA_BASE_URL = "https://openapi.tuyaus.com"


def load_config(path: str = CONFIG_FILE) -> dict:
    if not os.path.exists(path):
        sys.exit(f"Config file not found: {path}")
    with open(path) as f:
        content = "[default]\n" + f.read()
    parser = ConfigParser()
    parser.read_string(content)
    cfg = dict(parser["default"])
    return {k.upper(): v for k, v in cfg.items()}



import threading

class TuyaCloud:
    def __init__(self, access_id: str, access_key: str, base_url: str = TUYA_BASE_URL):
        self.access_id = access_id
        self.access_key = access_key
        self.base_url = base_url.rstrip("/")
        self._token: Optional[str] = None
        self._token_expiry: float = 0
        self._uid: str = ""
        self._session = requests.Session()
        self._lock = threading.Lock()  # For thread safety if needed

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

    def _get(self, path: str, params: dict = None) -> dict:
        token = self._get_token()
        if params:
            sorted_qs = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in sorted(params.items()))
            signed_path = f"{path}?{sorted_qs}"
        else:
            signed_path = path
        headers = self._headers("GET", signed_path, token=token)
        url = self.base_url + signed_path
        r = self._session.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        return r.json()

    def get_devices(self) -> list[dict]:
        self._get_token()
        if self._uid:
            devices = self._get_devices_by_uid(self._uid)
            if devices:
                return devices
        return self._get_devices_iot01()

    def _get_devices_by_uid(self, uid: str) -> list[dict]:
        devices = []
        page_no, page_size = 1, 100
        while True:
            data = self._get(f"/v1.0/users/{uid}/devices", params={"page_no": page_no, "page_size": page_size})
            if not data.get("success"):
                return []
            result = data.get("result", {})
            if isinstance(result, list):
                batch = result
                total = len(result)
            else:
                batch = result.get("devices", result.get("list", []))
                total = result.get("total", 0)
            devices.extend(batch)
            if len(batch) < page_size:
                break
            if total and len(devices) >= total:
                break
            page_no += 1
        return devices

    def _get_devices_iot01(self) -> list[dict]:
        devices = []
        last_row_key = ""
        page_size = 20
        while True:
            params = {"page_size": page_size}
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
            if not has_more or not last_row_key or len(batch) == 0:
                break
        return devices

    def get_device_status(self, device_id: str) -> dict:
        path = f"/v1.0/devices/{device_id}/status"
        data = self._get(path)
        if not data.get("success"):
            return {}
        return {item["code"]: item["value"] for item in data.get("result", [])}

    def set_device(self, device_id: str, code: str, value) -> dict:
        path = f"/v1.0/devices/{device_id}/commands"
        body = json.dumps({"commands": [{"code": code, "value": value}]})
        token = self._get_token()
        headers = self._headers("POST", path, body, token)
        url = self.base_url + path
        r = self._session.post(url, headers=headers, data=body, timeout=10)
        r.raise_for_status()
        return r.json()

# --- Logging setup ---
def setup_logging(logfile=None, debug=False):
    loglevel = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=loglevel,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)] +
                 ([logging.FileHandler(logfile)] if logfile else [])
    )

# --- Main logic ---

def extract_temperature_f(status: dict) -> tuple[float | None, float | None, str | None]:
    """
    Extract temperature from status dict, convert to Fahrenheit.
    Returns (temp_c, temp_f, key_used)
    """
    temp_keys = ["temp_value", "temp_current", "va_temperature"]
    for key in temp_keys:
        if key in status:
            temp_c = status[key]
            # Many Tuya sensors report tenths of Celsius, so check for int/float and scale
            if isinstance(temp_c, (int, float)) and temp_c > 60:
                temp_c = temp_c / 10.0
            try:
                temp_f = temp_c * 9.0 / 5.0 + 32.0
            except Exception:
                temp_f = None
            return temp_c, temp_f, key
    return None, None, None

def main():

    parser = argparse.ArgumentParser(description="Tuya temperature control script")
    parser.add_argument("--threshold", type=float, default=75.0, help="Temperature threshold in °F (default: 75)")
    parser.add_argument("--sensor", default="Downstairs T&H sensor", help="Friendly name of temperature sensor")
    parser.add_argument("--switch", default="DR Avalon Mini", help="Friendly name of switch to control")
    parser.add_argument("--state", choices=["on", "off"], default="off", help="Desired switch state when threshold is crossed (on/off, default: off)")
    parser.add_argument(
        "--direction",
        choices=["gt", "ge", "lt", "le"],
        default="gt",
        help="Threshold direction: 'gt' (temp > threshold), 'ge' (temp >= threshold), 'lt' (temp < threshold), 'le' (temp <= threshold). Default: gt"
    )
    parser.add_argument("--log", default=None, help="Log file path")
    parser.add_argument("--dry-run", action="store_true", help="Show actions but do not send commands")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    setup_logging(args.log, args.debug)
    logging.info(f"Starting Tuya control: sensor='{args.sensor}', switch='{args.switch}', threshold={args.threshold}F")

    cfg = load_config()
    access_id = cfg.get("TUYA_ACCESS_ID", "").strip()
    access_key = cfg.get("TUYA_ACCESS_KEY", "").strip()
    base_url = cfg.get("TUYA_BASE_URL", TUYA_BASE_URL).strip()
    cloud = TuyaCloud(access_id, access_key, base_url)

    devices = cloud.get_devices()
    logging.info(f"Found {len(devices)} device(s) from cloud")


    if args.debug:
        sorted_devices = sorted(devices, key=lambda d: d.get("name", "").lower())
        print("\nDevices found (sorted by friendly name):")
        for dev in sorted_devices:
            dev_id = dev.get('id','')
            name = dev.get('name','')
            status = cloud.get_device_status(dev_id)
            # Build a status summary similar to tuya-scan.py
            def status_summary(status: dict) -> str:
                if not status:
                    return "—"
                priority = ["switch", "switch_1", "power", "bright_value", "temp_value",
                            "colour_data", "work_mode", "countdown", "humidity_value",
                            "temp_current", "va_temperature", "va_humidity"]
                parts = []
                seen = set()
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
            summary = status_summary(status)
            print(f"- {name} (ID: {dev_id})  State: {summary}")
        print()

    sensor = next((d for d in devices if d.get("name", "").strip().lower() == args.sensor.strip().lower()), None)
    switch = next((d for d in devices if d.get("name", "").strip().lower() == args.switch.strip().lower()), None)

    if not sensor:
        logging.error(f"Sensor '{args.sensor}' not found!")
        sys.exit(2)
    if not switch:
        logging.error(f"Switch '{args.switch}' not found!")
        sys.exit(2)

    sensor_status = cloud.get_device_status(sensor["id"])
    temp_c, temp_f, temp_key = extract_temperature_f(sensor_status)
    if temp_f is None:
        logging.error(f"No temperature found in sensor '{args.sensor}' status: {sensor_status}")
        sys.exit(3)
    logging.info(f"Sensor '{args.sensor}' temperature: {temp_c:.1f}°C / {temp_f:.1f}°F (from '{temp_key}')")

    switch_status = cloud.get_device_status(switch["id"])
    # Check for 'switch', 'switch_1', or 'power' to determine ON/OFF
    is_on = None
    for key in ("switch", "switch_1", "power"):
        if key in switch_status:
            is_on = switch_status[key]
            break
    if is_on is None:
        logging.warning(f"Could not determine ON/OFF state for '{args.switch}' (status: {switch_status})")
    logging.info(f"Switch '{args.switch}' current state: {'ON' if is_on else 'OFF'}")

    # Use the same key for control (prefer 'switch', then 'switch_1', then 'power')
    control_key = None
    for key in ("switch", "switch_1", "power"):
        if key in switch_status:
            control_key = key
            break
    # Determine if action should be taken based on direction and threshold

    trigger = False
    if args.direction == "gt":
        trigger = temp_f > args.threshold
        direction_str = f"> {args.threshold}"
    elif args.direction == "ge":
        trigger = temp_f >= args.threshold
        direction_str = f">= {args.threshold}"
    elif args.direction == "lt":
        trigger = temp_f < args.threshold
        direction_str = f"< {args.threshold}"
    elif args.direction == "le":
        trigger = temp_f <= args.threshold
        direction_str = f"<= {args.threshold}"

    desired_on = args.state == "on"
    state_str = "ON" if desired_on else "OFF"

    if trigger:
        if is_on == desired_on:
            logging.info(f"Temperature {temp_f:.1f}°F {direction_str}°F: switch already {state_str}")
        else:
            logging.info(f"Temperature {temp_f:.1f}°F {direction_str}°F: setting '{args.switch}' to {state_str}")
            if not args.dry_run:
                if control_key:
                    resp = cloud.set_device(switch["id"], control_key, desired_on)
                    logging.info(f"Switch {state_str.lower()} command response: {resp}")
                else:
                    logging.error(f"No valid control key found for switch '{args.switch}'")
            else:
                logging.info(f"(Dry run) Would send switch {state_str.lower()} command")
    else:
        logging.info(f"Temperature {temp_f:.1f}°F does not meet trigger condition ({direction_str}°F): no action needed")

if __name__ == "__main__":
    main()
