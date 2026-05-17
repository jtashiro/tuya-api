#!/usr/bin/env python3
"""
Tuya Door Sensor Monitor

Subscribes to the Tuya Pulsar message service and sends an email when the
specified door sensor opens (or closes).

Pre-requisites
--------------
1. In the Tuya IoT Console → your project → "Message Service" tab:
     • Enable "Device status notification"
     • Save / Subscribe

2. Install dependencies:
     pip install pulsar-client pycryptodome

3. email_config.py must be configured (see email_config.py.template).

Usage
-----
  ./tuya-door-monitor.py
  ./tuya-door-monitor.py --sensor "LBI Roof Door Sensor"
  ./tuya-door-monitor.py --open-only    # email only on open, not close
  ./tuya-door-monitor.py --debug        # print every raw + decrypted message
"""

import argparse
import base64
import socket
import hashlib
import hmac
import json
import logging
import os
import smtplib
import sys
import time
from configparser import ConfigParser
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import quote

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")

try:
    import pulsar
except ImportError:
    sys.exit("Missing dependency: pip install pulsar-client")

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit("Missing dependency: pip install pycryptodome")

try:
    from email_config import SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM, EMAIL_TO
except ImportError:
    SMTP_SERVER = SMTP_PORT = SMTP_USERNAME = SMTP_PASSWORD = EMAIL_FROM = EMAIL_TO = None


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CONFIG_FILE   = ".config"
TUYA_BASE_URL = "https://openapi.tuyaus.com"
PULSAR_URL    = "pulsar+ssl://mqe.tuyaus.com:7285/"

MQ_ENV_PROD = "event"
MQ_ENV_TEST = "event-test"

DOOR_CODE = "doorcontact_state"   # true = open, false = closed


def load_config(path: str = CONFIG_FILE) -> dict:
    if not os.path.exists(path):
        sys.exit(f"Config file not found: {path}")
    with open(path) as f:
        content = "[default]\n" + f.read()
    parser = ConfigParser()
    parser.read_string(content)
    return {k.upper(): v for k, v in dict(parser["default"]).items()}


# ---------------------------------------------------------------------------
# Tuya REST client — device lookup only
# ---------------------------------------------------------------------------

class TuyaCloud:
    def __init__(self, access_id: str, access_key: str, base_url: str = TUYA_BASE_URL):
        self.access_id  = access_id
        self.access_key = access_key
        self.base_url   = base_url.rstrip("/")
        self._token:        str   = ""
        self._token_expiry: float = 0
        self._uid:          str   = ""
        self._owner_uid:    str   = ""

    def _sign(self, method: str, path: str, body: str = "", token: str = "") -> tuple[str, str]:
        ts = str(int(time.time() * 1000))
        content_hash   = hashlib.sha256(body.encode()).hexdigest()
        string_to_sign = "\n".join([method.upper(), content_hash, "", path])
        sign_str       = self.access_id + token + ts + string_to_sign
        sig = hmac.new(self.access_key.encode(), sign_str.encode(), hashlib.sha256).hexdigest().upper()
        return ts, sig

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
        self._token        = data["result"]["access_token"]
        self._uid          = data["result"].get("uid", "")
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

    def get_all_devices(self) -> list[dict]:
        devices, last_row_key = [], ""
        while True:
            params: dict = {"page_size": 20}
            if last_row_key:
                params["last_row_key"] = last_row_key
            data         = self._get("/v1.0/iot-01/associated-users/devices", params)
            if not data.get("success"):
                sys.exit(f"Device list error: {data.get('msg', data)}")
            result       = data.get("result", {})
            batch        = result.get("devices", result.get("list", []))
            last_row_key = result.get("last_row_key", "")
            devices.extend(batch)
            if not self._owner_uid:
                self._owner_uid = next((d.get("uid", "") for d in batch if d.get("uid")), "")
            if not result.get("has_more") or not last_row_key or not batch:
                break
        return devices

    def resolve_sensors(self, names: list[str]) -> dict[str, str]:
        """
        Return {device_id: friendly_name} for the sensors to monitor.

        If names is empty, returns all door/window contact sensors found on
        the account (Tuya category 'mcs').  If names are provided, each must
        match a device by friendly name (case-insensitive); exits on mismatch.
        """
        all_devices = self.get_all_devices()

        if not names:
            sensors = {d["id"]: d.get("name", d["id"]).strip()
                       for d in all_devices if d.get("category") == "mcs"}
            if not sensors:
                sys.exit("No door sensors (category 'mcs') found on this account.")
            return sensors

        name_lower = {d.get("name", "").strip().lower(): d for d in all_devices}
        result: dict[str, str] = {}
        for name in names:
            match = name_lower.get(name.strip().lower())
            if not match:
                available = sorted(d.get("name", "") for d in all_devices)
                sys.exit(f'Sensor "{name}" not found.\nAvailable:\n  ' + "\n  ".join(available))
            result[match["id"]] = match.get("name", match["id"]).strip()
        return result

    def get_homes(self) -> list[dict]:
        uid  = self._owner_uid or self._uid
        data = self._get(f"/v1.0/users/{uid}/homes")
        if not data.get("success"):
            logging.debug(f"get_homes failed: {data.get('msg', data)}")
            return []
        return data.get("result", [])

    def get_home_rooms(self, home_id) -> list[dict]:
        data = self._get(f"/v1.0/homes/{home_id}/rooms")
        if not data.get("success"):
            return []
        result = data.get("result", {})
        return result.get("rooms", result) if isinstance(result, dict) else result

    def get_room_device_ids(self, home_id, room_id) -> list[str]:
        data = self._get(f"/v1.0/homes/{home_id}/rooms/{room_id}/devices")
        if not data.get("success"):
            return []
        result = data.get("result", {})
        devs   = result if isinstance(result, list) else result.get("devices", result.get("list", []))
        return [d["id"] for d in devs if "id" in d]

    def build_location_map(self) -> dict[str, tuple[str, str]]:
        """Return {device_id: (home_name, room_name)} for all devices in rooms."""
        mapping: dict[str, tuple[str, str]] = {}
        for home in self.get_homes():
            home_id   = home.get("home_id") or home.get("id")
            home_name = home.get("name", "")
            for room in self.get_home_rooms(home_id):
                room_id   = room.get("room_id") or room.get("id")
                room_name = room.get("name", "")
                for did in self.get_room_device_ids(home_id, room_id):
                    mapping[did] = (home_name, room_name)
        return mapping


# ---------------------------------------------------------------------------
# Pulsar authentication (Tuya's proprietary "auth1" scheme)
# ---------------------------------------------------------------------------

def get_pulsar_auth(access_id: str, access_key: str) -> pulsar.Authentication:
    """
    Tuya's auth1 scheme (from tuya-pulsar-sdk-python/mq_authentication.py):
      1. md5_key     = MD5(access_key)
      2. combined    = access_id + md5_key
      3. md5_combined = MD5(combined)
      4. password    = md5_combined[8:24]
      username and password are passed as a split JSON string to AuthenticationBasic.
    """
    md5_key      = hashlib.md5(access_key.encode()).hexdigest()
    combined     = access_id + md5_key
    md5_combined = hashlib.md5(combined.encode()).hexdigest()
    username     = '{{"username": "{}","password"'.format(access_id)
    password     = '"' + md5_combined[8:24] + '"}'
    return pulsar.AuthenticationBasic(username, password, "auth1")


# ---------------------------------------------------------------------------
# Message decryption (supports AES-GCM and AES-ECB)
# ---------------------------------------------------------------------------

def decrypt_message(pulsar_message, access_key: str) -> str | None:
    """
    Decrypt a Tuya Pulsar message.
    The decryption key is access_key[8:24] (16 bytes).
    The mode (GCM or ECB) is in the message property 'em'.
    """
    try:
        payload      = pulsar_message.data().decode("utf-8")
        data_json    = json.loads(payload)
        encrypt_data = data_json.get("data", "")
        decrypt_mode = pulsar_message.properties().get("em", "")

        raw_bytes = base64.b64decode(encrypt_data)
        key_bytes = access_key[8:24].encode("utf-8")

        if decrypt_mode == "aes_gcm":
            nonce      = raw_bytes[:12]
            ciphertext = raw_bytes[12:-16]
            auth_tag   = raw_bytes[-16:]
            cipher     = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
            decrypted  = cipher.decrypt_and_verify(ciphertext, auth_tag)
        else:
            cipher    = AES.new(key_bytes, AES.MODE_ECB)
            decrypted = cipher.decrypt(raw_bytes)

        return decrypted.decode("utf-8").strip()
    except Exception as e:
        logging.warning(f"Decryption failed: {e}")
        return None


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def send_door_email(sensor_name: str, state: str,
                    home_name: str = "", room_name: str = "") -> None:
    if not all([SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM, EMAIL_TO]):
        logging.warning("Email config not set — skipping notification.")
        return
    color       = "red" if state == "OPENED" else "green"
    home_prefix = f"[{home_name}] " if home_name else ""
    subject     = f"Door Alert: {home_prefix}{sensor_name} {state}"
    now         = datetime.now().astimezone()
    timestamp   = now.strftime("%Y-%m-%d %H:%M:%S %Z")
    html = f"""
    <html><body>
        <h2>Door Sensor Alert</h2>
        <p><b>Sensor:</b> {sensor_name}</p>
        <p><b>Home:</b> {home_name or "—"}</p>
        <p><b>Room:</b> {room_name or "—"}</p>
        <p><b>State:</b> <span style='color:{color}; font-size:1.2em'><b>{state}</b></span></p>
        <p><i>{timestamp}</i></p>
    </body></html>
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"SmartLifeMonitor <{EMAIL_FROM}>"
    msg["To"]      = EMAIL_TO
    msg.attach(MIMEText(html, "html"))
    try:
        with smtplib.SMTP(SMTP_SERVER, int(SMTP_PORT)) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        logging.info(f"Email sent → {EMAIL_TO}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Real-time Tuya door sensor email notifier (Pulsar).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--sensor", nargs="*", default=[], metavar="NAME",
                        help="Friendly name(s) of door sensors to monitor. "
                             "Omit to monitor all door sensors on the account.")
    parser.add_argument("--open-only", action="store_true",
                        help="Send email only when the door opens, not when it closes")
    host = socket.gethostname().split(".")[0]
    prog = os.path.splitext(os.path.basename(sys.argv[0]))[0]
    default_consumer = f"{host}-{prog}"
    parser.add_argument("--consumer-name", default=default_consumer,
                        help=f"Consumer name shown in the Tuya portal (default: {default_consumer})")
    parser.add_argument("--test-env", action="store_true",
                        help="Subscribe to the test environment topic instead of production")
    parser.add_argument("--debug", action="store_true",
                        help="Print every raw and decrypted message")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stdout,
    )

    cfg        = load_config()
    access_id  = cfg.get("TUYA_ACCESS_ID",  "").strip()
    access_key = cfg.get("TUYA_ACCESS_KEY", "").strip()
    base_url   = cfg.get("TUYA_BASE_URL", TUYA_BASE_URL).strip()

    if not access_id or not access_key:
        sys.exit("TUYA_ACCESS_ID and TUYA_ACCESS_KEY must be set in .config")

    # -- Resolve sensors -------------------------------------------------------
    cloud   = TuyaCloud(access_id, access_key, base_url)
    label   = "all door sensors" if not args.sensor else ", ".join(f'"{s}"' for s in args.sensor)
    logging.info(f"Resolving sensors ({label}) …")
    monitored = cloud.resolve_sensors(args.sensor)   # {device_id: name}

    logging.info("Fetching home/room assignments …")
    location_map = cloud.build_location_map()         # {device_id: (home, room)}
    for did, dname in sorted(monitored.items(),
                             key=lambda kv: (location_map.get(kv[0], ("", ""))[0].lower(),
                                             kv[1].lower())):
        home, room = location_map.get(did, ("", ""))
        path = " / ".join(filter(None, [home, room, dname]))
        logging.info(f'  Monitoring: {path}  id={did}')

    # -- Pulsar setup ----------------------------------------------------------
    mq_env       = MQ_ENV_TEST if args.test_env else MQ_ENV_PROD
    topic        = f"{access_id}/out/{mq_env}"
    sub_name     = f"{access_id}-sub"

    logging.info(f"Connecting to {PULSAR_URL} …")
    logging.debug(f"  topic={topic}  subscription={sub_name}  env={mq_env}")

    pulsar_log_level = pulsar.LoggerLevel.Debug if args.debug else pulsar.LoggerLevel.Error
    client = pulsar.Client(
        PULSAR_URL,
        authentication=get_pulsar_auth(access_id, access_key),
        tls_allow_insecure_connection=True,
        operation_timeout_seconds=30,
        logger=pulsar.ConsoleLogger(pulsar_log_level),
    )

    consumer = client.subscribe(
        topic,
        sub_name,
        consumer_type=pulsar.ConsumerType.Failover,
        consumer_name=args.consumer_name,
    )

    logging.info(f"Listening for door events on {len(monitored)} sensor(s) — Ctrl-C to stop.")
    if args.open_only:
        logging.info("  (--open-only: close events logged but not emailed)")

    try:
        while True:
            try:
                msg = consumer.receive(timeout_millis=5_000)
            except pulsar.Interrupted:
                logging.info("Interrupted — shutting down.")
                break
            except Exception:
                continue   # receive timeout — keep looping

            if args.debug:
                logging.debug(f"RAW bytes: {msg.data()[:200]}")

            decrypted = decrypt_message(msg, access_key)
            if decrypted is None:
                consumer.acknowledge_cumulative(msg)
                continue

            if args.debug:
                logging.debug(f"DECRYPTED: {decrypted}")

            try:
                payload = json.loads(decrypted)
            except json.JSONDecodeError:
                logging.warning(f"Non-JSON decrypted payload: {decrypted[:120]}")
                consumer.acknowledge_cumulative(msg)
                continue

            # devId may be top-level (older format) or inside bizData (newer format)
            biz_data = payload.get("bizData", {})
            dev_id   = payload.get("devId") or biz_data.get("devId", "")

            sensor_name = monitored.get(dev_id)
            if sensor_name is None:
                consumer.acknowledge_cumulative(msg)
                continue

            # status items may be in top-level 'status' or bizData 'properties'
            items = payload.get("status") or biz_data.get("properties", [])
            for item in items:
                if item.get("code") == DOOR_CODE:
                    is_open = bool(item.get("value"))
                    state   = "OPENED" if is_open else "CLOSED"
                    home, room = location_map.get(dev_id, ("", ""))
                    loc_str    = f" [{home} / {room}]" if home or room else ""
                    logging.info(f'Door event: "{sensor_name}"{loc_str} → {state}')
                    if is_open or not args.open_only:
                        send_door_email(sensor_name, state, home, room)

            consumer.acknowledge_cumulative(msg)

    finally:
        consumer.close()
        client.close()


if __name__ == "__main__":
    main()
