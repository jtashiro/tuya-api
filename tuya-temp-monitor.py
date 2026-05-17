#!/usr/bin/env python3
"""
Tuya Temperature & Humidity Sensor Monitor

Subscribes to the Tuya Pulsar message service and sends an email when a
temperature or humidity reading crosses a configured threshold.

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
  ./tuya-temp-monitor.py
  ./tuya-temp-monitor.py --sensor "Living Room Sensor"
  ./tuya-temp-monitor.py --temp-high 85 --temp-low 55
  ./tuya-temp-monitor.py --humidity-high 70 --humidity-low 30
  ./tuya-temp-monitor.py --celsius --temp-high 30 --temp-low 13
  ./tuya-temp-monitor.py --cooldown 60        # alert cooldown in minutes
  ./tuya-temp-monitor.py --poll-interval 5    # poll REST API every 5 minutes
  ./tuya-temp-monitor.py --debug
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
import threading
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

SENSOR_CATEGORIES = {"wsdcg", "wsh"}   # Tuya categories for temp+humidity sensors
TEMP_CODES        = {"va_temperature", "temp_current", "temp_value"}
HUMIDITY_CODES    = {"va_humidity", "humidity_value", "humidity"}


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

        If names is empty, returns all temp/humidity sensors on the account
        (Tuya categories in SENSOR_CATEGORIES).  If names are provided, each
        must match a device by friendly name (case-insensitive).
        """
        all_devices = self.get_all_devices()

        if not names:
            sensors = {d["id"]: d.get("name", d["id"]).strip()
                       for d in all_devices if d.get("category") in SENSOR_CATEGORIES}
            if not sensors:
                cats = ", ".join(sorted(SENSOR_CATEGORIES))
                sys.exit(f"No temp/humidity sensors (categories: {cats}) found on this account.")
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

    def get_device_status(self, device_id: str) -> list[dict]:
        """Return current DPS status items for a single device."""
        data = self._get(f"/v1.0/devices/{device_id}/status")
        if not data.get("success"):
            return []
        return data.get("result", [])


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
# Unit helpers
# ---------------------------------------------------------------------------

def tuya_to_c(raw: int) -> float:
    """Convert Tuya raw temperature value to °C. Values > 200 are in tenths."""
    return raw / 10.0 if abs(raw) > 200 else float(raw)


def c_to_f(c: float) -> float:
    return c * 9.0 / 5.0 + 32.0


def format_temp(c: float, use_celsius: bool) -> str:
    if use_celsius:
        return f"{c:.1f}°C"
    return f"{c_to_f(c):.1f}°F"


# ---------------------------------------------------------------------------
# Threshold check
# ---------------------------------------------------------------------------

def check_thresholds(
    temp_c: float | None,
    humidity: float | None,
    temp_high: float | None,
    temp_low: float | None,
    humidity_high: float | None,
    humidity_low: float | None,
    use_celsius: bool,
) -> list[str]:
    """Return a list of human-readable threshold breach descriptions."""
    alerts = []
    if temp_c is not None:
        display = format_temp(temp_c, use_celsius)
        compare = temp_c if use_celsius else c_to_f(temp_c)
        if temp_high is not None and compare > temp_high:
            limit = f"{temp_high:.1f}°{'C' if use_celsius else 'F'}"
            alerts.append(f"Temperature {display} exceeds high threshold ({limit})")
        if temp_low is not None and compare < temp_low:
            limit = f"{temp_low:.1f}°{'C' if use_celsius else 'F'}"
            alerts.append(f"Temperature {display} below low threshold ({limit})")
    if humidity is not None:
        if humidity_high is not None and humidity > humidity_high:
            alerts.append(f"Humidity {humidity:.0f}% exceeds high threshold ({humidity_high:.0f}%)")
        if humidity_low is not None and humidity < humidity_low:
            alerts.append(f"Humidity {humidity:.0f}% below low threshold ({humidity_low:.0f}%)")
    return alerts


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

def send_alert_email(
    sensor_name: str,
    alerts: list[str],
    temp_c: float | None,
    humidity: float | None,
    home_name: str = "",
    room_name: str = "",
    use_celsius: bool = False,
) -> None:
    if not all([SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, EMAIL_FROM, EMAIL_TO]):
        logging.warning("Email config not set — skipping notification.")
        return

    home_prefix = f"[{home_name}] " if home_name else ""
    subject     = f"Temp/Humidity Alert: {home_prefix}{sensor_name}"
    now         = datetime.now().astimezone()
    timestamp   = now.strftime("%Y-%m-%d %H:%M:%S %Z")

    temp_str     = format_temp(temp_c, use_celsius) if temp_c is not None else "—"
    humidity_str = f"{humidity:.0f}%" if humidity is not None else "—"

    alerts_html = "".join(
        f"<li style='color:#c0392b'>{a}</li>" for a in alerts
    )

    html = f"""
    <html><body style="font-family:sans-serif">
        <h2>Temperature &amp; Humidity Alert</h2>
        <p><b>Sensor:</b> {sensor_name}</p>
        <p><b>Home:</b> {home_name or "—"}</p>
        <p><b>Room:</b> {room_name or "—"}</p>
        <table style="border-collapse:collapse;margin:12px 0">
            <tr>
                <td style="padding:6px 16px 6px 0"><b>Temperature</b></td>
                <td style="padding:6px 0;font-size:1.2em"><b>{temp_str}</b></td>
            </tr>
            <tr>
                <td style="padding:6px 16px 6px 0"><b>Humidity</b></td>
                <td style="padding:6px 0;font-size:1.2em"><b>{humidity_str}</b></td>
            </tr>
        </table>
        <ul style="margin:12px 0">{alerts_html}</ul>
        <p><i>{timestamp}</i></p>
    </body></html>
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"{home_name or 'Home'} Monitor <no-reply@fiospace.com>"
    msg["To"]      = EMAIL_TO
    msg.attach(MIMEText(html, "html"))
    try:
        with smtplib.SMTP(SMTP_SERVER, int(SMTP_PORT)) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        logging.info(f"Alert email sent → {EMAIL_TO}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Real-time Tuya temperature & humidity sensor email notifier (Pulsar).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--sensor", nargs="*", default=[], metavar="NAME",
                        help="Friendly name(s) of sensors to monitor. "
                             "Omit to monitor all temp/humidity sensors on the account.")
    parser.add_argument("--temp-high", type=float, default=None, metavar="TEMP",
                        help="Alert when temperature exceeds this value (°F by default)")
    parser.add_argument("--temp-low", type=float, default=None, metavar="TEMP",
                        help="Alert when temperature drops below this value (°F by default)")
    parser.add_argument("--humidity-high", type=float, default=None, metavar="PCT",
                        help="Alert when humidity exceeds this percentage")
    parser.add_argument("--humidity-low", type=float, default=None, metavar="PCT",
                        help="Alert when humidity drops below this percentage")
    parser.add_argument("--celsius", action="store_true",
                        help="Interpret --temp-high/--temp-low in °C and display temperatures in °C")
    parser.add_argument("--cooldown", type=int, default=30, metavar="MINUTES",
                        help="Minimum minutes between repeated alerts for the same sensor (default: 30)")
    parser.add_argument("--poll-interval", type=int, default=5, metavar="MINUTES",
                        help="Poll the REST API every N minutes for sensors not heard from via Pulsar "
                             "(default: 5, use 0 to disable)")
    host = socket.gethostname().split(".")[0]
    prog = os.path.splitext(os.path.basename(sys.argv[0]))[0]
    default_consumer = f"{host}-{prog}"
    parser.add_argument("--consumer-name", default=default_consumer,
                        help=f"Consumer name shown in the Tuya portal (default: {default_consumer})")
    parser.add_argument("--test-env", action="store_true",
                        help="Subscribe to the test environment topic instead of production")
    parser.add_argument("--log", default=None, metavar="FILE",
                        help="Also write log output to this file")
    parser.add_argument("--debug", action="store_true",
                        help="Print every raw and decrypted message")
    args = parser.parse_args()

    level    = logging.DEBUG if args.debug else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if args.log:
        os.makedirs(os.path.dirname(args.log), exist_ok=True)
        handlers.append(logging.FileHandler(args.log))
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=handlers)

    if not any([args.temp_high, args.temp_low, args.humidity_high, args.humidity_low]):
        logging.warning("No thresholds set — readings will be logged but no alerts will be sent.")

    cfg        = load_config()
    access_id  = cfg.get("TUYA_ACCESS_ID",  "").strip()
    access_key = cfg.get("TUYA_ACCESS_KEY", "").strip()
    base_url   = cfg.get("TUYA_BASE_URL", TUYA_BASE_URL).strip()

    if not access_id or not access_key:
        sys.exit("TUYA_ACCESS_ID and TUYA_ACCESS_KEY must be set in .config")

    # -- Resolve sensors -------------------------------------------------------
    cloud   = TuyaCloud(access_id, access_key, base_url)
    label   = "all temp/humidity sensors" if not args.sensor else ", ".join(f'"{s}"' for s in args.sensor)
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

    # -- Shared state (accessed from both Pulsar and poll threads) -------------
    readings:       dict[str, dict]  = {did: {"temp_c": None, "humidity": None} for did in monitored}
    last_logged:    dict[str, dict]  = {did: {"temp_c": None, "humidity": None} for did in monitored}
    last_alert:     dict[str, float] = {}
    pulsar_sensors: set[str]         = set()   # sensors confirmed to push via Pulsar
    state_lock      = threading.Lock()
    cooldown_secs       = args.cooldown * 60
    poll_interval_secs  = args.poll_interval * 60

    def process_items(dev_id: str, items: list[dict], source: str) -> None:
        """Apply a batch of DPS status items, log changes, and fire alerts."""
        with state_lock:
            changed = []
            for item in items:
                code  = item.get("code", "")
                value = item.get("value")
                if code in TEMP_CODES and value is not None:
                    readings[dev_id]["temp_c"] = tuya_to_c(int(value))
                    changed.append(f"temp={format_temp(readings[dev_id]['temp_c'], args.celsius)}")
                elif code in HUMIDITY_CODES and value is not None:
                    readings[dev_id]["humidity"] = float(value)
                    changed.append(f"humidity={readings[dev_id]['humidity']:.0f}%")

            if not changed:
                return

            temp_c   = readings[dev_id]["temp_c"]
            humidity = readings[dev_id]["humidity"]

            # Deduplicate: Tuya often sends two identical Pulsar messages per cycle
            prev = last_logged[dev_id]
            if temp_c == prev["temp_c"] and humidity == prev["humidity"]:
                return
            last_logged[dev_id] = {"temp_c": temp_c, "humidity": humidity}

        sensor_name = monitored[dev_id]
        home, room  = location_map.get(dev_id, ("", ""))
        loc_str     = f" [{home} / {room}]" if home or room else ""
        logging.info(f'{source}: "{sensor_name}"{loc_str} → {", ".join(changed)}')

        alerts = check_thresholds(
            temp_c, humidity,
            args.temp_high, args.temp_low,
            args.humidity_high, args.humidity_low,
            args.celsius,
        )
        if not alerts:
            return

        with state_lock:
            since_last = time.time() - last_alert.get(dev_id, 0)
            can_alert  = since_last >= cooldown_secs
            if can_alert:
                last_alert[dev_id] = time.time()

        if can_alert:
            for a in alerts:
                logging.warning(f"  ALERT: {a}")
            send_alert_email(sensor_name, alerts, temp_c, humidity, home, room, args.celsius)
        else:
            remaining = int((cooldown_secs - since_last) / 60)
            logging.info(f"  Threshold breached but cooldown active ({remaining}m remaining)")

    # -- Poll thread -----------------------------------------------------------
    if poll_interval_secs > 0:
        def poll_loop() -> None:
            logging.info(f"Poll thread started — polling {len(monitored)} sensor(s) every {args.poll_interval}m")
            while True:
                with state_lock:
                    to_poll = [did for did in monitored if did not in pulsar_sensors]
                if not to_poll:
                    logging.info("Poll thread: all sensors are pushing via Pulsar — exiting poll loop")
                    return
                for dev_id in to_poll:
                    sensor_name = monitored[dev_id]
                    try:
                        status = cloud.get_device_status(dev_id)
                    except Exception as e:
                        logging.warning(f'Poll failed for "{sensor_name}": {e}')
                        continue
                    if status:
                        process_items(dev_id, status, "Poll")
                time.sleep(poll_interval_secs)

        t = threading.Thread(target=poll_loop, daemon=True, name="poll")
        t.start()

    # -- Pulsar setup ----------------------------------------------------------
    mq_env   = MQ_ENV_TEST if args.test_env else MQ_ENV_PROD
    topic    = f"{access_id}/out/{mq_env}"
    sub_name = f"{access_id}-sub"

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

    logging.info(f"Listening for temp/humidity events on {len(monitored)} sensor(s) — Ctrl-C to stop.")

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

            biz_data = payload.get("bizData", {})
            dev_id   = payload.get("devId") or biz_data.get("devId", "")

            sensor_name = monitored.get(dev_id)
            if sensor_name is None:
                consumer.acknowledge_cumulative(msg)
                continue

            items = payload.get("status") or biz_data.get("properties", [])
            with state_lock:
                first_pulsar = dev_id not in pulsar_sensors
                pulsar_sensors.add(dev_id)
            if first_pulsar:
                logging.info(f'"{sensor_name}" is pushing via Pulsar — removing from poll list')
            process_items(dev_id, items, "Pulsar")

            consumer.acknowledge_cumulative(msg)

    finally:
        consumer.close()
        client.close()


if __name__ == "__main__":
    main()
