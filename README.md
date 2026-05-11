# Tuya API Utilities

This repository provides Python scripts for interacting with Tuya Cloud devices, including device listing and automated control based on sensor readings.

## Prerequisites
- Python 3.7+
- Tuya Cloud account ([iot.tuya.com](https://iot.tuya.com/))
- Tuya API credentials (Access ID, Access Secret, and registered project)

## Virtual Environment Setup (Recommended)

1. Create a virtual environment:
   ```bash
   python3 -m venv .venv
   ```
2. Activate the virtual environment:
   - On Linux/macOS:
     ```bash
     source .venv/bin/activate
     ```
   - On Windows:
     ```cmd
     .venv\Scripts\activate
     ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

All commands in this README assume you have activated your virtual environment.

## Setup
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Create a `.config` file in this directory with your Tuya API credentials:
   ```
   TUYA_ACCESS_ID=your-access-id
   TUYA_ACCESS_KEY=your-access-key
   # Optionally:
   # TUYA_BASE_URL=https://openapi.tuyaus.com
   ```

## Scripts

### tuya-lister.py
Lists all devices in your Tuya Cloud account, showing their status and key properties in a pretty table.

**Usage:**
```bash
python tuya-lister.py
```

- Reads credentials from `.config`.
- Fetches all devices and their live status.
- Outputs a sorted table by friendly name.

### tuya-temp-control.py
Automates control of a Tuya switch based on a temperature sensor reading (e.g., turn off a heater if temperature exceeds a threshold).

**Usage:**
```bash
python tuya-temp-control.py --sensor "Downstairs T&H sensor" --switch "DR Avalon Mini" --threshold 75
```

**Options:**
- `--sensor`   : Friendly name of the temperature sensor device
- `--switch`   : Friendly name of the switch device to control
- `--threshold`: Temperature threshold in °F (default: 75)
- `--dry-run`  : Show actions but do not send commands
- `--debug`    : Output all devices and their current state
- `--log`      : Log file path

- Reads credentials from `.config`.
- Logs all actions and device statuses.
- Supports cron/automation use.

## Security
- The `.config` file is included in `.gitignore` and will not be committed to git.
- Do not share your credentials.

## License
MIT
