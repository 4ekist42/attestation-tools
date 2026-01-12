#!/usr/bin/env python3
import json
from datetime import datetime
from pathlib import Path

INPUT = Path("attestation_dump.json")

IGNORE_FIELDS = {
    "id",
    "offsetId",
    "verifiedTimeFirst",
    "verifiedTimeLast",
    "timestamp",
    "time",
    "_id",
    "verifiedBootHash",
    "osPatchLevel",
    "vendorPatchLevel",
    "bootPatchLevel"
}

def ts_to_dt(ts):
    if not ts:
        return None
    try:
        return datetime.utcfromtimestamp(ts / 1000).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)

def compare_entries(prev, curr):
    changed = []
    for k in curr.keys():
        if k in IGNORE_FIELDS:
            continue
        if k not in prev:
            continue
        if curr[k] != prev[k]:
            changed.append(k)
    return changed

def extract_timestamp(entry):
    return (
        entry.get("verifiedTimeLast")
        or entry.get("verifiedTimeFirst")
        or entry.get("time")
        or entry.get("timestamp")
    )

def main():
    if not INPUT.exists():
        print("Ошибка: нет файла attestation_dump.json")
        return

    data = json.loads(INPUT.read_text())

    for fingerprint, block in data.items():
        device = block["device"]
        history = block["history"]

        if not history:
            print(f"{fingerprint}: нет истории")
            continue

        print("\n==============================")
        print(f"Устройство: {device.get('name')} ({fingerprint})")
        print("==============================")

        history_sorted = sorted(history, key=lambda x: x.get("id", 0))
        prev = history_sorted[0]

        for entry in history_sorted[1:]:
            changed = compare_entries(prev, entry)

            if changed:
                ts = extract_timestamp(entry)
                dt = ts_to_dt(ts)
                print(f"\n[Изменение] {dt}")
                print("Изменились поля:")
                for field in changed:
                    print(f"  - {field}: {prev.get(field)} → {entry.get(field)}")

            prev = entry

if __name__ == "__main__":
    main()