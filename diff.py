#!/usr/bin/env python3
import os
import json
import requests
from pathlib import Path
from dotenv import load_dotenv

BASE = "https://attestation.app/api"

LOGIN_URL = f"{BASE}/login"
ACCOUNT_URL = f"{BASE}/account"
DEVICES_URL = f"{BASE}/devices.json"
HISTORY_URL = f"{BASE}/attestation-history.json"

COOKIE_FILE = Path("cookies.json")

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Content-Type": "application/json",
    "Origin": "https://attestation.app",
    "Referer": "https://attestation.app/",
    "Connection": "keep-alive",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "same-origin",
    "Sec-Fetch-Site": "same-origin",
    "Sec-GPC": "1",
}

def load_credentials():
    load_dotenv()
    u = os.getenv("ATTEST_USERNAME")
    p = os.getenv("ATTEST_PASSWORD")
    if not u or not p:
        raise RuntimeError("ATTEST_USERNAME / ATTEST_PASSWORD не заданы в .env")
    return u, p

def save_cookies(session):
    cookies = requests.utils.dict_from_cookiejar(session.cookies)
    COOKIE_FILE.write_text(json.dumps(cookies, indent=2))
    print("[+] Cookies сохранены")

def load_cookies(session):
    if COOKIE_FILE.exists():
        cookies = json.loads(COOKIE_FILE.read_text())
        session.cookies = requests.utils.cookiejar_from_dict(cookies)
        print("[+] Cookies загружены")
        return True
    return False

def do_login(session):
    username, password = load_credentials()
    print("[*] Логин...")
    r = session.post(LOGIN_URL, json={"username": username, "password": password}, headers=HEADERS)
    if r.status_code != 200:
        print("[!] Ошибка логина:", r.status_code, r.text)
        exit(1)
    print("[+] Login OK")
    save_cookies(session)

def ensure_session():
    s = requests.Session()
    if load_cookies(s):
        r = s.post(ACCOUNT_URL, headers=HEADERS, data=b"")
        if r.status_code == 200:
            print("[+] Сессия активна")
            return s
        print("[!] Сессия истекла — новый логин")
    do_login(s)
    return s

def get_devices(session):
    print("[*] Получаем devices.json ...")
    r = session.post(DEVICES_URL, headers=HEADERS, data=b"")
    if r.status_code != 200:
        print("[!] Ошибка запроса devices:", r.status_code, r.text)
        exit(1)
    devices = r.json()
    print(f"[+] Получено устройств: {len(devices)}")
    return devices

def get_history_chunks(session, fingerprint, start_offset):
    print(f"[*] История для {fingerprint}, offset={start_offset}")
    history = []
    offset = start_offset

    while True:
        payload = {"fingerprint": fingerprint, "offsetId": offset}
        print(f"  -> chunk offset={offset}")
        r = session.post(HISTORY_URL, headers=HEADERS, json=payload)

        if r.status_code != 200:
            print("[!] Ошибка history:", r.status_code, r.text)
            break

        chunk = r.json()
        if not chunk:
            print("  -> Пусто, конец.")
            break

        history.extend(chunk)

        last_id = chunk[-1].get("id") or chunk[-1].get("offsetId")
        if not last_id:
            print("[!] Нет id, останов")
            break

        offset = last_id - 1

    return history

def main():
    session = ensure_session()
    devices = get_devices(session)
    output = {}

    for dev in devices:
        fingerprint = dev["fingerprint"]
        start_offset = dev.get("maxId") or dev.get("minId")

        print(f"\n=== Устройство: {dev.get('name')} ===")
        print(f" fingerprint: {fingerprint}")
        print(f" start offset: {start_offset}")

        history = get_history_chunks(session, fingerprint, start_offset)

        output[fingerprint] = {
            "device": dev,
            "history": history
        }

    Path("attestation_dump.json").write_text(json.dumps(output, indent=2))
    print("\n[+] Сохранено в attestation_dump.json")

if __name__ == "__main__":
    main()