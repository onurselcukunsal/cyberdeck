
import csv
import sys
import subprocess
from pathlib import Path
from datetime import datetime
from scapy.all import sniff, Dot11, RadioTap

INTERFACE = "wlan1mon"


def get_desktop():
    try:
        result = subprocess.run(
            ["xdg-user-dir", "DESKTOP"],
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )
        path = Path(result.stdout.strip()).expanduser()
        if path.is_dir():
            return path
    except (OSError, subprocess.SubprocessError):
        pass

    return Path.home()


CSV_PATH = get_desktop() / "mac_hunter.csv"
devices = {}

SUBTYPES = {
    0: "Association Request",
    1: "Association Response",
    4: "Probe Request",
    5: "Probe Response",
    8: "Beacon",
    10: "Disassociation",
    11: "Authentication",
    12: "Deauthentication",
}


def now():
    return datetime.now().astimezone().isoformat(
        timespec="seconds"
    )


def classify(pkt):
    dot11 = pkt[Dot11]

    if dot11.type == 0:
        return SUBTYPES.get(dot11.subtype, "Management")
    if dot11.type == 1:
        return "Control"
    if dot11.type == 2:
        return "Data"

    return "Unknown"


def get_signal(pkt):
    if pkt.haslayer(RadioTap):
        value = getattr(
            pkt[RadioTap], "dBm_AntSignal", None
        )
        if isinstance(value, (int, float)):
            return value
    return None


def save_csv():
    fields = [
        "mac",
        "first_seen",
        "last_seen",
        "packet_count",
        "frame_types",
        "last_signal_dbm",
    ]

    temp_path = CSV_PATH.with_suffix(".tmp")

    with temp_path.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for mac, item in sorted(devices.items()):
            writer.writerow({
                "mac": mac,
                "first_seen": item["first_seen"],
                "last_seen": item["last_seen"],
                "packet_count": item["packet_count"],
                "frame_types": ", ".join(
                    sorted(item["frame_types"])
                ),
                "last_signal_dbm": (
                    item["last_signal_dbm"]
                    if item["last_signal_dbm"] is not None
                    else ""
                ),
            })

    temp_path.replace(CSV_PATH)


def packet_callback(pkt):
    if not pkt.haslayer(Dot11):
        return

    dot11 = pkt[Dot11]
    mac = dot11.addr2

    if not mac:
        return

    timestamp = now()
    frame_type = classify(pkt)
    signal = get_signal(pkt)
    is_new = mac not in devices

    if is_new:
        devices[mac] = {
            "first_seen": timestamp,
            "last_seen": timestamp,
            "packet_count": 0,
            "frame_types": set(),
            "last_signal_dbm": None,
        }

    item = devices[mac]
    item["last_seen"] = timestamp
    item["packet_count"] += 1
    item["frame_types"].add(frame_type)

    if signal is not None:
        item["last_signal_dbm"] = signal

    if is_new:
        print(
            f"{mac:<20} | "
            f"{signal if signal is not None else 'Bilinmiyor':<12} | "
            f"{frame_type}"
        )
        save_csv()
        print(f"[+] Kayıt: {CSV_PATH}")


def main():
    print("\n[*] MAC Hunter 2.0 başlatılıyor\n")
    print(f"{'MAC ADRESİ':<20} | {'SİNYAL':<12} | TÜR")
    print("-" * 65)
    print(f"[*] CSV: {CSV_PATH}")
    print("[*] Durdurmak için Ctrl+C\n")

    try:
        sniff(
            iface=INTERFACE,
            prn=packet_callback,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n[*] Dinleme durduruldu.")
    except (PermissionError, OSError) as exc:
        print(f"\n[-] Arayüz/izin hatası: {exc}")
        sys.exit(1)
    finally:
        if devices:
            save_csv()
            print(f"[*] {len(devices)} adres kaydedildi.")
            print(f"[*] Dosya: {CSV_PATH}")


if __name__ == "__main__":
    main()
