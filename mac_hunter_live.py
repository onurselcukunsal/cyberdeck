
#!/usr/bin/env python3

import csv
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.table import Table
from scapy.all import sniff, Dot11, RadioTap
from scapy.sendrecv import AsyncSniffer

INTERFACE = "wlan1mon"
REFRESH_SECONDS = 1
SAVE_EVERY_SECONDS = 5

console = Console()
devices = {}
total_packets = 0


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


def now():
    return datetime.now().astimezone().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def classify(packet):
    frame = packet[Dot11]

    if frame.type == 0:
        subtypes = {
            0: "Association Request",
            1: "Association Response",
            2: "Reassociation Request",
            3: "Reassociation Response",
            4: "Probe Request",
            5: "Probe Response",
            8: "Beacon",
            10: "Disassociation",
            11: "Authentication",
            12: "Deauthentication",
            13: "Action",
        }
        return subtypes.get(frame.subtype, "Management")

    if frame.type == 1:
        return "Control"

    if frame.type == 2:
        return "Data"

    return "Unknown"


def get_signal(packet):
    if packet.haslayer(RadioTap):
        value = getattr(
            packet[RadioTap],
            "dBm_AntSignal",
            None,
        )
        if isinstance(value, (int, float)):
            return value

    return None


def on_packet(packet):
    global total_packets

    if not packet.haslayer(Dot11):
        return

    frame = packet[Dot11]
    mac = frame.addr2

    if not mac:
        return

    current_time = now()
    frame_type = classify(packet)
    signal = get_signal(packet)

    if mac not in devices:
        devices[mac] = {
            "first_seen": current_time,
            "last_seen": current_time,
            "packet_count": 0,
            "frame_types": set(),
            "last_signal_dbm": None,
        }

    entry = devices[mac]
    entry["last_seen"] = current_time
    entry["packet_count"] += 1
    entry["frame_types"].add(frame_type)

    if signal is not None:
        entry["last_signal_dbm"] = signal

    total_packets += 1


def build_table():
    table = Table(
        title="MAC Hunter | Passive Wi-Fi Monitor",
        expand=True,
    )

    table.add_column("MAC adress", style="cyan")
    table.add_column("Package", justify="right")
    table.add_column("Last RSSI", justify="right")
    table.add_column("Son seen")
    table.add_column("Frame Types")

    for mac, entry in sorted(
        devices.items(),
        key=lambda item: item[1]["last_seen"],
        reverse=True,
    ):
        signal = entry["last_signal_dbm"]
        signal_text = (
            f"{signal} dBm"
            if signal is not None
            else "N/A"
        )

        table.add_row(
            mac,
            str(entry["packet_count"]),
            signal_text,
            entry["last_seen"],
            ", ".join(sorted(entry["frame_types"])),
        )

    table.caption = (
        f"Interface: {INTERFACE} | "
        f"Unique transmitter address: {len(devices)} | "
        f"Total package: {total_packets}"
    )

    return table


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
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fields,
        )
        writer.writeheader()

        for mac, entry in sorted(devices.items()):
            writer.writerow({
                "mac": mac,
                "first_seen": entry["first_seen"],
                "last_seen": entry["last_seen"],
                "packet_count": entry["packet_count"],
                "frame_types": ", ".join(
                    sorted(entry["frame_types"])
                ),
                "last_signal_dbm": (
                    entry["last_signal_dbm"]
                    if entry["last_signal_dbm"] is not None
                    else ""
                ),
            })

    temp_path.replace(CSV_PATH)


def main():
    console.print("[bold green]MAC Hunter is starting up.[/bold green]")
    console.print(f"Interface: {INTERFACE}")
    console.print(f"CSV file: {CSV_PATH}")
    console.print("Exit: Ctrl+C\n")

    sniffer = AsyncSniffer(
        iface=INTERFACE,
        prn=on_packet,
        store=False,
    )

    last_save = time.monotonic()

    try:
        with Live(
            build_table(),
            console=console,
            refresh_per_second=4,
        ) as live:
            sniffer.start()

            while True:
                live.update(build_table())

                current = time.monotonic()
                if current - last_save >= SAVE_EVERY_SECONDS:
                    save_csv()
                    last_save = current

                time.sleep(REFRESH_SECONDS)

    except KeyboardInterrupt:
        console.print("\n[yellow]Listening is stopping...[/yellow]")

    except (PermissionError, OSError, RuntimeError) as exc:
        console.print(f"\n[red]Hata:[/red] {exc}")
        sys.exit(1)

    finally:
        if sniffer.running:
            sniffer.stop()

        save_csv()

    console.print(f"[green]CSV saved:[/green] {CSV_PATH}")
    console.print(f"Total Package: {total_packets}")
    console.print(f"Unique Adress: {len(devices)}")


if __name__ == "__main__":
    main()
