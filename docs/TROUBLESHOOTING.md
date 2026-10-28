# Troubleshooting (Windows & Linux)

| Problem | Cause | Fix |
|---|---|---|
| `python` not recognised (Windows) | Python not on PATH | Reinstall Python, tick "Add to PATH", or use `py -3` |
| PowerShell: "running scripts is disabled" | Execution policy | `Set-ExecutionPolicy -Scope Process Bypass` then re-run `venv\Scripts\activate` |
| `ModuleNotFoundError: flask` | venv not active / deps missing | Activate venv, `pip install -r requirements.txt` |
| `pip install scapy` fails | Old pip / no internet | `python -m pip install --upgrade pip`; Simulation + PCAP still work without Scapy |
| Live start: "Scapy/Npcap is not available" | Scapy or Npcap missing | `pip install scapy`; Windows: install Npcap (WinPcap-compatible mode), restart terminal |
| Live start: "Permission denied" / "Could not start packet capture" | Not privileged | Windows: run terminal as Administrator. Linux/macOS: `sudo venv/bin/python app.py` |
| No packets in live mode | Wrong interface | Leave interface blank or pick one from the list; check with Wireshark |
| Port 5000 already in use | Another app (AirPlay on macOS) | `set SYN_PORT=5001` (Windows) / `SYN_PORT=5001 python app.py` (Linux) |
| Charts empty | Chart.js CDN blocked/offline | See README section 9 (local copy) |
| Upload error 422 | Not a valid PCAP/PCAPNG, or empty | Re-save capture from Wireshark as `.pcap` / `.pcapng` |
| Upload error 413 | File > 50 MB | Split capture or raise `MAX_CONTENT_LENGTH` in config.py |
| PCAP shows 0 TCP packets | Unsupported link type or non-TCP traffic | Capture TCP traffic on Ethernet/Wi-Fi |
| `database is locked` | Two copies of the app | Close the other instance |
| Sample script fails | Wrong folder | Run commands from the project root |

Logs are in `logs/app.log`. Reset everything by stopping the app and deleting `data/syn_monitor.db`.
