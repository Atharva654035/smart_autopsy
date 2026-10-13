# Smart Autopsy

> **Intelligent Digital Forensics & File Carving Platform for Linux Workstations**

An advanced, modular digital forensics desktop application for forensic investigators to recover deleted, damaged, and unallocated files from physical storage devices (`/dev/sdb`, `/dev/nvme0n1`) and forensic disk images (`.dd`, `.img`, `.raw`).

---

## 📖 Complete Documentation & Progress
A comprehensive project document covering full architecture, module breakdowns, technical implementation details, operational instructions, and troubleshooting is available in:

👉 **[PROJECT_DOCUMENTATION.md](file:///d:/Desktop/SmartAutopsy/PROJECT_DOCUMENTATION.md)**

---

## ⚡ Quick Start (Kali Linux / Ubuntu)

### 1. Setup Virtual Environment & Dependencies
```bash
cd ~/smart_autopsy
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Launching

#### Forensic Disk Images (No Root):
```bash
source .venv/bin/activate
python3 main.py
```

#### Physical Block Devices (Root / Sudo):
```bash
source .venv/bin/activate
sudo $(which python3) main.py
```

*If you encounter an X11 display permission error running with `sudo`:*
```bash
xhost +si:localuser:root
sudo -E $(which python3) main.py
```

---

## 📁 Project Structure

```
smart_autopsy/
├── PROJECT_DOCUMENTATION.md    # Detailed architecture & progress report
├── main.py                     # Application entry point & environment validation
├── requirements.txt            # Python dependencies
├── core/
│   ├── __init__.py             # Core package initializer
│   ├── scanner.py              # Module 1: Physical drive discovery & raw sector streaming
│   └── carver.py               # Module 2: File carving engine, signature matching & hashing
└── gui/
    ├── __init__.py             # GUI package initializer
    └── dashboard.py            # CustomTkinter dark-mode forensic dashboard
```