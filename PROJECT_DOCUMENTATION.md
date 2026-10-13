# Smart Autopsy — Project Documentation & Progress Report
**Intelligent Digital Forensics & File Carving Platform for Linux Workstations**

---

## 1. Executive Summary & Operational Context

**Smart Autopsy** is a modular, high-performance digital forensics workstation application designed for digital forensics investigators and recovery engineers. 

When digital evidence media (such as physical hard drives, SSDs, USB drives, or forensic disk images) arrive in the lab, file systems (FAT32, NTFS, EXT4, etc.) are frequently corrupted, partitioned over, deleted, or unallocated. **Smart Autopsy** bypasses traditional operating system file system drivers and file allocation tables by reading low-level storage sectors directly (`/dev/sdb`, `/dev/nvme0n1`, etc.). It performs automated, signature-based file carving, validates recovered data, computes cryptographic hashes for legal evidence chains of custody, and prevents evidence contamination.

---

## 2. System Architecture & Pipeline

The system is structured as an extensible pipeline:

```
┌────────────────────────────────┐
│   Physical Storage Device      │  or  Forensic Disk Images
│     (/dev/sdb, /dev/sdc)       │      (.dd, .img, .raw)
└───────────────┬────────────────┘
                │
                ▼
┌────────────────────────────────┐
│   Module 1: Scanner Engine     │  • lsblk --json device discovery
│     (core/scanner.py)          │  • BLKGETSIZE64 ioctl sizing
└───────────────┬────────────────┘  • 64 KiB chunked stream reader
                │ (raw binary generator)
                ▼
┌────────────────────────────────┐
│   Module 2: Carver Engine      │  • Sliding-window buffer (boundary protection)
│     (core/carver.py)           │  • Header/footer signature matching
└───────────────┬────────────────┘  • Write-back protection gate (st_dev check)
                │                   • Simultaneous MD5 + SHA-256 hash generation
                ▼
┌────────────────────────────────┐
│   Module 3: Forensic GUI       │  • CustomTkinter dark-mode dashboard
│     (gui/dashboard.py)         │  • Real-time ttk.Treeview evidence table
└────────────────────────────────┘  • Thread-safe progress & control dispatch
```

---

## 3. Detailed Component Breakdown

### 3.1 Module 1: Data Acquisition & Raw Sector Reader (`core/scanner.py`)
- **Device Discovery (`list_physical_drives`)**:
  - Enumerate storage block devices via `lsblk --json -b -o NAME,PATH,SIZE,TYPE,MOUNTPOINT,MODEL,VENDOR,SERIAL,TRAN`.
  - Filters out boot/OS loop devices and system drives while surfacing target drives with readable capacity and transport types (USB, SATA, NVMe).
- **Physical Sector Reader (`DriveScanner`)**:
  - Direct binary reading via `open(path, "rb")`.
  - Query device size on Linux via low-level `ioctl` using `BLKGETSIZE64` (`0x80081272`).
  - Streams sectors in 64 KiB chunks as a Python generator (`stream_chunks()`) to ensure minimal memory overhead regardless of target drive size (e.g., 2 TB drives scan with < 100 MB RAM usage).
  - Robust exception handling for unreadable/bad sectors and permission barriers.

### 3.2 Module 2: File Carver Engine (`core/carver.py`)
- **Sliding-Window Matching**:
  - Implements a continuous sliding buffer with 16-byte tail retention across 64 KiB chunk boundaries so magic headers and footers crossing buffer edges are not missed.
- **Supported File Signatures**:
  - **JPEG** (`.jpg`): `FF D8 FF E0/E1/E2/DB` ... `FF D9`
  - **PDF** (`.pdf`): `%PDF` ... `%%EOF`
  - **PNG** (`.png`): `\x89PNG\r\n\x1a\n` ... `IEND\xaeB\`\x82`
  - **ZIP** (`.zip`): `PK\x03\x04` ... `PK\x05\x06`
  - **DOCX / Office** (`.docx`): `PK\x03\x04\x14\x00\x06\x00` ... `PK\x05\x06`
  - **MP3** (`.mp3`): `ID3` / `FF FB` frame sync
  - **GIF** (`.gif`): `GIF87a` / `GIF89a` ... `00 3B`
  - **BMP** (`.bmp`): `BM`
  - Headers are sorted in descending order of length so specific file formats (e.g., DOCX) take precedence over general formats (e.g., ZIP).
- **Critical Forensic Safety Gate (`SafetyViolationError`)**:
  - Checks filesystem device numbers (`os.stat().st_dev`) between the target device and the export folder.
  - **Strictly refuses** to export carved files back onto the source evidence drive, preventing catastrophic destruction of unallocated sectors.
- **Cryptographic Evidence Verification**:
  - Concurrently computes **MD5** and **SHA-256** checksums for every carved file.
  - Generates unique hex offset identifiers (`0x0001A400`) and metadata records (`CarvedFile`).
- **Memory & Allocation Guard**:
  - Implements a 50 MiB hard cap (`MAX_FILE_BYTES`) per carved file to prevent corrupt sectors from triggering runaway allocations.

### 3.3 Forensic Dashboard GUI (`gui/dashboard.py`)
- Built using **CustomTkinter** with a dark cybersecurity-themed interface.
- **Top Header**: Live dynamic badge displaying execution status:
  - 🟢 `ROOT PRIVILEGES ACTIVE` (Full raw block-device access enabled)
  - 🟡 `IMAGE-ONLY MODE (NON-ROOT)` (Advisory indicating disk images only)
- **Left Control Panel**:
  - Device dropdown (auto-refreshed physical drives).
  - Disk image file picker (`.dd`, `.img`, `.raw`, `.E01-raw`).
  - Export directory selector.
  - File-type checkboxes (toggle JPEG, PNG, PDF, DOCX, ZIP, etc.).
  - Real-time progress bar, speed indicators, and dynamic elapsed time counter.
  - Asynchronous Start / Stop controls.
- **Right Evidence Panel**:
  - Real-time `ttk.Treeview` styled table.
  - Columns: File Name, Type, Offset (Hex), Size, MD5, SHA-256.
  - Alternating row styling and auto-scroll to latest carved artifact.
- **Threading Model**:
  - File carving executes in a background daemon thread (`threading.Thread`).
  - Thread-safe UI updates use `widget.after()` callbacks to prevent GUI freezing.

### 3.4 Application Entry Point (`main.py`)
- Python version verification (requires Python >= 3.9).
- Platform constraint enforcement (Linux forensic workstation environment).
- Dual logging configuration (console stdout + rotating log file `smart_autopsy.log`).
- Window geometry auto-centering on screen.

---

## 4. Current Repository Structure

```
smart_autopsy/
├── main.py                     # Primary entry point & initialization
├── requirements.txt            # Python dependencies (customtkinter, numpy, etc.)
├── smart_autopsy.log           # Application runtime logs
├── core/
│   ├── __init__.py             # Exports DriveScanner, FileCarver, CarvedFile
│   ├── scanner.py              # Module 1: Device discovery & raw byte streaming
│   └── carver.py               # Module 2: File carving engine & hashing
└── gui/
    ├── __init__.py             # Exports SmartAutopsyApp
    └── dashboard.py            # Module 3: CustomTkinter forensic dashboard
```

---

## 5. Setup & Operational Guide (Kali Linux / Ubuntu)

### 5.1 System Prerequisites
Install required Linux forensic utility packages:
```bash
sudo apt update && sudo apt install -y util-linux e2fsprogs lshw parted python3-venv python3-tk
```

### 5.2 Python Virtual Environment Setup
Because modern Kali Linux and Debian use PEP 668 externally managed environments, use a virtual environment:
```bash
cd ~/smart_autopsy
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 5.3 Running the Application

#### Mode A: Forensic Disk Images (.dd, .img, .raw) — No Root Required
```bash
source .venv/bin/activate
python3 main.py
```

#### Mode B: Physical Block Devices (/dev/sdb, /dev/sdc) — Root Required
Because physical block devices require `sudo`, but `sudo` resets the shell's environment and `PATH`, run using the virtual environment's Python binary:

```bash
# Recommended command:
sudo $(which python3) main.py

# Or via absolute path:
sudo /home/kali/smart_autopsy/.venv/bin/python3 main.py
```

> **X11 Display Permission Fix for Root GUI:**  
> If `sudo` causes `_tkinter.TclError: couldn't connect to display ":0"` or `No protocol specified`:
> ```bash
> xhost +si:localuser:root
> sudo -E $(which python3) main.py
> ```

---

## 6. Progress & Milestones Completed

| Milestone | Status | Details |
|---|:---:|---|
| **Module 1: Data Acquisition** | ✅ Complete | Block device discovery via `lsblk`, size calculation, 64 KiB raw sector streaming. |
| **Module 2: File Carver** | ✅ Complete | Sliding-window header/footer parsing, 8 file types, 50MB file cap, MD5/SHA-256 calculation. |
| **Forensic Safety Enforcement** | ✅ Complete | Target write-back prevention gate using `os.stat().st_dev`. |
| **GUI Dashboard Integration** | ✅ Complete | Dark theme CustomTkinter interface, real-time results table, async scan threading. |
| **Logging & Error Handling** | ✅ Complete | Dual-logging to console and `smart_autopsy.log`, non-root advisory warnings. |
| **Linux Environment Compatibility**| ✅ Complete | Resolved Kali PEP 668 virtual environment execution and `sudo` path resolution. |

---

## 7. Upcoming Roadmap

1. **Module 4: Advanced Deep Carving & Fragment Reassembly**:
   - Smart defragmentation heuristics for fragmented media.
   - Filesystem header parsing (reading partial MFT / Inode tables when present).
2. **Module 5: Shannon Entropy & Encryption Analysis**:
   - Graph entropy across drive sectors to visualize encrypted containers vs plain unallocated space.
3. **Module 6: Forensic Evidence Reporting**:
   - Generate automated PDF/HTML/JSON investigation reports with investigator notes, timestamps, case numbers, and cryptographic verification hashes for legal proceedings.
