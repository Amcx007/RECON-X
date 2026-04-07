# R3C0N-X — Automated Port Reconnaissance Framework

> A Flask-based automated reconnaissance and port scanning tool with a hacker-themed terminal UI. Built as an internship project demonstrating tool integration, security workflows, and web application development.

---

## Features

- Multi-engine scanning — Nmap, Rustscan, and Masscan integrated into a single interface
- Four scan profiles — Fast, Full, Service, and Aggressive (tool-dependent)
- Automatic port risk classification with severity ratings (Critical / High / Medium / Low)
- Per-tool scan type validation enforced on both frontend and backend
- Dynamic scan profile dropdown — Rustscan and Masscan only show supported modes
- Persistent scan history saved across sessions
- JSON export for each scan result
- Hacker-themed terminal UI with matrix rain, glitch effects, and scanline overlay
- Loading state on scan button with tool-specific status messages
- bfcache fix — back button correctly resets loading state

---

## Tools Used

| Tool | Purpose |
|------|---------|
| **Nmap** | Deep scanning — service detection, OS fingerprinting, scripts |
| **Rustscan** | Ultra-fast port discovery, hands off to Nmap for version detection |
| **Masscan** | High-speed raw packet scanning across large port ranges |

---

## Prerequisites

Install the scanning tools on Kali Linux:

```bash
# Nmap (usually pre-installed on Kali)
sudo apt install nmap

# Masscan
sudo apt install masscan

# Rustscan (via Cargo)
curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env
cargo install rustscan
```

---

## Installation

**1. Clone the repository**

```bash
git clone https://github.com/YOUR_USERNAME/recon-x.git
cd recon-x
```

**2. Create and activate a virtual environment**

```bash
python3 -m venv venv
source venv/bin/activate
```

**3. Install Python dependencies**

```bash
pip install -r requirements.txt
```

**4. Run the application**

```bash
python3 app.py
```

**5. Open in browser**

```
http://127.0.0.1:5000
```

---

## Project Structure

```
recon-x/
├── app.py               # Flask application — routes, parsers, scan logic
├── requirements.txt     # Python dependencies
├── .gitignore           # Files excluded from version control
├── README.md            # This file
└── templates/
    ├── index.html       # Landing page — scan form
    └── results.html     # Results page — port table, raw output, history
```

---

## Scan Profiles

| Profile | Nmap | Rustscan | Masscan |
|---------|------|----------|---------|
| **Fast** | Top 100 ports | Top 1024 ports | 20 critical ports at 5000 pps |
| **Full** | All 65535 ports | All 65535 + version detect | All 65535 ports at 1000 pps |
| **Service** | Top 1000 ports + version detection | — | — |
| **Aggressive** | OS + version + scripts + traceroute | — | — |

---

## Usage Notes

- Only scan systems you own or have **explicit written permission** to test
- Masscan requires a raw IP address — hostnames are automatically resolved
- Rustscan is installed via Cargo at `~/.cargo/bin/rustscan` — the app detects this automatically
- Scan results are saved as JSON files in the `results/` directory (excluded from Git)
- Scan history persists in `history.json` (excluded from Git)

---

## Security Notes

- All user inputs are validated and whitelisted before being passed to CLI tools
- Tool and scan type values are checked against strict allowlists
- Download route validates UUIDs to prevent path traversal
- Run with `debug=False` in production (already set)

---

## Tech Stack

- **Backend** — Python 3, Flask
- **Scanning** — Nmap, Rustscan, Masscan
- **Frontend** — Vanilla HTML/CSS/JS with Google Fonts (Orbitron, Share Tech Mono, VT323)
- **Storage** — JSON files (no database required)

---

## Disclaimer

This tool is built for **educational purposes and authorized security testing only**. Unauthorized scanning of networks or systems is illegal. The author is not responsible for any misuse.

---

*Built as an internship automation project — R3C0N-X v2.0*
"# RECON-X" 
