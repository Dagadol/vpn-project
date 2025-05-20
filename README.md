# README.md

````markdown
# VPN Project

A Python-based VPN simulation framework, designed for Windows only, with client and server components, a GUI, email-notification features, and advanced networking dependencies.

---

## 📋 Table of Contents

1. [Features](#features)  
2. [Prerequisites](#prerequisites)  
3. [Installation](#installation)  
4. [Configuration](#configuration)  
5. [Usage](#usage)  
6. [Project Structure](#project-structure)  
7. [Dependencies](#dependencies)  
8. [Contributing](#contributing)  
9. [License](#license)  

---

## 🚀 Features

- **VPN Simulation**: Scapy-based tunneling between `vpn_client.py` and `vpn_server.py`.
- **Password Exchange & Hashing**: Secure key exchange with SHA-based password hashing.
- **Atomic Send**: Ensures message packets are sent atomically.
- **HTML Email Notifications**: Composed and sent via SMTP using custom HTML templates.
- **Dynamic Country Logic**: Per-client country-based routing updates.
- **Threaded GUI**: `gui_master.py` provides a CustomTkinter interface for status and control.
- **Database Logging**: `db_communication.py` logs session data to SQLite.
- **WinPcap/Npcap Support**: Compatible with Npcap in WinPcap API mode for Windows packet capture.

---

## 🛠 Prerequisites

- Windows 10 or later (tested).
- Python 3.9+.
- Administrator privileges (to load and control virtual adapters).
- Npcap installed in WinPcap compatibility mode.
- Wireguard windows client is installed.

---

## 💾 Installation

1. **Clone the repo** (branch `finally`):
   ```bash
   git clone --branch finally https://github.com/Dagadol/vpn-project.git
   cd vpn-project
````

2. **Install Npcap**: Download and install Npcap from [https://nmap.org/npcap](https://nmap.org/npcap), selecting "WinPcap Compatible Mode".

3. **Create & activate a virtual environment**:

   ```powershell
   python -m venv venv
   venv\Scripts\activate      # PowerShell
   ```

4. **Install Python dependencies**:

   ```powershell
   pip install -r requirements.txt
   ```
5. **Install Wireguard windows client**: Download and install from https://download.wireguard.com/windows-client/.
---

## ⚙️ Configuration

1. **`adapter_conf.py`**
   Adjust your local interface mappings and VPN adapter names.

2. **Email Settings**
   In `db_communication.py`, set your SMTP host, port, sender credentials, and recipient list.

3. **Database**
   Logs are stored in `vpn_sessions.db` (SQLite). No extra setup required.

---

## ▶️ Usage

* **Start the server** (run PowerShell as Administrator):

  ```powershell
  python main_server.py
  ```
* **Run the client**:

  ```powershell
  python vpn_client.py
  ```
* **Launch the GUI**:

  ```powershell
  python gui_master.py
  ```
* **Run tests** (requires `pytest`):

  ```powershell
  pip install pytest
  pytest tests/
  ```

---

## 📁 Project Structure

```
vpn-project/
├── adapter_conf.py        # Interface & adapter mappings
├── connect_protocol.py    # Core VPN handshake logic
├── db_communication.py    # SQLite logging & retrieval
├── email_content.html     # HTML template for notifications
├── gui_master.py          # CustomTkinter GUI
├── main_server.py         # VPN server entry point
├── scapy_client.py        # Low-level packet funcs
├── scapy_server.py        # Server packet handling
├── vpn_client.py          # High-level client CLI
├── vpn_server.py          # High-level server CLI
├── tests/                 # Unit & integration tests
└── requirements.txt       # Python dependencies
```

---

## 🧩 Dependencies

All required Python packages are listed in `requirements.txt`.

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/foo`)
3. Commit your changes (`git commit -m 'Add foo'`)
4. Push to the branch (`git push origin feature/foo`)
5. Open a Pull Request


````

# requirements.txt
```text
scapy==2.5.0
customtkinter>=5.0.0
cryptography>=40.0.0
netifaces>=0.11.0
````
