# SDN Firewall using RYU and OpenFlow

# Installation (macOS and Windows)

## Get the code

Put the project in **any folder** you want—for example clone the repo or unpack a zip into that folder.

Clone with Git:

```bash
cd my-folder-name
git clone https://github.com/aarondtrng/cmpe189.git
```

## Requirements

- **Python 3.10+**
- **pip** (included with Python from [python.org](https://www.python.org/downloads/))
- **Git** (to clone the repo)

---

## macOS

### 1. Python

If `python3 --version` is below 3.10, install Python from [python.org](https://www.python.org/downloads/) or Homebrew (`brew install python`).

### 2. Virtual environment and Ryu

```bash
cd /path/to/your-folder
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install ryu
```

### 3. Check install

```bash
ryu-manager --version
```

---

## Windows

### 1. Python

Install **Python 3.10+** from [Windows downloads](https://www.python.org/downloads/windows/) with **Add python.exe to PATH** enabled.

Check:

```cmd
py -3 --version
```

### 2. Virtual environment and Ryu

```cmd
cd C:\path\to\your-folder
py -3 -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install ryu
```

### 3. Check install

```cmd
ryu-manager --version
python manage_firewall.py --help
```

Activate the environment each session:

```cmd
.venv\Scripts\activate
```

---

## OpenFlow (switch / emulator) installation

Ryu is the controller. To actually speak **OpenFlow**, you also need an OpenFlow-capable switch/emulator such as **Open vSwitch (OVS)** (and optionally **Mininet**).

### Recommended (Windows + macOS): WSL2 / Linux

Install Ubuntu (WSL2 on Windows, or a Linux VM), then:

```bash
sudo apt update
sudo apt install -y openvswitch-switch
```

Optional (for quick network topologies):

```bash
sudo apt install -y mininet
```

### macOS note

OVS/Mininet are primarily maintained for Linux. If you need a full OpenFlow lab environment on macOS, the most reliable approach is a Linux VM (or remote Linux host) running OVS/Mininet, with Ryu running either on that VM or on your machine.

---

## Running Ryu firewall (all platforms)

1. Activate your virtual environment.
2. Open a terminal in this repo folder.
3. Start Ryu with `rest_firewall.py` first.

Run everything:

```bash
ryu-manager rest_firewall.py port_blocker.py allow_rules.py flood_detector.py
```

Check current firewall rules:

```bash
python manage_firewall.py list
```

>>>>>>> e8725db (add installation)
