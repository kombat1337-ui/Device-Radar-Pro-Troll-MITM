# Device-Radar-Pro-Troll-MITM
Disclaimer: Use responsibly on networks you own or have permission to test. Unauthorized spoofing or injection is illegal.Evrth had been done in education view and nth iilegal been tested.

# 🔥 Device Pro + Troll + MITM 🔥

A full-featured network reconnaissance and manipulation toolkit with:
- **ARP scanner** with interface selection & fallback  
- **ARP spoofing** (Start/Stop)  
- **ICMP ping & TCP/UDP port scan**  
- **Real-time network map** (via NetworkX + Matplotlib)  
- **MITM-style HTML injection** (using `mitmdump`)  
- **UDP “trolling”** messages to discovered hosts  
- **Configurable scan interval, custom injection, logging**  
- **Cross-platform**: Windows & Unix (Mac/Linux)

---

## ⚙️ Features

1. **Dynamic interface selector** (filters out virtual/WFP adapters)  
2. **Automatic subnet detection** & manual override  
3. **Threaded ARP scan** with fallback to system default interface  
4. **Deep host info** via optional Nmap OS detection & service scan  
5. **Live device list** with latency, ports, vendor, OS, services  
6. **Interactive network graph** (if `networkx` installed)  
7. **ARP spoofing** against any selected host  
8. **Custom command injector** (send UDP/TCP payloads)  
9. **UDP troll messages** on multiple ports with success/fail report  
10. **MITM proxy** via external `mitmdump` and user-defined HTML injection  
11. **GUI logging**, copy-to-clipboard, full-screen toggle  
12. **Config file** (`config.json`) for ports, colors, intervals, injection

---

## 🚀 Installation

1. **Clone the repo**
Create a virtualenv & install dependencies
python -m venv venv
source venv/bin/activate       # Linux/macOS
venv\Scripts\activate          # Windows
pip install --upgrade pip
pip install -r requirements.txt

Required system tools
Windows: run as Administrator, install WinPcap/Npcap
Unix (Linux/macOS): run with sudo, ensure libpcap
MITM proxy: install mitmproxy (pip install mitmproxy)
(Optional) Nmap (nmap CLI) & Python python-nmap
(Optional) NetworkX & Matplotlib



USAGE 
Interface: select your network adapter
Subnet: default auto-detect, override if needed
Rescan: manual ARP discovery
Devices tab: view live hosts, select one
Start/Stop Spoof
Send Cmd: inject custom UDP/TCP payloads
Troll: send a “You have been spotted” message to open UDP ports
Network Map tab: visual graph of gateway ↔ devices
MITM Proxy
Start MITM Proxy: launches mitmdump -p 8080 with your injection script
Inj HTML: edit the HTML snippet to inject
Apply: regenerate script for next proxy run
Press F11 for full-screen toggle.

IMPORTANT 

This project was made only for educational purposes, in real conditions the programme was not tested and everything was tested on its own network. In case of violation of the law the creator does not bear any responsibility for the violations of users - it is not legal to intrude into other people's Internet traffic, and this project was made for the purpose of studying the vulnerabilities of Internet traffic.
