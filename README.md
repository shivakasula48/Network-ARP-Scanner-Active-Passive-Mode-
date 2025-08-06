# Network-ARP-Scanner-Active-Passive-Mode-

# 🔍 Network ARP Scanner (Active & Passive Mode)

A powerful Python-based ARP Network Scanner that can actively and passively detect live hosts in a network. Supports multi-threaded scanning, batch IP processing, progress visualization, logging, and exports results in CSV/JSON formats. Ideal for cybersecurity professionals and network administrators.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Security](https://img.shields.io/badge/Use-Ethical-red)

---

## 🚀 Features

- 🔧 **Active ARP Scanning** with batching and threading for efficiency  
- 🕵️ **Passive Sniffing Mode** for stealthy host detection  
- 📊 **Progress Bars** for scanning status visualization  
- 🌈 **Color-coded CLI Output** for better readability  
- 🖥️ **Tabulated Output** in CLI for clean results  
- 🗃️ **Export Results** to CSV and/or JSON formats  
- 📝 **Logging System** to console and optional log files  
- ⚡ **Customizable Batch Size & Thread Count**  
- 📡 **CIDR Input Validation** and Interactive Prompts  
- 🐍 **Written in Python 3 using Scapy, TQDM, Colorama, Tabulate**  

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/shivakasula48/network-arp-scanner.git
cd network-arp-scanner
```

### 2. Install required dependencies

```bash
pip install -r requirements.txt
```

> `requirements.txt` contents:

```
scapy
tqdm
tabulate
colorama
```

---

## 🛠️ Usage

### ⚡ Active Mode (Standard Network Scan)

```bash
python scanner.py -n 192.168.1.0/24
```

### 🕵️ Passive Mode (Listen for ARP traffic for 60 seconds)

```bash
python scanner.py -m passive -p 60
```

### ⚙️ Custom Timeout, Threads, Batch Size, Verbose Debugging

```bash
python scanner.py -n 192.168.1.0/24 -t 2 -w 50 -b 20 --verbose
```

### 💾 Export to JSON Only

```bash
python scanner.py -n 192.168.1.0/24 -o json
```

### 📝 Log Output to a File

```bash
python scanner.py -n 192.168.1.0/24 --logfile scan_log.txt
```

---

## 📂 Example Outputs

### 📋 CLI Table Example

```
+---------------+-------------------+----------------------------+
| IP Address    | MAC Address       | Hostname                   |
+===============+===================+============================+
| 192.168.1.10  | e2:43:f8:57:fd:9c | DESKTOP-3GGCM0U.local      |
| 192.168.1.12  | 78:4f:43:b5:11:7a | android-93ba1f5.local      |
+---------------+-------------------+----------------------------+
```

### 📁 CSV Export Example

```
IP,MAC,Hostname
192.168.1.10,e2:43:f8:57:fd:9c,DESKTOP-3GGCM0U.local
192.168.1.12,78:4f:43:b5:11:7a,android-93ba1f5.local
```

---

## 📜 License

This project is licensed under the **MIT License**.  
You are free to use, modify, and distribute with proper credit.

---

## 👨‍💻 Author

**Kasula Shiva**  
🎓 B.Tech CSE (Cybersecurity)  
🔗 GitHub: [shivakasula48](https://github.com/shivakasula48)  
📧 Email: [shivakasula10@gmail.com](mailto:shivakasula10@gmail.com)

---

## 🙌 Contributing

Contributions are welcome!

1. Fork this repo  
2. Create a new branch  
3. Make your changes  
4. Submit a pull request  

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes** and **authorized internal network auditing** only.  
**Unauthorized scanning of networks is illegal.**  
The author is **not responsible for any misuse** of this software.

---

## ⭐ Support the Project

If you found this project helpful, please consider giving it a ⭐ on GitHub to show your support!
