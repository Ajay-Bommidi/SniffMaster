# 🛡️ SniffMaster - Advanced Real-Time Packet Sniffer CLI Tool

#### SniffMaster is a powerful and user-friendly command-line packet sniffing tool designed for network analysis, diagnostics, and real-time traffic monitoring. It captures, analyzes, and categorizes packets by protocol (TCP, UDP, ARP, ICMP, DNS), providing instant insights and live statistics.

![image (5)](https://github.com/user-attachments/assets/ebf8b994-1000-4c20-90a5-ecc9519d83fb)

#### Ideal for Cybersecurity Professionals, Network Engineers, CTFs, and learners who want to dig deeper into the packet-level details of network communication.

![image](https://github.com/user-attachments/assets/25abd5c6-7ad5-43f1-8510-6b55a1eebe77)

🚀 Features
#### ✅ Live Packet Capture with color-coded terminal output
#### ✅ Real-Time Statistics for TCP, UDP, ARP, ICMP, DNS
#### ✅ Packets Per Second (PPS) & Total Packet Counter
#### ✅ .pcap Export: Save captures for Wireshark analysis
#### ✅ Logging Support: Save packet logs to a file
#### ✅ Customizable CLI Interface for better user control
#### ✅ Lightweight & Easy to Use – Built with Scapy & Python

## 🧠 Use Cases
##### 🛡️ Penetration Testing & Traffic Analysis

##### 🧪 CTF (Capture The Flag) challenges

##### 🧰 Debugging Network Applications

##### 📊 Educational Tool for learning protocol structures

## 📦 Installation
Clone the repository and install required dependencies:

```bash
git clone https://github.com/Ajay-Bommidi/SniffMaster.git
cd SniffMaster
sudo python3 -m venv myenv
source myenv/bin/activate
sudo chown -R $USER:$USER ~/SniffMaster/myenv
pip install -r requirements.txt
sudo python sniffer.py
```
## 📌 Requirements
Python 3.6+

Root privileges (to access raw packets)

Dependencies listed in requirements.txt
(Includes scapy, colorama, etc.)

## 🖥️ Sample Output

### [+] Sniffing started on interface: eth0
### [TCP] Packet captured from 192.168.0.10 to 93.184.216.34
### [UDP] DNS Query to 8.8.8.8
### [ARP] Who has 192.168.0.1? Tell 192.168.0.100
...
### Stats: TCP: 23 | UDP: 14 | ICMP: 3 | ARP: 2 | DNS: 10 | PPS: 20

## 🧰 How to Use

Option	Description
Ctrl + C	Stop packet capture gracefully
.pcap file	Automatically created/exported
log.txt	Stores all detailed packet info

## 🛠️ Upcoming Improvements
#### GUI version using Tkinter or PyQT

#### Protocol filter flags (--tcp, --dns, etc.)

#### Alert system for suspicious packets

#### JSON export for external parsing tools

## 🤝 Contributing
#### We welcome contributions from the community!

#### Fork the repo

#### Create your feature branch (git checkout -b feature/foo)

#### Commit your changes (git commit -am 'Add foo feature')

#### Push to the branch (git push origin feature/foo)

#### Open a Pull Request

## 📄 License
MIT License - Feel free to use and modify under open-source terms.

## 🙋‍♂️ Author
# Ajay Bommidi


