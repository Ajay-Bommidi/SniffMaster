import os
import sys
import time
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, DNS, Raw, wrpcap
from datetime import datetime
from collections import Counter
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.live import Live
import threading
import psutil

class AdvancedPacketSnifferCLI:
    def __init__(self):
        self.console = Console()
        self.packet_data = []
        self.protocol_counter = Counter()
        self.tcp_count = 0
        self.udp_count = 0
        self.running = False
        self.interface = None
        self.packet_count = 0
        self.capture_file = None
        self.packet_lock = threading.Lock()
        self.packet_log_file = "packets_log.txt"  # Log file to store packet summaries

    def get_interfaces(self):
        """Retrieve available network interfaces"""
        try:
            interfaces = psutil.net_if_addrs().keys()
            return list(interfaces)
        except Exception as e:
            self.console.print(f"[red]Error retrieving interfaces: {e}", style="bold red")
            sys.exit(1)

    def display_interfaces(self):
        """Display network interfaces for selection"""
        interfaces = self.get_interfaces()
        if not interfaces:
            self.console.print("[red]No network interfaces found.", style="bold red")
            sys.exit(1)

        self.console.print("[cyan]Available Interfaces:[/cyan]", style="bold cyan")
        for idx, iface in enumerate(interfaces, 1):
            self.console.print(f"[green]{idx}. {iface}[/green]")

        while True:
            try:
                choice = int(input("Select an interface (number): ")) - 1
                if 0 <= choice < len(interfaces):
                    self.interface = interfaces[choice]
                    break
                else:
                    self.console.print("[red]Invalid choice. Try again.[/red]", style="bold red")
            except ValueError:
                self.console.print("[red]Invalid input. Enter a number.[/red]", style="bold red")

    def packet_to_json(self, packet):
        """Convert packet to a dictionary"""
        packet_info = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "src": packet[IP].src if IP in packet else (packet[Ether].src if Ether in packet else "Unknown"),
            "dst": packet[IP].dst if IP in packet else (packet[Ether].dst if Ether in packet else "Unknown"),
            "protocol": "Other",
            "port": "N/A",
            "size": len(packet)
        }
        if TCP in packet:
            packet_info["protocol"] = "TCP"
            packet_info["port"] = packet[TCP].dport
        elif UDP in packet:
            packet_info["protocol"] = "UDP"
            packet_info["port"] = packet[UDP].dport
        elif ICMP in packet:
            packet_info["protocol"] = "ICMP"
        elif ARP in packet:
            packet_info["protocol"] = "ARP"
        elif DNS in packet:
            packet_info["protocol"] = "DNS"
        if Raw in packet:
            packet_info["payload"] = packet[Raw].load.decode(errors="ignore")
        return packet_info

    def process_packet(self, packet):
        """Process and add packet information to the data"""
        packet_info = self.packet_to_json(packet)
        with self.packet_lock:
            self.packet_data.append(packet_info)
            self.protocol_counter[packet_info["protocol"]] += 1
            self.packet_count += 1

            if packet_info["protocol"] == "TCP":
                self.tcp_count += 1
            elif packet_info["protocol"] == "UDP":
                self.udp_count += 1

        # Log packet summary to file
        self.log_packet_to_file(packet_info)

        # Export packet to pcap if a capture file is specified
        if self.capture_file:
            wrpcap(self.capture_file, packet, append=True)

    def log_packet_to_file(self, packet_info):
        """Log packet summary to the log file"""
        try:
            with open(self.packet_log_file, "a") as log_file:
                log_file.write(f"{packet_info['timestamp']} {packet_info['src']} -> {packet_info['dst']} {packet_info['protocol']} Port: {packet_info['port']} Size: {packet_info['size']} bytes\n")
        except Exception as e:
            self.console.print(f"[red]Error logging packet: {e}", style="bold red")

    def start_sniffing(self):
        """Start packet sniffing"""
        self.console.print(f"[bold green]Starting packet sniffing on interface: {self.interface}[/bold green]")
        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=False,
                filter="ip or arp or icmp or udp or tcp"
            )
        except PermissionError:
            self.console.print("[red]Permission denied. Run the script as administrator/root.[/red]", style="bold red")
            sys.exit(1)
        except Exception as e:
            self.console.print(f"[red]Error while sniffing packets: {e}", style="bold red")
            sys.exit(1)

    def display_packet_logs(self):
        """Display packet summary logs in real-time"""
        with Live(auto_refresh=True, console=self.console) as live:
            while self.running:
                time.sleep(0.5)  # Update logs every half a second
                log_output = Text()

                with self.packet_lock:
                    for packet in self.packet_data[-20:]:  # Display the last 20 packets
                        log_output.append(f"{packet['timestamp']} {packet['src']} -> {packet['dst']} "
                                          f"{packet['protocol']} Port: {packet['port']} "
                                          f"Size: {packet['size']} bytes\n")
                        log_output.append("-------------------------------\n")

                # Update the live display with the latest logs
                live.update(log_output)

    def display_statistics(self):
        """Display real-time statistics (packets per second, top talkers, etc.)"""
        last_packet_count = 0
        while self.running:
            time.sleep(5)
            with self.packet_lock:
                packet_diff = self.packet_count - last_packet_count
                statistics = Text()
                statistics.append(f"Total packets: {self.packet_count}  |  ")
                statistics.append(f"Packets/sec: {packet_diff}  |  ")
                statistics.append(f"TCP: {self.tcp_count}  |  ")
                statistics.append(f"UDP: {self.udp_count}  |  ")
                statistics.append(f"Other: {self.packet_count - self.tcp_count - self.udp_count}")
            
            

            # Update the statistics on the terminal without cluttering
            self.console.clear()
            self.console.print(statistics, justify="center")
            last_packet_count = self.packet_count

    def stop_sniffing(self):
        self.running = False
        self.console.print("Stopping packet capture...")

    def auto_save_packets(self):
        """Automatically create a file name and save packets to it"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.capture_file = f"packet_capture_{timestamp}.pcap"
        self.console.print(f"[green]Packets will be saved to {self.capture_file}[/green]")

    def run(self):
        self.console.print(Panel(Text("Welcome to the Advanced Packet Sniffer CLI", justify="center", style="bold green"), expand=False))
        self.display_interfaces()
        self.auto_save_packets()  # Automatically set up file saving
        self.running = True

        # Start the live log display and statistics updates in the background
        threading.Thread(target=self.display_packet_logs, daemon=True).start()
        threading.Thread(target=self.display_statistics, daemon=True).start()

        try:
            self.start_sniffing()
        except KeyboardInterrupt:
            self.stop_sniffing()
            self.console.print("[bold blue]Packet sniffing terminated. Here are your statistics:[/bold blue]")
            self.display_statistics()
        finally:
            self.console.print("[bold blue]Packet sniffing terminated. Goodbye![/bold blue]")

if __name__ == "__main__":
    AdvancedPacketSnifferCLI().run()