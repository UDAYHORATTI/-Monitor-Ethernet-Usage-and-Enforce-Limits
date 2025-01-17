# -Monitor-Ethernet-Usage-and-Enforce-Limits
This script uses scapy to capture Ethernet packets and tracks data usage for devices based on their MAC addresses.
from scapy.all import sniff
import subprocess
import time
import threading

# Configuration
USAGE_LIMIT_MB = 500  # Limit in MB
CHECK_INTERVAL = 60  # Check interval in seconds
DEVICES = {
    "00:1A:2B:3C:4D:5E": {"name": "Device1", "usage": 0, "blocked": False},
    "00:1A:2B:3C:4D:6F": {"name": "Device2", "usage": 0, "blocked": False},
}

# Function to block a MAC address
def block_mac(mac_address):
    if not DEVICES[mac_address]["blocked"]:
        try:
            subprocess.run(
                ["iptables", "-A", "FORWARD", "-m", "mac", "--mac-source", mac_address, "-j", "DROP"],
                check=True
            )
            DEVICES[mac_address]["blocked"] = True
            print(f"Blocked MAC: {mac_address}")
        except subprocess.CalledProcessError as e:
            print(f"Error blocking MAC {mac_address}: {e}")

# Function to unblock a MAC address
def unblock_mac(mac_address):
    if DEVICES[mac_address]["blocked"]:
        try:
            subprocess.run(
                ["iptables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac_address, "-j", "DROP"],
                check=True
            )
            DEVICES[mac_address]["blocked"] = False
            DEVICES[mac_address]["usage"] = 0
            print(f"Unblocked MAC: {mac_address}")
        except subprocess.CalledProcessError as e:
            print(f"Error unblocking MAC {mac_address}: {e}")

# Packet handler to track usage
def packet_handler(packet):
    if packet.haslayer("Ethernet"):
        src_mac = packet.src
        if src_mac in DEVICES:
            packet_size = len(packet)
            DEVICES[src_mac]["usage"] += packet_size
            print(f"MAC: {src_mac}, Usage: {DEVICES[src_mac]['usage'] / (1024 * 1024):.2f} MB")

# Function to enforce limits
def enforce_limits():
    while True:
        time.sleep(CHECK_INTERVAL)
        for mac, data in DEVICES.items():
            usage_mb = data["usage"] / (1024 * 1024)  # Convert bytes to MB
            if usage_mb > USAGE_LIMIT_MB and not data["blocked"]:
                block_mac(mac)

# Main function
def main():
    print("Starting Ethernet monitoring...")
    sniff(filter="ether", prn=packet_handler, store=0)

# Start the Ethernet monitoring and limit enforcement in parallel
if __name__ == "__main__":
    monitor_thread = threading.Thread(target=main, daemon=True)
    monitor_thread.start()

    enforce_limits()
