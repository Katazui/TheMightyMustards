import tkinter as tk
from tkinter import ttk
import requests
import time
import threading
from scapy.all import sniff, DNS, DNSQR

# Configuration
DEBUG = True  # Enable debug mode
SLEEP_TIME = 5  # Time to wait between each domain check

# Do not change these values
PACKETS_BLOCKED = 0
PACKETS_ALLOWED = 0

# Set up communication with Arduino
# arduino = serial.Serial('/dev/cu.usbmodemXXXX', 9600, timeout=1)

# VirusTotal API Configuration
API_KEY = '3c0482bf9d3af7edf8eed1f5d74f36abeeaa9b3027e364bd8b2f0fff020881ce'
API_URL = 'https://www.virustotal.com/vtapi/v2/url/report'

# Color Codes
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[31m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_BLUE = "\033[34m"
COLOR_PURPLE = "\033[35m"
COLOR_CYAN = "\033[36m"
COLOR_GREY = "\033[37m"

# Message Prefixes
MSG_ERROR = f"{COLOR_RED}[Error]{COLOR_RESET}: "
MSG_NOTICE = f"{COLOR_YELLOW}[Notice]{COLOR_RESET}: "
MSG_DEBUG = f"{COLOR_CYAN}[Debug]{COLOR_RESET}: "
MSG_SUCCESS = f"{COLOR_GREEN}[Success]{COLOR_RESET}: "
MSG_STATUS = f"{COLOR_GREEN}[Status]{COLOR_RESET}: "
MSG_WARNING = f"{COLOR_BLUE}[Warning]{COLOR_RESET}: "
LINE_BREAK = f"{COLOR_GREY}----------------------------------------{COLOR_RESET}"

# Check a domain against VirusTotal API
def check_domain(domain):
    global arduino
    params = {'apikey': API_KEY, 'resource': domain}
    print(f"{MSG_NOTICE}Checking domain: {domain}")  # Debug statement
    response = requests.get(API_URL, params=params)
    
    if DEBUG == True: 
        print(f"{MSG_DEBUG}Response Code: {response.status_code}")  # Debug statement
    if response.status_code == 200:
        try:
            result = response.json()
            if result.get('positives', 0) > 0:
                print(f"{MSG_ERROR}{domain} is blocked!")
                send_command('BLOCK_IP\n', domain)
                # arduino.write(b'G')
                return True
            else:
                print(f"{MSG_SUCCESS}{domain} is clean.")
                send_command('ALLOW_IP\n', domain)
                # arduino.write(b'R')
                return False
        except ValueError:
            print("Error parsing JSON response from VirusTotal.")
            print("Response Content:", response.text)  # Debug statement
            return False
    else:
        print(f"{MSG_ERROR}Error querying VirusTotal for {domain}: {response.status_code}")
        if response.text:
            if DEBUG == True: 
                print(f"{MSG_DEBUG}Response Content:", response.text)
        # arduino.write(b'Y')
        return False

# Check if a domain supports HTTP/HTTPS
def check_http_https(domain):
    http_url = f"http://{domain}"
    https_url = f"https://{domain}"
    
    try:
        # Check HTTP
        http_response = requests.get(http_url, timeout=5)
        http_available = http_response.status_code < 400  # HTTP status code check
        # print(f"{domain} - HTTP Available: {http_available}")
    except requests.RequestException as e:
        # print(f"HTTP check failed for {domain}: {e}")
        http_available = False

    try:
        # Check HTTPS
        https_response = requests.get(https_url, timeout=5)
        https_available = https_response.status_code < 400  # HTTP status code check
        # print(f"{domain} - HTTPS Available: {https_available}")
    except requests.RequestException as e:
        # print(f"HTTPS check failed for {domain}: {e}")
        https_available = False
        
    if DEBUG == True: 
        print(f"{MSG_DEBUG}HTTP Available: {http_available}, HTTPS Available: {https_available}")
    return http_available, https_available

# Parse packets for DNS requests
def packet_handler(packet):
    # Check if the packet has a DNS layer
    if packet.haslayer('DNS'):
        dns_layer = packet.getlayer('DNS')
        if dns_layer.qd:
            # Extract the queried domain from the DNS request
            queried_domain = dns_layer.qd.qname.decode()
            print(f"{MSG_NOTICE}Incoming domain: {queried_domain}")
            check_domain(queried_domain)

            # Debug: Check if the website supports HTTP/HTTPS
            check_http_https(queried_domain)

            # Delay before the next packet
            time.sleep(SLEEP_TIME)

# Start Sniffing Command
def start_sniffing():
    # Start sniffing packets in threads
    status_label.config(text=f"System Status: Sniffing Packets...")
    def sniff_packets():
        print(f"{MSG_STATUS}Starting packet sniffing...")
        sniff(prn=packet_handler, store=False, filter="udp port 53")
    
    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.daemon = True  # This ensures the thread will close when the main program exits
    sniff_thread.start()

# Function to handle commands and update the system status
def send_command(command, domain):
    global PACKETS_BLOCKED, PACKETS_ALLOWED
    if command == 'BLOCK_IP\n':
        PACKETS_BLOCKED += 1
        update_traffic_label(f"Blocked Domain: {domain}")
    elif command == 'ALLOW_IP\n':
        PACKETS_ALLOWED += 1
        update_traffic_label(f"Allowed Domain: {domain}")
    update_packet_count()

# Function to update the packet count display
def update_packet_count():
    packet_count_label.config(text=f"Packets Blocked: {PACKETS_BLOCKED}\nPackets Allowed: {PACKETS_ALLOWED}")

# Function to update the traffic label with a single simulated packet
def update_traffic_label(packet):
    traffic_label.config(text=packet)

# Button functions
def close_program():
    root.destroy()  # Close the program

# GUI Setup
root = tk.Tk()
root.title("The Mighty Mustard")
root.geometry("800x600")

# GUI Style
style = ttk.Style()
style.theme_use("clam")
style.configure("TButton", font=("Helvetica", 14), padding=20)
style.configure("TLabel", font=("Helvetica", 12), background="#f0f0f0")
style.configure("Header.TLabel", font=("Helvetica", 16, "bold"), background="#f0f0f0")

# Create a navigation bar frame at the top
navbar = tk.Frame(root, bg="#3e3e3e", height=50)
navbar.pack(fill="x")

# Navigation Bar
nav_label = tk.Label(navbar, text="Malicous Network Detection Dashboard", fg="white", bg="#3e3e3e", font=("Helvetica", 16))
nav_label.pack(pady=10)

# Welcome Section
welcome_frame = tk.LabelFrame(root, text="The Mighty Mustard", font=("Helvetica", 14, "bold"), padx=20, pady=20, bg="#f0f0f0", fg="black")
welcome_frame.pack(fill="x", padx=20, pady=10)

# Welcome message
welcome_message = ttk.Label(welcome_frame, text="Welcome to the Malicous Network Detection.\n\n"
                                               "Use the Control Panel on the left to start sniffing internet traffic.\n"
                                               "The system will monitor every traffic request against VirusTotal to check if the request was malicous.")
welcome_message.pack()

# Main Frame
content = tk.Frame(root, bg="#f0f0f0", pady=20, padx=20)
content.pack(fill="both", expand=True)

# Frames for Control Panel, System Status, and Network Traffic
control_frame = tk.LabelFrame(content, text="Control Panel", font=("Helvetica", 14, "bold"), padx=20, pady=20, bg="#f0f0f0", fg="black")
control_frame.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=10, pady=10)

status_frame = tk.LabelFrame(content, text="System Status", font=("Helvetica", 14, "bold"), padx=20, pady=20, bg="#f0f0f0", fg="black")
status_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

traffic_frame = tk.LabelFrame(content, text="Network Traffic", font=("Helvetica", 14, "bold"), padx=20, pady=20, bg="#f0f0f0", fg="black")
traffic_frame.grid(row=1, column=1, sticky="nsew", padx=10, pady=10)

# Buttons
button_width = 20

block_ip_button = ttk.Button(control_frame, text="Start Sniffing", command=start_sniffing, width=button_width)
block_ip_button.grid(row=1, column=0, pady=10, padx=10)

allow_ip_button = ttk.Button(control_frame, text="Close Program", command=close_program, width=button_width)
allow_ip_button.grid(row=2, column=0, pady=10, padx=10)

# Status Labels
status_label = ttk.Label(status_frame, text="System Status: Waiting for Action", style="Header.TLabel")
status_label.pack(pady=20, padx=20)

# Packet Labels
packet_count_label = ttk.Label(status_frame, text="Packets Blocked: 0\nPackets Allowed: 0", font=("Helvetica", 12))
packet_count_label.pack(pady=10)

# Traffic  label
traffic_label = ttk.Label(traffic_frame, text="Traffic Data:\n[DNS traffic will appear here]", font=("Helvetica", 12))
traffic_label.pack(pady=20, padx=20)

# Grid Configuration
content.grid_rowconfigure(0, weight=1)
content.grid_rowconfigure(1, weight=1)
content.grid_columnconfigure(0, weight=1)
content.grid_columnconfigure(1, weight=1)

def main():
    # Run GUI
    root.mainloop()

if __name__ == "__main__":
    main()