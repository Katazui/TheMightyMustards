import requests
import serial
import time
import os
from scapy.all import sniff, DNS, DNSQR

# Configuration
DEBUG = True  # Enable debug mode
SLEEP_TIME = 5  # Time to wait between each domain check

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

def check_domain(domain):
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
                arduino.write(b'G')
                return True
            else:
                print(f"{MSG_SUCCESS}{domain} is clean.")
                arduino.write(b'R')
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
        arduino.write(b'Y')
        return False

def read_domains_from_file(file_path):
    with open(file_path, 'r') as file:
        domains = file.readlines()
    return [domain.strip() for domain in domains]

def packet_handler(packet):
    # Check if the packet has a DNS layer
    if packet.haslayer('DNS'):
        dns_layer = packet.getlayer('DNS')
        if dns_layer.qd:
            # Extract the queried domain from the DNS request
            queried_domain = dns_layer.qd.qname.decode()
            print(f"{MSG_NOTICE}Incoming domain: {queried_domain}")
            check_domain(queried_domain)

            # Check if the website supports HTTP/HTTPS
            check_http_https(queried_domain)

            # Delay before the next packet
            time.sleep(SLEEP_TIME)


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

def main():
    domain_file = 'blocked_domains.txt'
    domains = read_domains_from_file(domain_file)
    
    # # Check Domains against list of blocked domains
    # for domain in domains:
    #     check_domain(domain)

    # Start sniffing for DNS packets in a separate thread
    print(f"{MSG_NOTICE}Starting packet sniffing...")
    sniff(filter="udp port 53", prn=packet_handler, store=0)  # Sniff DNS traffic


if __name__ == "__main__":
    main()