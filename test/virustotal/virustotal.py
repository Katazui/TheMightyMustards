import requests
import serial
import time

# Set up communication with Arduino
arduino = serial.Serial('/dev/cu.usbmodemXXXX', 9600, timeout=1)

# VirusTotal API (you can replace this with any domain checking API)
API_KEY = '3c0482bf9d3af7edf8eed1f5d74f36abeeaa9b3027e364bd8b2f0fff020881ce'
API_URL = 'https://www.virustotal.com/vtapi/v2/url/report'

def check_domain(domain):
    params = {'apikey': API_KEY, 'resource': domain}
    response = requests.get(API_URL, params=params)
    result = response.json()
    
    # If the domain is blocked, send 'R' for red LED
    if result.get('positives', 0) > 0:
        print(f"{domain} is blocked!")
        arduino.write(b'R')
    else:
        # Send 'G' for green LED
        print(f"{domain} is clean.")
        arduino.write(b'G')

    time.sleep(1)  # Delay for readability

def read_domains_from_file(file_path):
    with open(file_path, 'r') as file:
        domains = file.readlines()
    return [domain.strip() for domain in domains]

def main():
    domain_file = 'blocked_domains.txt'
    domains = read_domains_from_file(domain_file)
    
    for domain in domains:
        check_domain(domain)

if __name__ == "__main__":
    main()