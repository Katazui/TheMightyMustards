import tkinter as tk
from tkinter import ttk, messagebox
import random

# Variables to track packet counts and current packet state
packets_blocked = 0
packets_allowed = 0
current_packet = None
current_packet_is_malicious = False  # Flag to indicate if the current packet is malicious

# List of known malicious IP addresses for simulation
malicious_ips = [f"192.168.0.{random.randint(1, 255)}" for _ in range(5)]  # Simulated list of malicious IPs

# Function to handle commands and update the system status
def send_command(command):
    global packets_blocked, packets_allowed
    if command == 'BLOCK_IP\n':
        packets_blocked += 1
        if current_packet_is_malicious:
            response = "Correct: Malicious Packet Blocked!"
            messagebox.showinfo("Action Feedback", "Correct: You blocked a malicious packet!")
        else:
            response = "Incorrect: Safe Packet Blocked!"
            messagebox.showwarning("Action Feedback", "Incorrect: You blocked a safe packet!")
        simulate_traffic_data()  # Generate the next packet after blocking
    elif command == 'ALLOW_IP\n':
        packets_allowed += 1
        if current_packet_is_malicious:
            response = "Incorrect: Malicious Packet Allowed!"
            messagebox.showwarning("Action Feedback", "Incorrect: You allowed a malicious packet!")
        else:
            response = "Correct: Safe Packet Allowed!"
            messagebox.showinfo("Action Feedback", "Correct: You allowed a safe packet!")
        simulate_traffic_data()  # Generate the next packet after allowing
    status_label.config(text=f"System Status: {response}")
    update_packet_count()

# Function to update the packet count display
def update_packet_count():
    packet_count_label.config(text=f"Packets Blocked: {packets_blocked}\nPackets Allowed: {packets_allowed}")

# Function to update the traffic label with a single simulated packet
def update_traffic_label(packet):
    traffic_label.config(text=packet)

# Function to generate and display a single simulated traffic packet
def simulate_traffic_data():
    global current_packet, current_packet_is_malicious
    src_ip = f"192.168.0.{random.randint(1, 255)}"
    dst_ip = f"10.0.0.{random.randint(1, 255)}"
    protocol = random.choice(["TCP", "UDP", "ICMP"])
    current_packet_is_malicious = random.choice([True, False])

    # Generate packet with a flag for malicious packets
    packet_summary = f"Packet: {src_ip} -> {dst_ip} [Protocol: {protocol}]"
    if current_packet_is_malicious:
        packet_summary += " [Malicious]"
        src_ip = random.choice(malicious_ips)  # Assign a known malicious IP

    current_packet = packet_summary
    update_traffic_label(current_packet)

# Button functions
def block_ip():
    send_command('BLOCK_IP\n')

def allow_ip():
    send_command('ALLOW_IP\n')

def close_program():
    root.destroy()  # Close the program

# Setup the main application window
root = tk.Tk()
root.title("Simulated Network Traffic Dashboard")
root.geometry("800x700")

# Define styles for the dashboard
style = ttk.Style()
style.theme_use("clam")
style.configure("TButton", font=("Helvetica", 14), padding=20)
style.configure("TLabel", font=("Helvetica", 12), background="#f0f0f0")
style.configure("Header.TLabel", font=("Helvetica", 16, "bold"), background="#f0f0f0")

# Create a navigation bar frame at the top
navbar = tk.Frame(root, bg="#3e3e3e", height=50)
navbar.pack(fill="x")

# Navigation bar title
nav_label = tk.Label(navbar, text="Network Traffic Control Dashboard", fg="white", bg="#3e3e3e", font=("Helvetica", 16))
nav_label.pack(pady=10)

# Create a welcome section frame
welcome_frame = tk.LabelFrame(root, text="Welcome", font=("Helvetica", 14, "bold"), padx=20, pady=20, bg="#f0f0f0", fg="black")
welcome_frame.pack(fill="x", padx=20, pady=10)

# Welcome message
welcome_message = ttk.Label(welcome_frame, text="Welcome to the Network Traffic Control Dashboard.\n\n"
                                               "Use the Control Panel on the left to interact with the system.\n"
                                               "You can simulate network traffic, block or allow IP addresses, and monitor the system status.")
welcome_message.pack()

# Create main content frame
content = tk.Frame(root, bg="#f0f0f0", pady=20, padx=20)
content.pack(fill="both", expand=True)

# Create frames for different sections in the dashboard
control_frame = tk.LabelFrame(content, text="Control Panel", font=("Helvetica", 14, "bold"), padx=20, pady=20, bg="#f0f0f0", fg="black")
control_frame.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=10, pady=10)

status_frame = tk.LabelFrame(content, text="System Status", font=("Helvetica", 14, "bold"), padx=20, pady=20, bg="#f0f0f0", fg="black")
status_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

traffic_frame = tk.LabelFrame(content, text="Network Traffic", font=("Helvetica", 14, "bold"), padx=20, pady=20, bg="#f0f0f0", fg="black")
traffic_frame.grid(row=1, column=1, sticky="nsew", padx=10, pady=10)

# Add buttons to Control Panel frame
button_width = 20  # Set a uniform width for all buttons
simulate_traffic_button = ttk.Button(control_frame, text="Simulate Traffic", command=simulate_traffic_data, width=button_width)
simulate_traffic_button.grid(row=0, column=0, pady=20)

block_ip_button = ttk.Button(control_frame, text="Block IP", command=block_ip, width=button_width)
block_ip_button.grid(row=1, column=0, pady=10, padx=10)

allow_ip_button = ttk.Button(control_frame, text="Allow IP", command=allow_ip, width=button_width)
allow_ip_button.grid(row=2, column=0, pady=10, padx=10)

# Add a "Close Program" button to the control panel
close_button = ttk.Button(control_frame, text="Close Program", command=close_program, width=button_width)
close_button.grid(row=3, column=0, pady=20)

# Add status label in System Status frame
status_label = ttk.Label(status_frame, text="System Status: Waiting for Action", style="Header.TLabel")
status_label.pack(pady=20, padx=20)

# Add packet count label to show packets blocked or allowed
packet_count_label = ttk.Label(status_frame, text="Packets Blocked: 0\nPackets Allowed: 0", font=("Helvetica", 12))
packet_count_label.pack(pady=10)

# Add placeholders for network traffic data in the Network Traffic frame
traffic_label = ttk.Label(traffic_frame, text="Traffic Data:\n[Simulated data will appear here]", font=("Helvetica", 12))
traffic_label.pack(pady=20, padx=20)

# Adjust grid layout weights for responsive design
content.grid_rowconfigure(0, weight=1)
content.grid_rowconfigure(1, weight=1)
content.grid_columnconfigure(0, weight=1)
content.grid_columnconfigure(1, weight=1)

# Run the main application loop
root.mainloop()
