import serial
import time

# Replace 'COM3' with your Arduino's serial port
ser = serial.Serial('COM3', 9600, timeout=1)
time.sleep(2)  # Wait for the connection to initialize

ser.write(b'Hello Arduino\n')
while True:
    line = ser.readline().decode('utf-8').rstrip()
    if line:
        print(f"Received from Arduino: {line}")