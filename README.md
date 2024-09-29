# TheMightyMustards

Hackoverflow Hackathon Fall 2024

### Requirements

```
pip install pyserial
```

## Inspiration

Our project was inspired by concerns about data privacy and online safety. Users often wonder if the websites they visit are tracking them or potentially posing a threat. We wanted to create a tool that provides real-time visibility and alerts about the safety of internet traffic.

## What it does

The Malicious Network Detector identifies and alerts users when incoming network requests are deemed a threat. It uses a combination of software and hardware, with a visual indicator and buzzer to notify users when malicious or safe traffic is detected.

## How we built it

We built the project using an Arduino for controlling LED lights (green for allowed, red for blocked, and blue for status), a buzzer, and a stepper motor. The Arduino is connected to a PC running Python, which handles the network traffic analysis and communication with the Arduino to provide real-time feedback.

## Challenges we ran into

- Limited supply.
- USB C to USB A Converters.

## Accomplishments that we're proud of

- First ever Hackathon for every member.

## What we learned

- Learning how to use Arduino.

## What's next for Malicious Network Detector

- Maybe a full product with your support.
