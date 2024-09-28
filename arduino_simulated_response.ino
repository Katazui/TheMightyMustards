String command = "";

// Define pins for green and red LEDs and the buzzer
int greenLEDs[] = {2, 3, 4, 5, 6};  // Green LEDs for correct actions
int redLEDs[] = {7, 8, 9, 10, 11};  // Red LEDs for incorrect actions
int buzzerPin = 12;  // Buzzer pin

void setup() {
  Serial.begin(9600);  // Initialize serial communication

  // Set all LED and buzzer pins to OUTPUT
  for (int i = 0; i < 5; i++) {
    pinMode(greenLEDs[i], OUTPUT);
    pinMode(redLEDs[i], OUTPUT);
  }
  pinMode(buzzerPin, OUTPUT);

  // Flash all LEDs 3 times to indicate Arduino is connected
  flashAllLEDs(3);
}

void loop() {
  // Check if there's a new command from the serial port
  if (Serial.available() > 0) {
    command = Serial.readStringUntil('\n');  // Read the command

    if (command == "CAPTURE_PACKETS") {
      lightUpGreenLEDs();  // Light up green LEDs one by one for capturing packets
    } else if (command == "CLOSE_PROGRAM") {
      turnOffGreenLEDs();  // Turn off green LEDs simultaneously
      flashAllLEDs(1);  // Flash all LEDs once for program close
    } else if (command == "CORRECT_CLASSIFICATION") {
      flashGreenLEDsOnce();  // Flash green LEDs once for correct classification
    } else if (command == "INCORRECT_CLASSIFICATION") {
      flashRedLEDsTwice();  // Flash red LEDs twice for incorrect classification
      soundBuzzer();  // Sound the buzzer for incorrect classification
    }
  }
}

// Flash all LEDs a specified number of times
void flashAllLEDs(int times) {
  for (int i = 0; i < times; i++) {
    for (int j = 0; j < 5; j++) {
      digitalWrite(greenLEDs[j], HIGH);
      digitalWrite(redLEDs[j], HIGH);
    }
    delay(500);
    for (int j = 0; j < 5; j++) {
      digitalWrite(greenLEDs[j], LOW);
      digitalWrite(redLEDs[j], LOW);
    }
    delay(500);
  }
}

// Light up green LEDs one by one
void lightUpGreenLEDs() {
  for (int i = 0; i < 5; i++) {
    digitalWrite(greenLEDs[i], HIGH);  // Turn on green LED
    delay(500);  // Wait for 500 milliseconds
  }
  Serial.println("Green LEDs are on");
}

// Turn off all green LEDs simultaneously
void turnOffGreenLEDs() {
  for (int i = 0; i < 5; i++) {
    digitalWrite(greenLEDs[i], LOW);  // Turn off green LED
  }
  Serial.println("Green LEDs are off");
}

// Flash green LEDs once for correct classification
void flashGreenLEDsOnce() {
  for (int j = 0; j < 5; j++) {
    digitalWrite(greenLEDs[j], HIGH);  // Turn on green LED
  }
  delay(500);
  for (int j = 0; j < 5; j++) {
    digitalWrite(greenLEDs[j], LOW);  // Turn off green LED
  }
  Serial.println("Green LEDs flashed once");
}

// Flash red LEDs twice for incorrect classification
void flashRedLEDsTwice() {
  for (int i = 0; i < 2; i++) {
    for (int j = 0; j < 5; j++) {
      digitalWrite(redLEDs[j], HIGH);  // Turn on red LED
    }
    delay(500);
    for (int j = 0; j < 5; j++) {
      digitalWrite(redLEDs[j], LOW);  // Turn off red LED
    }
    delay(500);
  }
  Serial.println("Red LEDs flashed twice");
}

// Sound the buzzer for incorrect classification
void soundBuzzer() {
  for (int i = 0; i < 3; i++) {
    digitalWrite(buzzerPin, HIGH);  // Turn on the buzzer
    delay(200);
    digitalWrite(buzzerPin, LOW);  // Turn off the buzzer
    delay(200);
  }
  Serial.println("Buzzer sounded for incorrect classification");
}
