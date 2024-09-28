int redLedPin = 12;  // Pin for red LED
int greenLedPin = 13;  // Pin for green LED
char input;

void setup() {
  Serial.begin(9600);  // Start serial communication
  pinMode(redLedPin, OUTPUT);
  pinMode(greenLedPin, OUTPUT);
}

void loop() {
  if (Serial.available() > 0) {
    input = Serial.read();  // Read input from Python script

    if (input == 'R') {
      // Blink red LED
      digitalWrite(redLedPin, HIGH);
      digitalWrite(greenLedPin, LOW);  // Ensure green LED is off
      delay(500);  // Adjust delay for blinking
      digitalWrite(redLedPin, LOW);
    } else if (input == 'G') {
      // Blink green LED
      digitalWrite(greenLedPin, HIGH);
      digitalWrite(redLedPin, LOW);  // Ensure red LED is off
      delay(500);  // Adjust delay for blinking
      digitalWrite(greenLedPin, LOW);
    }
  }
}