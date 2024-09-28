#include <Stepper.h>
int start = 1;
char input;

int green = 2;
int red = 3;
int blue = 4;
int speaker = 5;

int delay_time = 4500; 
int delay_slow = 250;

// Define the number of steps per revolution for your motor (adjust as needed)
const int stepsPerRevolution = 100;
// Initialize the motor 
Stepper myStepper(stepsPerRevolution, 6, 7, 8, 9);

void redLight() {
    // Blink red LED
    digitalWrite(speaker, HIGH);
    delay(delay_slow);
    digitalWrite(speaker, LOW);
    digitalWrite(red, HIGH);
    digitalWrite(green, LOW);  // Ensure green LED is off
    digitalWrite(blue, LOW);  // Ensure LED is off
    delay(delay_time);  // Adjust delay for blinking
    digitalWrite(red, LOW);
    delay(delay_slow);
    digitalWrite(speaker, HIGH);
    delay(delay_slow);
    turnMotor();
}

void greenLight() {
    // Blink green LED
    digitalWrite(speaker, HIGH);
    delay(delay_slow);
    digitalWrite(speaker, LOW);
    digitalWrite(green, HIGH);
    digitalWrite(red, LOW);  // Ensure LED is off
    digitalWrite(blue, LOW);  // Ensure LED is off
    delay(delay_time);  // Adjust delay for blinking
    digitalWrite(green, LOW);
    turnMotor();

}

void blueLight() {
    digitalWrite(speaker, HIGH);
    delay(delay_slow);
    digitalWrite(speaker, LOW);
    digitalWrite(blue, HIGH);
    digitalWrite(red, LOW);  // Ensure LED is off
    digitalWrite(green, LOW);  // Ensure LED is off
    delay(delay_time);  // Adjust delay for blinking
    digitalWrite(blue, LOW);
    turnMotor();
}

void turnMotor() {
  myStepper.step(stepsPerRevolution);
  digitalWrite(6, HIGH);  // Move one full revolution forward
  digitalWrite(7, HIGH);
  digitalWrite(8, HIGH);
  digitalWrite(9,HIGH);
  delay(250);
}

void setup() {
  // Set the speed of the motor in RPM
  myStepper.setSpeed(100);
  // Initialize serial communication
  Serial.begin(9600);
  Serial.println("Stepper motor continuous rotation started...");
  pinMode(2, OUTPUT);
  pinMode(3, OUTPUT);
  pinMode(4, OUTPUT);
  pinMode(5, OUTPUT);
}

void startup() {
    digitalWrite(2, HIGH);
    delay(250);
    digitalWrite(2, LOW);
    digitalWrite(3, HIGH);
    delay(250);
    digitalWrite(3, LOW);
    digitalWrite(4, HIGH);
    delay(250);
    digitalWrite(4, LOW);
    digitalWrite(5, HIGH);
    delay(250);
    digitalWrite(5, LOW);
    delay(250);
    turnMotor();
}

void loop() {
  if (start == 1){
    startup();
    start -= 1;
  }

  if (Serial.available() > 0) {
  input = Serial.read();  

  if (input == 'R') {
      redLight();
  } else if (input == 'G') {
      greenLight();
  } else if (input == 'B') {
      blueLight();
  }
}


}