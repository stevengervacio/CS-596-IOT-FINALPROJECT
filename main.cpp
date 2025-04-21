#include <Arduino.h>
#include <WiFi.h>
#include <HttpClient.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include "Wire.h"
#include "SparkFunLSM6DSO.h"
#include <TFMPlus.h>

#define PHOTOCELL_PIN 36
#define LIDAR_RX 15
#define LIDAR_TX 13

char ssid[] = "SETUP-2F8A";
char pass[] = "fifty4884almost";
const char kHostname[] = "3.138.34.177";
int port = 5000;

LSM6DSO myIMU;
TFMPlus tfmP;
WiFiClient client;
HttpClient http(client);

BLEServer *pServer;
BLECharacteristic *pCharacteristic;
#define SERVICE_UUID "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define CHAR_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"

// Threshold values for security levels – adjust these based on calibration data.
const int lightThreshold = 400;         // Difference in light to trigger Tier 1
const int lidarThreshold = 20;            // Difference in LiDAR to trigger Tier 2
const float accelUpperThreshold = 2.0;    // Acceleration above this is too fast (suspicious)
const float accelLowerThreshold = 0.1;    // Acceleration below this is too slow (suspicious)

// Save last sensor readings for comparison
int lastLight = 0;
int lastLidar = 0;
float lastAccelMagnitude = 0;

// Connect to Wi-Fi
void connectWiFi() {
  Serial.print("Connecting to WiFi: ");
  WiFi.begin(ssid, pass);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected!");
}

// Send sensor data and alert level to the cloud via an HTTP GET request.
void sendAlertToCloud(int level, float accel, int distance, int light) {
  String path = "/alert?level=" + String(level) +
                "&accel=" + String(accel) +
                "&distance=" + String(distance) +
                "&light=" + String(light);
  http.get(kHostname, port, path.c_str());
  http.stop();
}

void setup() {
  Serial.begin(115200);
  Wire.begin(21, 22);

  connectWiFi();

  // Initialize BLE for local monitoring
  BLEDevice::init("DoorSecurity");
  pServer = BLEDevice::createServer();
  BLEService *pService = pServer->createService(SERVICE_UUID);
  pCharacteristic = pService->createCharacteristic(
    CHAR_UUID,
    BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY
  );
  pService->start();
  pServer->getAdvertising()->start();

  // Initialize the IMU
  myIMU.begin();
  myIMU.initialize(BASIC_SETTINGS);
  Serial.println("IMU and BLE initialized");

  // Initialize LiDAR module communication via Serial2
  Serial2.begin(115200, SERIAL_8N1, LIDAR_RX, LIDAR_TX);
  tfmP.begin(&Serial2);
}

// Calculate the acceleration magnitude from the IMU sensor
float getAccelMagnitude() {
  float ax = myIMU.readFloatAccelX();
  float ay = myIMU.readFloatAccelY();
  float az = myIMU.readFloatAccelZ();
  return sqrt(ax * ax + ay * ay + az * az);
}

void loop() {
  // Read sensor values
  int currentLight = analogRead(PHOTOCELL_PIN);

  int16_t currentLidar;
  if (!tfmP.getData(currentLidar)) {
    currentLidar = lastLidar;
  }

  float currentAccelMagnitude = getAccelMagnitude();

  // Determine the suspicion level, starting at 0 (no suspicion)
  int susLevel = 0;

  // Tier 1: Change in ambient light (e.g., door opened or someone nearby)
  if (abs(currentLight - lastLight) > lightThreshold) {
    susLevel = 1;
  }

  // Tier 2: In addition to light change, a significant change in the LiDAR distance is detected.
  if (susLevel >= 1 && abs(currentLidar - lastLidar) > lidarThreshold) {
    susLevel = 2;
  }

  // Tier 3: With the changes above, if the acceleration is outside the normal range (either too low or too high),
  // then the system flags a full-blown security breach.
  if (susLevel == 2 && (currentAccelMagnitude > accelUpperThreshold || currentAccelMagnitude < accelLowerThreshold)) {
    susLevel = 3;
  }

  // Record all events (levels 1, 2, and 3) to the cloud for logging and analysis.
  if (susLevel > 0) {
    sendAlertToCloud(susLevel, currentAccelMagnitude, currentLidar, currentLight);
  }

  // Update BLE so a connected mobile app can view current sensor readings and status.
  char bleData[100];
  sprintf(bleData, "Accel:%.2f Light:%d Lidar:%d", currentAccelMagnitude, currentLight, currentLidar);
  pCharacteristic->setValue(bleData);
  pCharacteristic->notify();

  // Debug output on the serial monitor.
  Serial.print("Suspicion Level: ");
  Serial.println(susLevel);
  Serial.print("Light: "); Serial.print(currentLight);
  Serial.print(" | LiDAR: "); Serial.print(currentLidar);
  Serial.print(" | Accel: "); Serial.println(currentAccelMagnitude);

  // Save current sensor readings for comparison in the next loop.
  lastLight = currentLight;
  lastLidar = currentLidar;
  lastAccelMagnitude = currentAccelMagnitude;

  delay(1000); // Adjust delay as needed for your application
}
