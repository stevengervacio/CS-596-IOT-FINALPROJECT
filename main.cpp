/*
 * Door the Explorer - Multi-tier Security System
 * 
 * Genesis Anne Villar (RED ID: 824435476)
 * Steven Gervacio (RedID: 825656527)
 * CS 596 IOT - Prof. Donyanavard
 * 
 * Features:
 * - 3-tier security system using sensor fusion
 * - Real-time alerts via WiFi & email notifications
 * - Cloud recording of security events
 * - BLE monitoring and control interface
 * - Customizable security thresholds
 */

 #include <Arduino.h>
 #include <WiFi.h>
 #include <WiFiClient.h>
 #include <HttpClient.h>
 #include <BLEDevice.h>
 #include <TFT_eSPI.h>
 #include <Wire.h>
 #include "SparkFunLSM6DSO.h"
 #include <TFMPlus.h>
 
 // Pin definitions
 #define PHOTOCELL_PIN 36    // Light sensor
 #define LIDAR_RX 13         // LiDAR sensor RX
 #define LIDAR_TX 15         // LiDAR sensor TX
 #define BUZZER_PIN 26       // Buzzer for alarm
 
 // BLE UUIDs (Using the same from your lab code)
 #define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
 #define CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"
 
 // TFT Display colors
 #define TFT_BACKGROUND TFT_BLACK
 #define TFT_TEXT       TFT_WHITE
 #define TFT_HIGHLIGHT  TFT_GREEN
 #define TFT_WARNING    TFT_RED
 
 // WiFi credentials
 const char* ssid = "SETUP-2F8A";
 const char* password = "fifty4884almost";
 const char* serverAddress = "3.149.29.253"; // AWS server address
 const int serverPort = 5000;
 
 // Instantiate objects
 LSM6DSO myIMU;              // Accelerometer
 TFMPlus tfmP;               // LiDAR sensor
 TFT_eSPI tft = TFT_eSPI();  // Display
 
 // BLE objects - simplified based on Lab 4
 BLECharacteristic *pSecurityCharacteristic; // BLE characteristic for security data
 bool alarmEnabled = true;    // Alarm enabled by default
 
 // Security thresholds
 const int LIGHT_THRESHOLD = 400;         // Difference in light to trigger Tier 1
 const int LIDAR_THRESHOLD = 20;          // Difference in LiDAR to trigger Tier 2
 const float ACCEL_UPPER_THRESHOLD = 2.0; // Acceleration above this is too fast (suspicious)
 const float ACCEL_LOWER_THRESHOLD = 0.1; // Acceleration below this is too slow (suspicious)
 
 // Last sensor readings for comparison
 int lastLight = 0;
 int lastLidar = 0;
 float lastAccelMagnitude = 0;
 
 // Store the current suspicion level
 int currentSuspicionLevel = 0;
 
 // Flag to avoid repeated notifications for the same event
 bool notificationSent = false;
 
 // Flag to track if an alarm has been triggered
 bool alarmTriggered = false;
 
 // Function declarations
 void updateDisplay();
 void sendSecurityData();
 float getAccelMagnitude();
 void connectWiFi();
 void sendAlertToCloud(int level, float accel, int distance, int light);
 
 // BLE callbacks class (similar to Lab 4)
 class MyCallbacks: public BLECharacteristicCallbacks {
   void onWrite(BLECharacteristic *pCharacteristic) {
     std::string value = pCharacteristic->getValue();
 
     if (value.length() > 0) {
       Serial.println("*********");
       Serial.print("Command received: ");
       for (int i = 0; i < value.length(); i++) {
         Serial.print(value[i]);
       }
       Serial.println();
       
       // Check for alarm control commands
       if (value == "ON") {
         alarmEnabled = true;
         Serial.println("Alarm enabled");
         tft.fillRect(20, 140, 200, 20, TFT_BACKGROUND);
         tft.setTextColor(TFT_HIGHLIGHT);
         tft.setCursor(20, 140);
         tft.println("Alarm: ON");
       } 
       else if (value == "OFF") {
         alarmEnabled = false;
         // Clear the alarm triggered flag when alarm is turned off
         alarmTriggered = false; 
         Serial.println("Alarm disabled");
         tft.fillRect(20, 140, 200, 20, TFT_BACKGROUND);
         tft.setTextColor(TFT_WARNING);
         tft.setCursor(20, 140);
         tft.println("Alarm: OFF");
         // Turn off the buzzer when alarm is disabled
         ledcWrite(0, 0);
       }
       else if (value == "RESET") {
         // Reset the security alert and alarm
         currentSuspicionLevel = 0;
         notificationSent = false;
         alarmTriggered = false; // Reset the alarm trigger flag
         Serial.println("Security alert reset");
         
         // Update display
         updateDisplay();
         
         // Turn off buzzer
         ledcWrite(0, 0);
         
         // Clear alert and return to main screen
         tft.fillScreen(TFT_BACKGROUND);
         tft.setTextSize(2);
         tft.setTextColor(TFT_TEXT);
         tft.setCursor(20, 10);
         tft.println("Door the Explorer");
         tft.setTextSize(1);
         tft.setCursor(20, 40);
         tft.println("Security System v1.0");
         updateDisplay();
       }
       Serial.println("*********");
     }
   }
 };
 
 // Calculate acceleration magnitude from IMU
 float getAccelMagnitude() {
   float ax = myIMU.readFloatAccelX();
   float ay = myIMU.readFloatAccelY();
   float az = myIMU.readFloatAccelZ();
   return sqrt(ax * ax + ay * ay + az * az);
 }
 
 // Connect to Wi-Fi network
 void connectWiFi() {
   Serial.print("Connecting to WiFi: ");
   Serial.println(ssid);
   
   WiFi.begin(ssid, password);
   
   // Wait for connection with timeout
   int timeout = 0;
   while (WiFi.status() != WL_CONNECTED && timeout < 20) {
     delay(500);
     Serial.print(".");
     timeout++;
   }
   
   if (WiFi.status() == WL_CONNECTED) {
     Serial.println("\nWiFi connected!");
     Serial.print("IP address: ");
     Serial.println(WiFi.localIP());
     
     tft.fillRect(20, 160, 200, 20, TFT_BACKGROUND);
     tft.setTextColor(TFT_HIGHLIGHT);
     tft.setCursor(20, 160);
     tft.println("WiFi Connected");
   } else {
     Serial.println("\nWiFi connection failed!");
     
     tft.fillRect(20, 160, 200, 20, TFT_BACKGROUND);
     tft.setTextColor(TFT_WARNING);
     tft.setCursor(20, 160);
     tft.println("WiFi Failed");
   }
 }
 
 // Send alert data to cloud server
 void sendAlertToCloud(int level, float accel, int distance, int light) {
  if (WiFi.status() == WL_CONNECTED) {
    WiFiClient client;
    HttpClient http(client);
    
    // Create the query parameters
    String path = "/alert?level=" + String(level) +
                 "&accel=" + String(accel) +
                 "&distance=" + String(distance) +
                 "&light=" + String(light);
                 
    Serial.print("Sending alert to: ");
    Serial.println(path);
    
    // Send the request - using the correct API for your HttpClient library
    int err = http.get(serverAddress, serverPort, path.c_str());
    
    if (err == 0) {
      // Check the response
      int statusCode = http.responseStatusCode();
      
      Serial.print("HTTP Status code: ");
      Serial.println(statusCode);
      
      // Read the response body directly from the client
      String response = "";
      while (client.available()) {
        response += (char)client.read();
      }
      
      Serial.print("Response: ");
      Serial.println(response);
      
      // Display success message
      tft.fillRect(20, 180, 200, 20, TFT_BACKGROUND);
      if (statusCode > 0) {
        if (level == 3) {
          tft.setTextColor(TFT_WARNING);
          tft.setCursor(20, 180);
          tft.println("Alert Sent!");
        } else {
          tft.setTextColor(TFT_HIGHLIGHT);
          tft.setCursor(20, 180);
          tft.println("Event Logged");
        }
      } else {
        Serial.print("Error code: ");
        Serial.println(statusCode);
        
        tft.fillRect(20, 180, 200, 20, TFT_BACKGROUND);
        tft.setTextColor(TFT_WARNING);
        tft.setCursor(20, 180);
        tft.println("Send Failed");
      }
    } else {
      Serial.print("HTTP Request failed, error: ");
      Serial.println(err);
      
      tft.fillRect(20, 180, 200, 20, TFT_BACKGROUND);
      tft.setTextColor(TFT_WARNING);
      tft.setCursor(20, 180);
      tft.println("HTTP Error");
    }
    
    // Free resources
    http.stop();
  } else {
    Serial.println("WiFi not connected. Cannot send alert.");
    
    tft.fillRect(20, 180, 200, 20, TFT_BACKGROUND);
    tft.setTextColor(TFT_WARNING);
    tft.setCursor(20, 180);
    tft.println("WiFi Error");
  }
}
 
 // Control buzzer for alarm
 void controlBuzzer(bool enabled, int level) {
   // Sound the alarm if it's enabled and either at level 3 or previously triggered
   if (enabled && (level == 3 || alarmTriggered)) {
     // Set the alarm triggered flag when we reach level 3
     if (level == 3) {
       alarmTriggered = true;
     }
     
     // Use a PWM pattern for alarm sound
     static unsigned long lastToggle = 0;
     static bool buzzerState = false;
     
     unsigned long currentMillis = millis();
     
     // Toggle the buzzer state rapidly for an alarm effect
     if (currentMillis - lastToggle > 200) {
       buzzerState = !buzzerState;
       ledcWrite(0, buzzerState ? 127 : 0);
       lastToggle = currentMillis;
     }
   } else {
     // Ensure buzzer is off for other levels or when disabled
     ledcWrite(0, 0);
   }
 }
 
 // Update the TFT display with current status
 void updateDisplay() {
   // Clear data area
   tft.fillRect(20, 60, 200, 80, TFT_BACKGROUND);
 
   // Display suspicion level
   tft.setCursor(20, 60);
   tft.setTextColor(TFT_TEXT);
   tft.print("Suspicion Level: ");
   
   // Color-code the suspicion level
   switch (currentSuspicionLevel) {
     case 0:
       tft.setTextColor(TFT_HIGHLIGHT);
       break;
     case 1:
       tft.setTextColor(TFT_YELLOW);
       break;
     case 2:
       tft.setTextColor(TFT_ORANGE);
       break;
     case 3:
       tft.setTextColor(TFT_WARNING);
       break;
     default:
       tft.setTextColor(TFT_TEXT);
   }
   tft.println(currentSuspicionLevel);
   
   // Display sensor data
   tft.setTextColor(TFT_TEXT);
   tft.setCursor(20, 80);
   tft.print("Light: ");
   tft.println(lastLight);
   
   tft.setCursor(20, 100);
   tft.print("Distance: ");
   tft.println(lastLidar);
   
   tft.setCursor(20, 120);
   tft.print("Accel: ");
   tft.println(lastAccelMagnitude);
   
   // Display alarm status
   tft.setCursor(20, 140);
   if (alarmEnabled) {
     tft.setTextColor(TFT_HIGHLIGHT);
     tft.println("Alarm: ON");
   } else {
     tft.setTextColor(TFT_WARNING);
     tft.println("Alarm: OFF");
   }
 }
 
 // Send sensor and status data via BLE
 void sendSecurityData() {
   char securityString[50];
   sprintf(securityString, "S%d,A%.2f,L%d,D%d", 
           currentSuspicionLevel, lastAccelMagnitude, lastLight, lastLidar);
   pSecurityCharacteristic->setValue(securityString);
   pSecurityCharacteristic->notify();
 }
 
 void setup() {
   Serial.begin(115200);
   Serial.println("\n\nDoor the Explorer - Security System Starting...");
   
   // Initialize TFT display
   tft.init();
   tft.setRotation(1);  // landscape orientation
   tft.fillScreen(TFT_BACKGROUND);
   tft.setTextSize(2);
   tft.setTextColor(TFT_TEXT);
   tft.setCursor(20, 10);
   tft.println("Door the Explorer");
   tft.setTextSize(1);
   tft.setCursor(20, 40);
   tft.println("Security System v1.0");
   
   // Initialize buzzer using LEDC for PWM
   ledcSetup(0, 2000, 8); // Channel 0, 2kHz frequency, 8-bit resolution
   ledcAttachPin(BUZZER_PIN, 0);
   
   // Initialize I2C for IMU sensor
   Wire.begin(21, 22);
   
   // Initialize IMU
   if (myIMU.begin()) {
     Serial.println("LSM6DSO sensor initialized");
     
     if (myIMU.initialize(BASIC_SETTINGS)) {
       Serial.println("IMU settings loaded successfully");
     } else {
       Serial.println("Failed to load IMU settings");
     }
     
     tft.setCursor(20, 200);
     tft.setTextColor(TFT_HIGHLIGHT);
     tft.println("Accelerometer connected!");
   } else {
     Serial.println("LSM6DSO sensor initialization failed");
     tft.setCursor(20, 200);
     tft.setTextColor(TFT_WARNING);
     tft.println("ERROR: Accelerometer not found!");
     while (1); // halt if sensor not found
   }
   
   // Initialize LiDAR
   Serial2.begin(115200, SERIAL_8N1, LIDAR_RX, LIDAR_TX);
   tfmP.begin(&Serial2);
   delay(500);
   
   // Test LiDAR
   int16_t tfDist = 0;
   if (tfmP.getData(tfDist)) {
     Serial.println("LiDAR initialized. Distance: " + String(tfDist) + " cm");
   } else {
     Serial.println("LiDAR not responding!");
     tft.setCursor(20, 220);
     tft.setTextColor(TFT_WARNING);
     tft.println("ERROR: LiDAR not found!");
   }
   
   // Connect to WiFi
   connectWiFi();
   
   // Initialize BLE - simplified like Lab 4
   BLEDevice::init("DoorExplorer");
   BLEServer *pServer = BLEDevice::createServer();
   BLEService *pService = pServer->createService(SERVICE_UUID);
   
   // Create BLE characteristic for security data
   pSecurityCharacteristic = pService->createCharacteristic(
                              CHARACTERISTIC_UUID,
                              BLECharacteristic::PROPERTY_READ |
                              BLECharacteristic::PROPERTY_WRITE |
                              BLECharacteristic::PROPERTY_NOTIFY
                            );
   
   pSecurityCharacteristic->setCallbacks(new MyCallbacks());
   
   // Set initial value
   pSecurityCharacteristic->setValue("S0,A0.00,L0,D0");
   
   // Start the service
   pService->start();
   
   // Start advertising
   BLEAdvertising *pAdvertising = pServer->getAdvertising();
   pAdvertising->addServiceUUID(SERVICE_UUID);
   pAdvertising->setScanResponse(true);
   pAdvertising->start();
   
   Serial.println("BLE server started. Connect with your phone!");
   
   // Take initial readings
   lastLight = analogRead(PHOTOCELL_PIN);
   
   // Correctly pass lastLidar as a reference
   int16_t tfDistance = 0;
   if (tfmP.getData(tfDistance)) {
     lastLidar = tfDistance;
   }
   
   lastAccelMagnitude = getAccelMagnitude();
   
   // Update display with initial values
   updateDisplay();
   
   // Set alarm status display
   tft.fillRect(20, 140, 200, 20, TFT_BACKGROUND);
   tft.setTextColor(TFT_HIGHLIGHT);
   tft.setCursor(20, 140);
   tft.println("Alarm: ON");
   
   Serial.println("Setup complete. Monitoring started...");
 }
 
 void loop() {
   // Read current sensor values
   int currentLight = analogRead(PHOTOCELL_PIN);
   
   // Correctly handle LiDAR reading with reference parameter
   int16_t tfDistance = 0;
   int16_t currentLidar;
   if (tfmP.getData(tfDistance)) {
     currentLidar = tfDistance;
   } else {
     currentLidar = lastLidar; // Use previous value if read fails
   }
   
   float currentAccelMagnitude = getAccelMagnitude();
   
   // Calculate deltas (absolute differences)
   int lightDelta = abs(currentLight - lastLight);
   int lidarDelta = abs(currentLidar - lastLidar);
   
   // Reset suspicion level to 0 initially
   int susLevel = 0;
   
   // Tier 1: Significant change in ambient light
   if (lightDelta > LIGHT_THRESHOLD) {
     susLevel = 1;
   }
   
   // Tier 2: Light change + significant distance change
   if (susLevel >= 1 && lidarDelta > LIDAR_THRESHOLD) {
     susLevel = 2;
   }
   
   // Tier 3: Previous conditions + suspicious acceleration
   if (susLevel == 2 && (currentAccelMagnitude > ACCEL_UPPER_THRESHOLD || 
                         currentAccelMagnitude < ACCEL_LOWER_THRESHOLD)) {
     susLevel = 3;
   }
   
   // Update the current suspicion level if it changed
   if (susLevel != currentSuspicionLevel) {
     currentSuspicionLevel = susLevel;
     updateDisplay();
     notificationSent = false; // Reset flag when level changes
   }
   
   // Handle suspicion level actions
   if (susLevel > 0) {
     // Record all events (all levels) to the cloud
     sendAlertToCloud(susLevel, currentAccelMagnitude, currentLidar, currentLight);
     
     // For level 3, trigger the alarm if enabled
     if (susLevel == 3 && !notificationSent) {
       // Send the notification only once per event
       sendAlertToCloud(susLevel, currentAccelMagnitude, currentLidar, currentLight);
       notificationSent = true;
       
       // Display alert on TFT
       tft.fillScreen(TFT_RED); // Flash the screen
       delay(200);
       tft.fillScreen(TFT_BACKGROUND);
       
       // Redraw the interface
       tft.setTextSize(2);
       tft.setTextColor(TFT_TEXT);
       tft.setCursor(20, 10);
       tft.println("Door the Explorer");
       tft.setTextSize(1);
       
       tft.setTextColor(TFT_WARNING);
       tft.setCursor(20, 40);
       tft.println("!!! SECURITY ALERT !!!");
       
       updateDisplay();
     }
   }
   
   // Control the buzzer based on suspicion level and alarm settings
   controlBuzzer(alarmEnabled, susLevel);
   
   // Send BLE update
   sendSecurityData();
   
   // Debug output
   Serial.print("Suspicion Level: ");
   Serial.print(susLevel);
   Serial.print(" | Light: ");
   Serial.print(currentLight);
   Serial.print(" (Δ");
   Serial.print(lightDelta);
   Serial.print(") | LiDAR: ");
   Serial.print(currentLidar);
   Serial.print(" (Δ");
   Serial.print(lidarDelta);
   Serial.print(") | Accel: ");
   Serial.println(currentAccelMagnitude);
   
   // Save current readings for next comparison
   lastLight = currentLight;
   lastLidar = currentLidar;
   lastAccelMagnitude = currentAccelMagnitude;
   
   // Short delay
   delay(200);
 }