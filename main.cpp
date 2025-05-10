/*
 * Door the Explorer - Multi-tier Security System
 * 
 * Genesis Anne Villar (RED ID: 824435476)
 * Steven Gervacio (RedID: 825656527)
 * CS 596 IOT - Prof. Donyanavard
 * 
 * features:
 * - 3-tier security system using sensor fusion
 * - real-time alerts via wifi & email notifications
 * - cloud recording of security events
 * - ble monitoring and control interface
 * - customizable security thresholds
 * - slow door opening detection
 * - normal door activity recognition
 * - sneaky intrusion detection
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
 
 // pin definitions
 #define PHOTOCELL_PIN 36    // light sensor
 #define LIDAR_RX 13         // lidar sensor rx
 #define LIDAR_TX 15         // lidar sensor tx
 #define BUZZER_PIN 26       // buzzer for alarm
 
 // ble uuids (using the same from your lab code)
 #define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
 #define CHARACTERISTIC_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"
 
 // tft display colors
 #define TFT_BACKGROUND TFT_BLACK
 #define TFT_TEXT       TFT_WHITE
 #define TFT_HIGHLIGHT  TFT_GREEN
 #define TFT_WARNING    TFT_RED
 
 // wifi credentials
 const char* ssid = "SETUP-2F8A";
 const char* password = "fifty4884almost";
 const char* serverAddress = "18.227.13.46"; // aws server address
 const int serverPort = 5000;
 
 // instantiate objects
 LSM6DSO myIMU;              // accelerometer
 TFMPlus tfmP;               // lidar sensor
 TFT_eSPI tft = TFT_eSPI();  // display
 
 // ble objects - simplified based on lab 4
 BLECharacteristic *pSecurityCharacteristic; // ble characteristic for security data
 bool alarmEnabled = true;    // alarm enabled by default
 
 // security thresholds - updated for better sensitivity
 int LIGHT_THRESHOLD = 10;    // will be dynamically adjusted during calibration
 const int LIDAR_THRESHOLD = 1;           // more sensitive to detect slow movement
 const float ACCEL_UPPER_THRESHOLD = 1.22; // acceleration above this is suspicious
 const float ACCEL_LOWER_THRESHOLD = 0.05; // acceleration below this is suspicious
 const float ACCEL_CHANGE_THRESHOLD = 0.005; // more sensitive to slight vibrations
 
 // last sensor readings for comparison
 int lastLight = 0;
 int lastLidar = 0;
 float lastAccelMagnitude = 0;
 
 // acceleration change tracking
 float accelChangeRate = 0.0;
 float previousAccelMagnitude = 0.0;
 
 // store the current suspicion level
 int currentSuspicionLevel = 0;
 
 // flag to avoid repeated notifications for the same event
 bool notificationSent = false;
 
 // flag to track if an alarm has been triggered
 bool alarmTriggered = false;
 
 // variables for command checking
 unsigned long lastCommandCheckTime = 0;
 const unsigned long commandCheckInterval = 10000; // check every 10 seconds
 
 // display update timer variables
 unsigned long lastDisplayUpdateTime = 0;
 const unsigned long displayUpdateInterval = 500; // update display every 500ms
 
 // variables for persistent suspicious state
 bool lightSuspiciousPersistent = false;
 bool lidarSuspiciousPersistent = false;
 bool accelSuspiciousPersistent = false;
 unsigned long lastSuspiciousLightTime = 0;
 unsigned long lastSuspiciousLidarTime = 0;
 unsigned long lastSuspiciousAccelTime = 0;
 const unsigned long suspiciousPersistTime = 3000; // 3 seconds persistence
 
 // variables for slow door opening detection
 unsigned long patternStartTime = 0;
 bool slowDoorPatternDetected = false;
 int cumulativeLidarChange = 0;
 int previousLidar = 0;
 bool directionEstablished = false;
 int directionSign = 0;
 unsigned long lastMovementTime = 0;
 float doorOpeningVelocity = 0.0;  // track door opening speed
 
 // variables for normal door detection
 bool normalDoorOpeningDetected = false;
 unsigned long normalActivityTime = 0;
 
 // variables for enhanced sneaky intrusion detection
 bool sneakyIntrusion = false;
 
 // variable for level 3 debouncing
 unsigned long level3DebounceTime = 0;
 const unsigned long LEVEL3_DEBOUNCE_PERIOD = 1500; // 1.5 seconds to confirm level 3 (reduced from 3s)
 
 // function declarations
 void updateDisplay();
 void updateSensorValues(int light, int distance, float accel);
 void sendSecurityData();
 float getAccelMagnitude();
 void connectWiFi();
 void sendAlertToCloud(int level, float accel, int distance, int light);
 void checkForCommands();
 void calibrateLight();  // light sensor calibration
 
 // ble callbacks class (similar to lab 4)
 class MyCallbacks: public BLECharacteristicCallbacks 
 {
   void onWrite(BLECharacteristic *pCharacteristic) 
   {
     std::string value = pCharacteristic->getValue();
 
     if (value.length() > 0) 
     {
       Serial.println("*********");
       Serial.print("Command received: ");
       for (int i = 0; i < value.length(); i++) 
       {
         Serial.print(value[i]);
       }
       Serial.println();
       
       // check for alarm control commands
       if (value == "ON") 
       {
         alarmEnabled = true;
         Serial.println("Alarm enabled");
         tft.fillRect(20, 140, 200, 20, TFT_BACKGROUND);
         tft.setTextColor(TFT_HIGHLIGHT);
         tft.setCursor(20, 140);
         tft.println("Alarm: ON");
       } 
       else if (value == "OFF") 
       {
         alarmEnabled = false;
         alarmTriggered = false; // clear the alarm triggered flag when alarm is turned off
         Serial.println("Alarm disabled");
         tft.fillRect(20, 140, 200, 20, TFT_BACKGROUND);
         tft.setTextColor(TFT_WARNING);
         tft.setCursor(20, 140);
         tft.println("Alarm: OFF");
         ledcWrite(0, 0); // turn off the buzzer when alarm is disabled
       }
       else if (value == "RESET") 
       {
         // reset the security alert and alarm
         currentSuspicionLevel = 0;
         notificationSent = false;
         alarmTriggered = false; // reset the alarm trigger flag
         
         // reset persistent suspicious flags
         lightSuspiciousPersistent = false;
         lidarSuspiciousPersistent = false;
         accelSuspiciousPersistent = false;
         
         // reset slow door opening detection variables
         slowDoorPatternDetected = false;
         cumulativeLidarChange = 0;
         directionEstablished = false;
         normalDoorOpeningDetected = false;
         level3DebounceTime = 0;
         sneakyIntrusion = false;
         
         Serial.println("Security alert reset");
         
         updateDisplay();
         
         ledcWrite(0, 0); // turn off buzzer
         
         // clear alert and return to main screen
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
 
 // calculate acceleration magnitude from imu
 float getAccelMagnitude() 
 {
   float ax = myIMU.readFloatAccelX();
   float ay = myIMU.readFloatAccelY();
   float az = myIMU.readFloatAccelZ();
   return sqrt(ax * ax + ay * ay + az * az); // calculate 3d vector magnitude
 }
 
 // calibrate the light sensor based on ambient light
 void calibrateLight() 
 {
   Serial.println("Calibrating light sensor...");
   int readings = 0;
   int sum = 0;
   
   // take 10 readings
   for (int i = 0; i < 10; i++) 
   {
     int reading = analogRead(PHOTOCELL_PIN);
     sum += reading;
     readings++;
     delay(100);
   }
   
   // calculate average baseline
   int baselineLight = sum / readings;
   
   // adjust light threshold based on baseline
   LIGHT_THRESHOLD = max(10, baselineLight / 5); // dynamic threshold based on ambient light
   
   Serial.print("Light sensor baseline: ");
   Serial.println(baselineLight);
   Serial.print("Adjusted light threshold: ");
   Serial.println(LIGHT_THRESHOLD);
 }
 
 // connect to wi-fi network
 void connectWiFi() 
 {
   Serial.print("Connecting to WiFi: ");
   Serial.println(ssid);
   
   WiFi.begin(ssid, password);
   
   // wait for connection with timeout
   int timeout = 0;
   while (WiFi.status() != WL_CONNECTED && timeout < 20) 
   {
     delay(500);
     Serial.print(".");
     timeout++;
   }
   
   if (WiFi.status() == WL_CONNECTED) 
   {
     Serial.println("\nWiFi connected!");
     Serial.print("IP address: ");
     Serial.println(WiFi.localIP());
     
     tft.fillRect(20, 160, 200, 20, TFT_BACKGROUND);
     tft.setTextColor(TFT_HIGHLIGHT);
     tft.setCursor(20, 160);
     tft.println("WiFi Connected");
   } 
   else 
   {
     Serial.println("\nWiFi connection failed!");
     
     tft.fillRect(20, 160, 200, 20, TFT_BACKGROUND);
     tft.setTextColor(TFT_WARNING);
     tft.setCursor(20, 160);
     tft.println("WiFi Failed");
   }
 }
 
 // send alert data to cloud server
 void sendAlertToCloud(int level, float accel, int distance, int light) 
 {
   if (WiFi.status() == WL_CONNECTED) 
   {
     WiFiClient client;
     HttpClient http(client);
 
     // create device id from mac address
     String deviceId = "door_explorer_" + WiFi.macAddress();
     deviceId.replace(":", ""); // remove colons from mac address
     
     // create the query parameters
     String path = "/alert?level=" + String(level) +
                  "&accel=" + String(accel) +
                  "&distance=" + String(distance) +
                  "&light=" + String(light) +
                  "&device_id=" + deviceId;
                  
     Serial.print("Sending alert to: ");
     Serial.println(path);
     
     // send the request - using the correct api for your httpclient library
     int err = http.get(serverAddress, serverPort, path.c_str());
     
     if (err == 0) 
     {
       // check the response
       int statusCode = http.responseStatusCode();
       
       Serial.print("HTTP Status code: ");
       Serial.println(statusCode);
       
       // read the response body directly from the client
       String response = "";
       while (client.available()) 
       {
         response += (char)client.read();
       }
       
       Serial.print("Response: ");
       Serial.println(response);
       
       // display success message
       tft.fillRect(20, 180, 200, 20, TFT_BACKGROUND);
       if (statusCode > 0) 
       {
         if (level == 3) 
         {
           tft.setTextColor(TFT_WARNING);
           tft.setCursor(20, 180);
           tft.println("Alert Sent!");
         } 
         else 
         {
           tft.setTextColor(TFT_HIGHLIGHT);
           tft.setCursor(20, 180);
           tft.println("Event Logged");
         }
       } 
       else 
       {
         Serial.print("Error code: ");
         Serial.println(statusCode);
         
         tft.fillRect(20, 180, 200, 20, TFT_BACKGROUND);
         tft.setTextColor(TFT_WARNING);
         tft.setCursor(20, 180);
         tft.println("Send Failed");
       }
     } 
     else 
     {
       Serial.print("HTTP Request failed, error: ");
       Serial.println(err);
       
       tft.fillRect(20, 180, 200, 20, TFT_BACKGROUND);
       tft.setTextColor(TFT_WARNING);
       tft.setCursor(20, 180);
       tft.println("HTTP Error");
     }
     
     // free resources
     http.stop();
   } 
   else 
   {
     Serial.println("WiFi not connected. Cannot send alert.");
     
     tft.fillRect(20, 180, 200, 20, TFT_BACKGROUND);
     tft.setTextColor(TFT_WARNING);
     tft.setCursor(20, 180);
     tft.println("WiFi Error");
   }
 }
 
 // control buzzer for alarm
 void controlBuzzer(bool enabled, int level) 
 {
   // sound the alarm if it's enabled and either at level 3 or previously triggered
   if (enabled && (level == 3 || alarmTriggered)) 
   {
     // set the alarm triggered flag when we reach level 3
     if (level == 3) 
     {
       alarmTriggered = true;
     }
     
     // use a pwm pattern for alarm sound
     static unsigned long lastToggle = 0;
     static bool buzzerState = false;
     
     unsigned long currentMillis = millis();
     
     // toggle the buzzer state rapidly for an alarm effect
     if (currentMillis - lastToggle > 200) 
     {
       buzzerState = !buzzerState;
       if (buzzerState) 
       {
         ledcWrite(0, 127); // turn buzzer on at half volume
       }
       else 
       {
         ledcWrite(0, 0); // turn buzzer off
       }
       lastToggle = currentMillis;
     }
   } 
   else 
   {
     // ensure buzzer is off for other levels or when disabled
     ledcWrite(0, 0);
   }
 }
 
 // update just the sensor values on the display (more efficient)
 void updateSensorValues(int light, int distance, float accel) 
 {
   // update light value - increased rectangle size
   tft.fillRect(70, 80, 150, 12, TFT_BACKGROUND); // increased height to 12
   tft.setCursor(70, 80);
   tft.setTextColor(TFT_TEXT);
   tft.println(light);
   
   // update distance value - increased rectangle size
   tft.fillRect(70, 100, 150, 12, TFT_BACKGROUND); // increased height to 12
   tft.setCursor(70, 100);
   tft.println(distance);
   
   // update acceleration value - increased rectangle size
   tft.fillRect(70, 120, 150, 12, TFT_BACKGROUND); // increased height to 12
   tft.setCursor(70, 120);
   tft.println(accel);
   
   // add indicators for door activity
   tft.fillRect(150, 60, 150, 12, TFT_BACKGROUND);
   if (sneakyIntrusion) 
   {
     tft.setCursor(150, 60);
     tft.setTextColor(TFT_RED);
     tft.println("SNEAKY INTRUSION!");
   } 
   else if (slowDoorPatternDetected) 
   {
     tft.setCursor(150, 60);
     tft.setTextColor(TFT_WARNING);
     tft.println("SLOW DOOR");
   } 
   else if (normalDoorOpeningDetected) 
   {
     tft.setCursor(150, 60);
     tft.setTextColor(TFT_HIGHLIGHT);
     tft.println("NORMAL DOOR");
   }
 }
 
 // update the tft display with current status
 void updateDisplay() 
 {
   // clear data area
   tft.fillRect(20, 60, 200, 80, TFT_BACKGROUND);
 
   // display suspicion level
   tft.setCursor(20, 60);
   tft.setTextColor(TFT_TEXT);
   tft.print("Suspicion Level: ");
   
   // color-code the suspicion level
   switch (currentSuspicionLevel) 
   {
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
   
   // display door activity indicators
   if (sneakyIntrusion) 
   {
     tft.setCursor(150, 60);
     tft.setTextColor(TFT_RED);
     tft.println("SNEAKY INTRUSION!");
   } 
   else if (slowDoorPatternDetected) 
   {
     tft.setCursor(150, 60);
     tft.setTextColor(TFT_WARNING);
     tft.println("SLOW DOOR");
   } 
   else if (normalDoorOpeningDetected) 
   {
     tft.setCursor(150, 60);
     tft.setTextColor(TFT_HIGHLIGHT);
     tft.println("NORMAL DOOR");
   }
   
   // display sensor data
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
   
   // display alarm status
   tft.setCursor(20, 140);
   if (alarmEnabled) 
   {
     tft.setTextColor(TFT_HIGHLIGHT);
     tft.println("Alarm: ON");
   } 
   else 
   {
     tft.setTextColor(TFT_WARNING);
     tft.println("Alarm: OFF");
   }
 }
 
 // send sensor and status data via ble
 void sendSecurityData() 
 {
   char securityString[50];
   sprintf(securityString, "S%d,A%.2f,L%d,D%d", 
           currentSuspicionLevel, lastAccelMagnitude, lastLight, lastLidar);
   pSecurityCharacteristic->setValue(securityString);
   pSecurityCharacteristic->notify(); // notify any connected ble devices
 }
 
 void setup() 
 {
   Serial.begin(115200);
   Serial.println("\n\nDoor the Explorer - Security System Starting...");
   
   // initialize tft display
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
   
   // initialize buzzer using ledc for pwm
   ledcSetup(0, 2000, 8); // channel 0, 2khz frequency, 8-bit resolution
   ledcAttachPin(BUZZER_PIN, 0);
   
   // initialize i2c for imu sensor
   Wire.begin(21, 22);
   
   // initialize imu
   if (myIMU.begin()) 
   {
     Serial.println("LSM6DSO sensor initialized");
     
     if (myIMU.initialize(BASIC_SETTINGS)) 
     {
       Serial.println("IMU settings loaded successfully");
     } 
     else 
     {
       Serial.println("Failed to load IMU settings");
     }
     
     tft.setCursor(20, 200);
     tft.setTextColor(TFT_HIGHLIGHT);
     tft.println("Accelerometer connected!");
   } 
   else 
   {
     Serial.println("LSM6DSO sensor initialization failed");
     tft.setCursor(20, 200);
     tft.setTextColor(TFT_WARNING);
     tft.println("ERROR: Accelerometer not found!");
     while (1); // halt if sensor not found
   }
   
   // initialize lidar
   Serial2.begin(115200, SERIAL_8N1, LIDAR_RX, LIDAR_TX);
   tfmP.begin(&Serial2);
   delay(500);
   
   // test lidar
   int16_t tfDist = 0;
   if (tfmP.getData(tfDist)) 
   {
     Serial.println("LiDAR initialized. Distance: " + String(tfDist) + " cm");
   } 
   else 
   {
     Serial.println("LiDAR not responding!");
     tft.setCursor(20, 220);
     tft.setTextColor(TFT_WARNING);
     tft.println("ERROR: LiDAR not found!");
   }
   
   // calibrate light sensor
   calibrateLight();
   
   // connect to wifi
   connectWiFi();
   
   // initialize ble - simplified like lab 4
   BLEDevice::init("DoorExplorer");
   BLEServer *pServer = BLEDevice::createServer();
   BLEService *pService = pServer->createService(SERVICE_UUID);
   
   // create ble characteristic for security data
   pSecurityCharacteristic = pService->createCharacteristic(
                              CHARACTERISTIC_UUID,
                              BLECharacteristic::PROPERTY_READ |
                              BLECharacteristic::PROPERTY_WRITE |
                              BLECharacteristic::PROPERTY_NOTIFY
                            );
   
   pSecurityCharacteristic->setCallbacks(new MyCallbacks());
   
   // set initial value
   pSecurityCharacteristic->setValue("S0,A0.00,L0,D0");
   
   // start the service
   pService->start();
   
   // start advertising
   BLEAdvertising *pAdvertising = pServer->getAdvertising();
   pAdvertising->addServiceUUID(SERVICE_UUID);
   pAdvertising->setScanResponse(true);
   pAdvertising->start();
   
   Serial.println("BLE server started. Connect with your phone!");
   
   // take initial readings
   lastLight = analogRead(PHOTOCELL_PIN);
   
   // debug raw light sensor value
   Serial.print("Initial raw light sensor reading: ");
   Serial.println(lastLight);
   
   // correctly pass lastlidar as a reference
   int16_t tfDistance = 0;
   if (tfmP.getData(tfDistance)) 
   {
     lastLidar = tfDistance;
     previousLidar = lastLidar; // initialize previous lidar value for pattern detection
   }
   
   lastAccelMagnitude = getAccelMagnitude();
   previousAccelMagnitude = lastAccelMagnitude; // initialize the previous accel value
   
   // update display with initial values
   updateDisplay();
   
   // set alarm status display
   tft.fillRect(20, 140, 200, 20, TFT_BACKGROUND);
   tft.setTextColor(TFT_HIGHLIGHT);
   tft.setCursor(20, 140);
   tft.println("Alarm: ON");
   
   // initialize timer variables
   lastDisplayUpdateTime = millis();
   lastCommandCheckTime = millis();
   lastMovementTime = millis();
   
   Serial.println("Setup complete. Monitoring started...");
 }
 
 void loop() 
 {
   // read current sensor values
   int currentLight = analogRead(PHOTOCELL_PIN);
   
   // debug raw light sensor reading periodically
   static unsigned long lastLightDebugTime = 0;
   unsigned long currentTime = millis();
   if (currentTime - lastLightDebugTime > 5000)  // every 5 seconds
   {
     Serial.print("Raw light sensor reading: ");
     Serial.println(currentLight);
     lastLightDebugTime = currentTime;
   }
   
   // correctly handle lidar reading with reference parameter
   int16_t tfDistance = 0;
   int16_t currentLidar;
   if (tfmP.getData(tfDistance)) 
   {
     currentLidar = tfDistance;
   } 
   else 
   {
     currentLidar = lastLidar; // use previous value if read fails
   }
   
   float currentAccelMagnitude = getAccelMagnitude();
   
   // calculate acceleration change rate
   accelChangeRate = abs(currentAccelMagnitude - previousAccelMagnitude);
   previousAccelMagnitude = currentAccelMagnitude;
   
   // calculate deltas (absolute differences)
   int lightDelta = abs(currentLight - lastLight);
   int lidarDelta = abs(currentLidar - lastLidar);
   
   // track which sensors are showing suspicious readings
   bool lightSuspicious = (lightDelta > LIGHT_THRESHOLD); // significant light change detected
   bool lidarSuspicious = (lidarDelta > LIDAR_THRESHOLD); // movement detected by lidar
   bool accelSuspicious = (currentAccelMagnitude > ACCEL_UPPER_THRESHOLD || 
                          currentAccelMagnitude < ACCEL_LOWER_THRESHOLD ||
                          accelChangeRate > ACCEL_CHANGE_THRESHOLD); // abnormal acceleration patterns
   
   // normal door opening pattern: quick significant movement
   if (lidarDelta > 15 && (currentTime - lastMovementTime < 1000)) // large change in short time
   {
     normalDoorOpeningDetected = true;
     normalActivityTime = currentTime;
     Serial.println("Normal door activity detected");
   }
   
   // reset normal activity flag after a while
   if (normalDoorOpeningDetected && (currentTime - normalActivityTime > 5000)) 
   {
     normalDoorOpeningDetected = false;
   }
   
   // track cumulative changes in one direction (slow door opening)
   if (currentLidar != previousLidar) 
   {
     lastMovementTime = currentTime;
     
     // check if we've established a movement direction yet
     if (!directionEstablished && lidarDelta > 0) 
     {
       directionEstablished = true;
       if (currentLidar > previousLidar) // door moving away (opening)
       {
         directionSign = 1;
       }
       else // door moving closer (closing)
       {
         directionSign = -1;
       }
       patternStartTime = currentTime;
       Serial.print("Direction established: ");
       if (directionSign > 0) 
       {
         Serial.println("increasing");
       }
       else 
       {
         Serial.println("decreasing");
       }
     }
     
     // if we have a direction, check if current movement follows that pattern
     if (directionEstablished) 
     {
       int currentDirectionSign;
       if (currentLidar > previousLidar) 
       {
         currentDirectionSign = 1;
       }
       else 
       {
         currentDirectionSign = -1;
       }
       
       // if movement continues in same direction, add to cumulative change
       if (currentDirectionSign == directionSign && lidarDelta > 0) 
       {
         cumulativeLidarChange += lidarDelta; // accumulate changes in same direction
         
         // calculate velocity (change per second) if enough time has passed
         if (currentTime - patternStartTime > 100) // avoid division by near-zero
         {
           doorOpeningVelocity = cumulativeLidarChange / ((currentTime - patternStartTime) / 1000.0);
           
           Serial.print("Door opening velocity: ");
           Serial.print(doorOpeningVelocity);
           Serial.println(" cm/s");
           
           // debug output for slow door detection
           Serial.print("Cumulative LiDAR change: ");
           Serial.print(cumulativeLidarChange);
           Serial.print(" over ");
           Serial.print((currentTime - patternStartTime) / 1000.0);
           Serial.println(" seconds");
           
           // fast opening (normal) vs. slow opening (suspicious)
           if (doorOpeningVelocity > 5.0)  // threshold for normal door opening speed
           {
             slowDoorPatternDetected = false;
             sneakyIntrusion = false;
             if (!normalDoorOpeningDetected && cumulativeLidarChange > 10) 
             {
               normalDoorOpeningDetected = true;
               normalActivityTime = currentTime;
               Serial.println("Normal door velocity detected");
             }
           } 
           // a sneaky door opening is slow but consistent over time
           else if (cumulativeLidarChange > 10 && (currentTime - patternStartTime < 10000) && 
                    (currentTime - patternStartTime > 2000) && doorOpeningVelocity < 5.0 && 
                    doorOpeningVelocity > 0.5) // slow but deliberate movement
           {
             slowDoorPatternDetected = true;
             normalDoorOpeningDetected = false;
             Serial.println("*** SLOW DOOR PATTERN DETECTED ***");
             
             // check for sneaky intrusion
             if (doorOpeningVelocity < 3.0 && cumulativeLidarChange > 15 && 
                 (currentTime - patternStartTime > 3000)) // very slow, sustained movement
             {
               sneakyIntrusion = true;
               Serial.println("!!! SNEAKY INTRUSION DETECTED !!!");
             }
           } 
           else if (cumulativeLidarChange > 10 && (currentTime - patternStartTime < 2000)) 
           {
             // this is a normal door opening - fast but significant change
             slowDoorPatternDetected = false;
             sneakyIntrusion = false;
             normalDoorOpeningDetected = true;
             normalActivityTime = currentTime;
             Serial.println("Normal door opening detected - not suspicious");
           }
         }
       } 
       else if (currentDirectionSign != directionSign && lidarDelta > 0) 
       {
         Serial.println("Direction change - resetting pattern detection");
         directionEstablished = false;
         cumulativeLidarChange = 0;
         slowDoorPatternDetected = false;
         doorOpeningVelocity = 0.0;
         sneakyIntrusion = false;
       }
     }
     
     previousLidar = currentLidar;
   }
   
   // reset pattern detection if no movement for a while
   if (directionEstablished && (currentTime - lastMovementTime > 5000)) 
   {
     Serial.println("No movement for 5 seconds - resetting pattern detection");
     directionEstablished = false;
     cumulativeLidarChange = 0;
     slowDoorPatternDetected = false;
     doorOpeningVelocity = 0.0;
     sneakyIntrusion = false;
   }
   
   // update persistent suspicious status
   if (lightSuspicious) 
   {
     lightSuspiciousPersistent = true;
     lastSuspiciousLightTime = currentTime;
   } 
   else if (currentTime - lastSuspiciousLightTime > suspiciousPersistTime) 
   {
     lightSuspiciousPersistent = false; // reset after 3 seconds of normal readings
   }
   
   if (lidarSuspicious) 
   {
     lidarSuspiciousPersistent = true;
     lastSuspiciousLidarTime = currentTime;
   } 
   else if (currentTime - lastSuspiciousLidarTime > suspiciousPersistTime) 
   {
     lidarSuspiciousPersistent = false; // reset after 3 seconds of normal readings
   }
   
   if (accelSuspicious) 
   {
     accelSuspiciousPersistent = true;
     lastSuspiciousAccelTime = currentTime;
   } 
   else if (currentTime - lastSuspiciousAccelTime > suspiciousPersistTime) 
   {
     accelSuspiciousPersistent = false; // reset after 3 seconds of normal readings
   }
   
   // debug individual sensor suspicion - use persistent values
   Serial.print("Sensors suspicious: Light=");
   Serial.print(lightSuspiciousPersistent);
   Serial.print(", Lidar=");
   Serial.print(lidarSuspiciousPersistent);
   Serial.print(", Accel=");
   Serial.print(accelSuspiciousPersistent);
   Serial.print(", SlowDoor=");
   Serial.println(slowDoorPatternDetected);
   
   // reset suspicion level to 0 initially
   int susLevel = 0;
   
   // tier 1: any single sensor showing suspicious activity
   if (lightSuspiciousPersistent || lidarSuspiciousPersistent || accelSuspiciousPersistent) 
   {
     susLevel = 1; // single sensor alert
   }
   
   // tier 2: any two sensors showing suspicious activity or a slow door pattern detected
   // count how many sensors are suspicious
   int suspiciousCount = 0;
   if (lightSuspiciousPersistent) 
   {
     suspiciousCount++;
   }
   if (lidarSuspiciousPersistent) 
   {
     suspiciousCount++;
   }
   if (accelSuspiciousPersistent) 
   {
     suspiciousCount++;
   }
   
   // only upgrade to level 2 if not a normal door opening
   if ((suspiciousCount >= 2 || slowDoorPatternDetected) && !normalDoorOpeningDetected) 
   {
     susLevel = 2; // multiple sensors or slow pattern detected
   }
   
   // tier 3 criteria check - improved logic
   bool level3Criteria = ((lightSuspiciousPersistent && lidarSuspiciousPersistent && accelSuspiciousPersistent) || 
                         (suspiciousCount >= 2 && sneakyIntrusion) || 
                         (slowDoorPatternDetected && cumulativeLidarChange > 20 && doorOpeningVelocity < 3.0)) && 
                         !normalDoorOpeningDetected;
   
   // first time reaching level 3 criteria, start debounce timer
   if (level3Criteria && level3DebounceTime == 0) 
   {
     level3DebounceTime = currentTime;
     susLevel = 2; // keep at level 2 until debounce period passes
     Serial.println("Potential level 3 alert - waiting for confirmation");
   }
   // if still meeting criteria and debounce period has passed, confirm level 3
   else if (level3Criteria && (currentTime - level3DebounceTime > LEVEL3_DEBOUNCE_PERIOD)) 
   {
     susLevel = 3; // confirmed high-risk intrusion
     Serial.println("Level 3 alert confirmed after debounce");
   }
   // if not meeting criteria anymore but timer was started, reset it
   else if (!level3Criteria && level3DebounceTime != 0) 
   {
     level3DebounceTime = 0;
     if (susLevel > 2) 
     {
       susLevel = 2; // downgrade from level 3 if needed
     }
     Serial.println("Level 3 criteria no longer met, resetting timer");
   }
   
   // force level 3 for clear intrusion attempts - direct override
   if (slowDoorPatternDetected && cumulativeLidarChange > 25 && doorOpeningVelocity < 2.0 && 
       (currentTime - patternStartTime > 5000)) 
   {
     susLevel = 3; // this is definitely a sneaky intrusion - force level 3
     Serial.println("FORCED LEVEL 3: Definite sneaky intrusion detected");
   }
   
   // if normal activity is detected, cap the suspicion level at 1
   if (normalDoorOpeningDetected && susLevel > 1) 
   {
     susLevel = 1; // reduce suspicion for normal door activity
     Serial.println("Suspicion level capped at 1 due to normal door activity pattern");
   }
   
   // update the current suspicion level if it changed
   if (susLevel != currentSuspicionLevel) 
   {
     currentSuspicionLevel = susLevel;
     updateDisplay();
     notificationSent = false; // reset flag when level changes
   }
   
   // handle suspicion level actions
   if (susLevel > 0) 
   {
     // record all events (all levels) to the cloud
     sendAlertToCloud(susLevel, currentAccelMagnitude, currentLidar, currentLight);
     
     // for level 3, trigger the alarm if enabled
     if (susLevel == 3 && !notificationSent) 
     {
       // send the notification only once per event
       sendAlertToCloud(susLevel, currentAccelMagnitude, currentLidar, currentLight);
       notificationSent = true;
       
       // display alert on tft
       tft.fillScreen(TFT_RED); // flash the screen
       delay(200);
       tft.fillScreen(TFT_BACKGROUND);
       
       // redraw the interface
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
   
   // update display with current sensor values periodically
   if (currentTime - lastDisplayUpdateTime >= displayUpdateInterval) 
   {
     lastDisplayUpdateTime = currentTime;
     updateSensorValues(currentLight, currentLidar, currentAccelMagnitude);
   }
   
   // control the buzzer based on suspicion level and alarm settings
   controlBuzzer(alarmEnabled, susLevel);
   
   // send ble update
   sendSecurityData();
   
   // debug output
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
   Serial.print(currentAccelMagnitude);
   Serial.print(" (Δ");
   Serial.print(accelChangeRate);
   Serial.println(")");
   
   // save current readings for next comparison
   lastLight = currentLight;
   lastLidar = currentLidar;
   lastAccelMagnitude = currentAccelMagnitude;
   
   // check for commands from server
   if (currentTime - lastCommandCheckTime >= commandCheckInterval) 
   {
     lastCommandCheckTime = currentTime;
     checkForCommands();
   }
   
   // short delay
   delay(200);
 }
 
 // check for commands from the server
 void checkForCommands() 
 {
   if (WiFi.status() == WL_CONNECTED) 
   {
     WiFiClient client;
     HttpClient http(client);
     
     // create a device id (you could use esp32's mac address or a custom id)
     String deviceId = "door_explorer_" + WiFi.macAddress();
     deviceId.replace(":", ""); // remove colons from mac address
     
     // create the query parameters
     String path = "/api/device_commands?device_id=" + deviceId;
     
     Serial.print("Checking for commands: ");
     Serial.println(path);
     
     // send the request
     int err = http.get(serverAddress, serverPort, path.c_str());
     if (err == 0) 
     {
       int statusCode = http.responseStatusCode();
       
       if (statusCode == 200) 
       {
         // read the response
         String response = "";
         while (client.available()) 
         {
           response += (char)client.read();
         }
         
         Serial.print("Command response: ");
         Serial.println(response);
         
         // parse the json response
         // this is a simple parser - in a real app, use arduinojson library
         if (response.indexOf("RESET") != -1) 
         {
           Serial.println("Received RESET command from server");
           // reset the security alert and alarm
           currentSuspicionLevel = 0;
           notificationSent = false;
           alarmTriggered = false;
           
           // reset persistent suspicious flags
           lightSuspiciousPersistent = false;
           lidarSuspiciousPersistent = false;
           accelSuspiciousPersistent = false;
           
           // reset slow door detection
           slowDoorPatternDetected = false;
           cumulativeLidarChange = 0;
           directionEstablished = false;
           normalDoorOpeningDetected = false;
           level3DebounceTime = 0;
           sneakyIntrusion = false;
           
           // update display
           updateDisplay();
           
           // turn off buzzer
           ledcWrite(0, 0);
           
           // clear alert and return to main screen
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
         else if (response.indexOf("ON") != -1) 
         {
           Serial.println("Received ALARM ON command from server");
           alarmEnabled = true;
           tft.fillRect(20, 140, 200, 20, TFT_BACKGROUND);
           tft.setTextColor(TFT_HIGHLIGHT);
           tft.setCursor(20, 140);
           tft.println("Alarm: ON");
         }
         else if (response.indexOf("OFF") != -1) 
         {
           Serial.println("Received ALARM OFF command from server");
           alarmEnabled = false;
           alarmTriggered = false;
           tft.fillRect(20, 140, 200, 20, TFT_BACKGROUND);
           tft.setTextColor(TFT_WARNING);
           tft.setCursor(20, 140);
           tft.println("Alarm: OFF");
           ledcWrite(0, 0);
         }
       } 
       else 
       {
         Serial.print("HTTP Error: ");
         Serial.println(statusCode);
       }
     } 
     else 
     {
       Serial.print("Connection error: ");
       Serial.println(err);
     }
     
     http.stop();
   }
 }