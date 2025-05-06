# Door the Explorer - Smart Door Alert System

CS 596: IoT Software and Systems – Final Project

### Team Members:

* **Genesis Anne Villar** (RedID: 824435476)
  Email: [gvillar7974@sdsu.edu](mailto:gvillar7974@sdsu.edu)
* **Steven Gervacio** (RedID: 825656527)
  Email: [sgervacio7160@sdsu.edu](mailto:sgervacio7160@sdsu.edu)

Instructor: **Prof. Donyanavard**
Semester: **Spring 2025**

---

## Project Overview

**Door the Explorer** is an affordable, intelligent IoT-based security solution designed to detect unauthorized door access and provide real-time alerts and insightful analytics. Motivated by personal experiences with shared living spaces and the high cost of traditional security systems, our project offers a practical, cost-friendly alternative using advanced sensor fusion and cloud-based analytics.

Full Project Report: [Download PDF](Final_Report_CS596_IOT_VILLAR_GERVACIO.pdf)

---

## Features

* Multi-tier security system using sensor fusion
* Real-time alerts via WiFi & email notifications
* Cloud recording of security events (AWS Integration)
* BLE monitoring and remote control interface
* Customizable security thresholds
* Advanced intrusion detection:

  * Normal door activity recognition
  * Slow door opening detection
  * Sneaky intrusion detection
* Persistent state tracking and debounce protection to minimize false positives
* Cloud analytics and visualization dashboard:

  * Alert Level Distribution
  * Sensor Value Trends
  * Anomaly Detection
  * Sensor Activity Correlation
  * Hourly Alert Distribution

---

## System Architecture

Our system follows a sophisticated multi-layered architecture:

### Sensing Layer:

* **LiDAR Sensor (TF-LUNA)**: Measures door distance.
* **Accelerometer/Gyroscope (LSM6DSO)**: Detects movement patterns.
* **Light Sensor (Photoresistor/LDR)**: Monitors environmental lighting conditions.

### Processing Layer:

* **TTGO Lily Display (ESP32)**: Performs local sensor data processing, real-time pattern recognition, and initial anomaly detection.

### Communication Layer:

* **Wi-Fi**: Secure data transmission to AWS cloud.
* **Bluetooth Low Energy (BLE)**: Direct communication and monitoring through mobile devices.

### Cloud & User Interface:

* **AWS EC2 Flask Server**: Cloud backend for data storage, analytics, and real-time alerts.
* **Web-based Dashboard**: Visualizes analytics and historical data insights.

## Circuit Diagram

A top-down view of the circuit diagram is provided below:

![Circuit Diagram](top_down.jpg)

### Pin Connections:

* **LiDAR**: UART pins (GPIO 13 RX, GPIO 15 TX)
* **Accelerometer/Gyroscope**: I2C (GPIO 21 SDA, GPIO 22 SCL)
* **Photoresistor (LDR)**: Analog input (GPIO 36)
* **Buzzer**: PWM (GPIO 26)

---

## Software Implementation

* **Wi-Fi & BLE Integration**: Real-time remote monitoring and control.
* **Real-Time Analytics**: Detection of abnormal activities using accelerometer and LiDAR data.
* **Email Notifications**: Instant security alerts.
* **Cloud Data Visualization**: Comprehensive AWS-hosted analytics dashboard.
* **Security Alert Levels**:

  * Level 1: Single sensor anomaly.
  * Level 2: Multiple sensors anomaly or slow door opening detected.
  * Level 3: Confirmed intrusion patterns.
---

## Source Code

* GitHub Repository: [Door the Explorer - Source Code](https://github.com/stevengervacio/CS-596-IOT-FINALPROJECT)

---

## Video Demonstration

* [Watch Demonstration Video](https://www.youtube.com/watch?v=OIBaBByA4Hg)

---

## Project Report

Complete documentation can be accessed here:

[📄 Final Project Report (PDF)](Final_Report_CS596_IOT_VILLAR_GERVACIO.pdf)

---

© Genesis Anne Villar & Steven Gervacio | CS 596 IoT Systems – SDSU | Spring 2025
