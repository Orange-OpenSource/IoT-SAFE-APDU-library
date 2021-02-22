/*
 * Copyright (C) 2021 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file   Azure_IoT_Hub_Arduino_MKR1500NB.ino
 * @brief  Advanced Arduino IoT SAFE which use a preloaded key and certificate to
 *         connect to Azure IoT Hub.
 */

#include <ArduinoBearSSL.h>
#include <ArduinoMqttClient.h>
#include <MKRNB.h>

#include "arduino_secrets.h"
#include "IoTSAFE.h"

/////// Enter your sensitive data in arduino_secrets.h
const char pinnumber[]   = SECRET_PINNUMBER;
const char broker[]      = SECRET_BROKER;
String     deviceId;

// Use a custom AID
static const uint8_t IOT_SAFE_CUSTOM_AID[] = {
  0xA0, 0x00, 0x00, 0x02, 0x48, 0x04, 0x00
};

// Define the private key ID inside the IoT SAFE applet
static const uint8_t IOT_SAFE_PRIVATE_KEY_ID[] = { 0x01 };
// Define the certificate file ID inside the IoT SAFE applet
static const uint8_t IOT_SAFE_CLIENT_CERTIFICATE_FILE_ID[] = { 0x02 };

NB nbAccess;
GPRS gprs;
NBModem modem;
IoTSAFE iotSAFE(IOT_SAFE_CUSTOM_AID, sizeof(IOT_SAFE_CUSTOM_AID));
IoTSAFECertificate client_certificate;

NBClient      nbClient;            // Used for the TCP socket connection
BearSSLClient sslClient(nbClient); // Used for SSL/TLS connection
MqttClient    mqttClient(sslClient);

unsigned long lastMillis = 0;

size_t iot_safe_sign(const br_ec_impl *impl, const br_hash_class *hf,
  const void *hash_value, const br_ec_private_key *sk, void *sig)
{
  return iotSAFE.sign(IOT_SAFE_PRIVATE_KEY_ID, sizeof(IOT_SAFE_PRIVATE_KEY_ID),
    impl, hf, hash_value, sk, sig);
}

void setup() {
  SerialUSB.begin(115200);
  while (!SerialUSB);

  // start modem test (reset and check response)
  SerialUSB.print("Starting modem test...");
  if (modem.begin()) {
    SerialUSB.println("modem.begin() succeeded");
  } else {
    SerialUSB.println("ERROR, no modem answer.");
  }

  // Set a callback to get the current time
  // used to validate the servers certificate
  ArduinoBearSSL.onGetTime(getTime);

  // Set the message callback, this function is
  // called when the MQTTClient receives a message
  mqttClient.onMessage(onMessageReceived);
}

void loop() {
  if (nbAccess.status() != NB_READY || gprs.status() != GPRS_READY) {
    connectNB();
  }

  if (!mqttClient.connected()) {
    // MQTT client is disconnected, connect
    connectMQTT();
  }

  // poll for new MQTT messages and send keep alives
  mqttClient.poll();

  // publish a message roughly every 5 seconds.
  if (millis() - lastMillis > 5000) {
    lastMillis = millis();

    publishMessage();
  }
}

unsigned long getTime() {
  // get the current time from the cellular module
  return nbAccess.getTime();
}

void connectNB() {
  SerialUSB.println("Attempting to connect to the cellular network");

  while ((nbAccess.begin(pinnumber) != NB_READY) ||
         (gprs.attachGPRS() != GPRS_READY)) {
    // failed, retry
    SerialUSB.print(".");
    delay(1000);
  }

  SerialUSB.println("You're connected to the cellular network");
  SerialUSB.println();
}

void connectMQTT() {
  SerialUSB.print("Attempting to connect to MQTT broker: ");
  SerialUSB.print(broker);
  SerialUSB.println(" ");

  while (true) {
    // OBKG process can be triggered by OTA and can take some time on the applet as:
    // - a new key pair must be generated,
    // - the CSR must be send through OTA
    // - the certificate must be send back by OTA
    SerialUSB.println("Waiting 10 seconds to let time for the IoT SAFE OBKG process");
    delay(10000);
    client_certificate =
      iotSAFE.readCertificate(IOT_SAFE_CLIENT_CERTIFICATE_FILE_ID,
        sizeof(IOT_SAFE_CLIENT_CERTIFICATE_FILE_ID));
    sslClient.setEccCert(client_certificate.getCertificate());
    sslClient.setEccSign(iot_safe_sign);
    deviceId = client_certificate.getCertificateCommonName();

    // Set the client id used for MQTT as the device id
    mqttClient.setId(deviceId);

    // Set the username to "<broker>/<device id>/?api-version=2018-06-30" and empty password
    String username;

    username += broker;
    username += "/";
    username += deviceId;
    username += "/?api-version=2018-06-30";

    mqttClient.setUsernamePassword(username, "");

    if (!mqttClient.connect(broker, 8883)) {
      SerialUSB.println("Unable to connect, retry in 10 seconds");
      SerialUSB.println(mqttClient.connectError());
    } else
      break;
  }
  SerialUSB.println();

  SerialUSB.println("You're connected to the MQTT broker");
  SerialUSB.println();

  // subscribe to a topic
  mqttClient.subscribe("devices/" + deviceId + "/messages/devicebound/#");
}

void publishMessage() {
  SerialUSB.println("Publishing message");

  // send message, the Print interface can be used to set the message contents
  mqttClient.beginMessage("devices/" + deviceId + "/messages/events/");
  mqttClient.print("hello ");
  mqttClient.print(millis());
  mqttClient.endMessage();
}

void onMessageReceived(int messageSize) {
  // we received a message, print out the topic and contents
  SerialUSB.print("Received a message with topic '");
  SerialUSB.print(mqttClient.messageTopic());
  SerialUSB.print("', length ");
  SerialUSB.print(messageSize);
  SerialUSB.println(" bytes:");

  // use the Stream interface to print the contents
  while (mqttClient.available()) {
    SerialUSB.print((char)mqttClient.read());
  }
  SerialUSB.println();

  SerialUSB.println();
}
