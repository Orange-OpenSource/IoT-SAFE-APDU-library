/*
 * Copyright (C) 2021 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file   AWS_IoT_Arduino_MKR1500NB.ino
 * @brief  Advanced Arduino IoT SAFE which use a preloaded key and certificate to
 *         connect to AWS IoT Core.
 */

#include <ArduinoBearSSL.h>
#include <ArduinoMqttClient.h>
#include <MKRNB.h>

#include "arduino_secrets.h"
#include "IoTSAFE.h"

/////// Enter your sensitive data in arduino_secrets.h
const char pinnumber[]     = SECRET_PINNUMBER;
const char broker[]        = SECRET_BROKER;

// Use a custom AID
static const uint8_t IOT_SAFE_CUSTOM_AID[] = {
  0xA0, 0x00, 0x00, 0x02, 0x48, 0x04, 0x00
};

// Define the private key ID inside the IoT SAFE applet
static const uint8_t IOT_SAFE_PRIVATE_KEY_ID[] = { 0x01 };
// Define the client certificate file ID inside the IoT SAFE applet
static const uint8_t IOT_SAFE_CLIENT_CERTIFICATE_FILE_ID[] = { 0x02 };
// Define the CA certificate file ID inside the IoT SAFE applet
static const uint8_t IOT_SAFE_CA_CERTIFICATE_FILE_ID[] = { 0x03 };

NB nbAccess;
GPRS gprs;
NBModem modem;
IoTSAFE iotSAFE(IOT_SAFE_CUSTOM_AID, sizeof(IOT_SAFE_CUSTOM_AID));
IoTSAFECertificate client_certificate;
IoTSAFECertificate root_ca_certificate;

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
  SERIAL_PORT_MONITOR.begin(115200);
  while (!SERIAL_PORT_MONITOR);

  // start modem test (reset and check response)
  SERIAL_PORT_MONITOR.print("Starting modem test...");
  if (modem.begin()) {
    SERIAL_PORT_MONITOR.println("modem.begin() succeeded");
  } else {
    SERIAL_PORT_MONITOR.println("ERROR, no modem answer.");
  }

  // Set a callback to get the current time
  // used to validate the servers certificate
  ArduinoBearSSL.onGetTime(getTime);

  sslClient.setEccSign(iot_safe_sign);

  // Optional, set the client id used for MQTT,
  // each device that is connected to the broker
  // must have a unique client id. The MQTTClient will generate
  // a client id for you based on the millis() value if not set
  //
  // mqttClient.setId("clientId");

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
  // get the current time from the NB module
  return nbAccess.getTime();
}

void connectNB() {
  SERIAL_PORT_MONITOR.println("Attempting to connect to the cellular network");

  while ((nbAccess.begin(pinnumber) != NB_READY) ||
         (gprs.attachGPRS() != GPRS_READY)) {
    // failed, retry
    SERIAL_PORT_MONITOR.print(".");
    delay(1000);
  }

  SERIAL_PORT_MONITOR.println("You're connected to the cellular network");
  SERIAL_PORT_MONITOR.println();
}

void connectMQTT() {
  SERIAL_PORT_MONITOR.print("Attempting to connect to MQTT broker: ");
  SERIAL_PORT_MONITOR.print(broker);
  SERIAL_PORT_MONITOR.println(" ");

  while (true) {
    // OBKG process can be triggered by OTA and can take some time on the applet as:
    // - a new key pair must be generated,
    // - the CSR must be send through OTA
    // - the certificate must be send back by OTA
    SERIAL_PORT_MONITOR.println("Waiting 10 seconds to let time for the IoT SAFE OBKG process");
    delay(10000);
    client_certificate =
      iotSAFE.readCertificate(IOT_SAFE_CLIENT_CERTIFICATE_FILE_ID,
        sizeof(IOT_SAFE_CLIENT_CERTIFICATE_FILE_ID));

    root_ca_certificate =
      iotSAFE.readCertificate(IOT_SAFE_CA_CERTIFICATE_FILE_ID,
        sizeof(IOT_SAFE_CA_CERTIFICATE_FILE_ID));

    br_x509_certificate br_chain[2];
    br_chain[0] = client_certificate.getCertificate();
    br_chain[1] = root_ca_certificate.getCertificate();
    sslClient.setEccChain(br_chain, 2);
    if (!mqttClient.connect(broker, 8883)) {
      SERIAL_PORT_MONITOR.println("Unable to connect, retry in 10 seconds");
      SERIAL_PORT_MONITOR.println(mqttClient.connectError());
    } else
      break;
  }
  SERIAL_PORT_MONITOR.println();

  SERIAL_PORT_MONITOR.println("You're connected to the MQTT broker");
  SERIAL_PORT_MONITOR.println();

  // subscribe to a topic
  mqttClient.subscribe("arduino/incoming");
}

void publishMessage() {
  SERIAL_PORT_MONITOR.println("Publishing message");

  // send message, the Print interface can be used to set the message contents
  mqttClient.beginMessage("arduino/outgoing");
  mqttClient.print("hello ");
  mqttClient.print(millis());
  mqttClient.endMessage();
}

void onMessageReceived(int messageSize) {
  // we received a message, print out the topic and contents
  SERIAL_PORT_MONITOR.print("Received a message with topic '");
  SERIAL_PORT_MONITOR.print(mqttClient.messageTopic());
  SERIAL_PORT_MONITOR.print("', length ");
  SERIAL_PORT_MONITOR.print(messageSize);
  SERIAL_PORT_MONITOR.println(" bytes:");

  // use the Stream interface to print the contents
  while (mqttClient.available()) {
    SERIAL_PORT_MONITOR.print((char)mqttClient.read());
  }
  SERIAL_PORT_MONITOR.println();

  SERIAL_PORT_MONITOR.println();
}
