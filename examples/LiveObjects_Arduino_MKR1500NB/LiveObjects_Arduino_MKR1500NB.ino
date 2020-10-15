/*
 * Copyright (C) 2020 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file   Arduino_MKR1500NB.ino
 * @brief  Advanced Arduino IoT SAFE which use a preloaded key and certificate to
 *         connect to LiveObjects.
 */

#define DEFAULT_TX_FREQUENCY 60

#include "arduino_secrets.h"
#include <ArduinoBearSSL.h>
#include <ArduinoMqttClient.h>
#include <ArduinoJson.h>
#include <MKRNB.h>

// Comment to disable Ethernet and use cellular connection (untested for now)
#define ETHERNET_ENABLED

#include "IoTSAFE.h"

// Use a custom AID
static const uint8_t IOT_SAFE_CUSTOM_AID[] = {
  0xA0, 0x00, 0x00, 0x02, 0x48, 0x04, 0x00
};

// Define the private key ID inside the IoT SAFE applet
static const uint8_t IOT_SAFE_PRIVATE_KEY_ID[] = { 0x01 };
// Define the certificate file ID inside the IoT SAFE applet
static const uint8_t IOT_SAFE_CLIENT_CERTIFICATE_FILE_ID[] = { 0x02 };

const char mqtt_user[] = SECRET_MQTTUSER;
const char mqtt_pass[] = SECRET_MQTTPASS;

const char mqtt_broker[] = "liveobjects.orange-business.com";
int mqtt_port = 8883;

const char mqtt_pubdata[] = "dev/data";
const char mqtt_pubcfg[] = "dev/cfg";
const char mqtt_subcfg[] = "dev/cfg/upd";

const char* JSONdata = "{\"model\":\"github_sample_MKR\",\"value\":{\"uptime\":0}}";
const char* JSONcfg= "{\"cfg\":{\"transmit frequency (s)\":{\"t\":\"u32\",\"v\":0}}}";

uint32_t transmissionFrequency = DEFAULT_TX_FREQUENCY * 1000;
uint32_t lastTransmission = DEFAULT_TX_FREQUENCY * 1000;

uint32_t uptimeInSec = 0;

StaticJsonDocument<350> payload;

// Live Objects certificate (because certificate is validated by Rich OS)
static const unsigned char TA0_DN[] = {
  0x30, 0x61, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
  0x02, 0x55, 0x53, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0A,
  0x13, 0x0C, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49,
  0x6E, 0x63, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13,
  0x10, 0x77, 0x77, 0x77, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72,
  0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x20, 0x30, 0x1E, 0x06, 0x03, 0x55,
  0x04, 0x03, 0x13, 0x17, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74,
  0x20, 0x47, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x20, 0x52, 0x6F, 0x6F, 0x74,
  0x20, 0x43, 0x41
};

static const unsigned char TA0_RSA_N[] = {
  0xE2, 0x3B, 0xE1, 0x11, 0x72, 0xDE, 0xA8, 0xA4, 0xD3, 0xA3, 0x57, 0xAA,
  0x50, 0xA2, 0x8F, 0x0B, 0x77, 0x90, 0xC9, 0xA2, 0xA5, 0xEE, 0x12, 0xCE,
  0x96, 0x5B, 0x01, 0x09, 0x20, 0xCC, 0x01, 0x93, 0xA7, 0x4E, 0x30, 0xB7,
  0x53, 0xF7, 0x43, 0xC4, 0x69, 0x00, 0x57, 0x9D, 0xE2, 0x8D, 0x22, 0xDD,
  0x87, 0x06, 0x40, 0x00, 0x81, 0x09, 0xCE, 0xCE, 0x1B, 0x83, 0xBF, 0xDF,
  0xCD, 0x3B, 0x71, 0x46, 0xE2, 0xD6, 0x66, 0xC7, 0x05, 0xB3, 0x76, 0x27,
  0x16, 0x8F, 0x7B, 0x9E, 0x1E, 0x95, 0x7D, 0xEE, 0xB7, 0x48, 0xA3, 0x08,
  0xDA, 0xD6, 0xAF, 0x7A, 0x0C, 0x39, 0x06, 0x65, 0x7F, 0x4A, 0x5D, 0x1F,
  0xBC, 0x17, 0xF8, 0xAB, 0xBE, 0xEE, 0x28, 0xD7, 0x74, 0x7F, 0x7A, 0x78,
  0x99, 0x59, 0x85, 0x68, 0x6E, 0x5C, 0x23, 0x32, 0x4B, 0xBF, 0x4E, 0xC0,
  0xE8, 0x5A, 0x6D, 0xE3, 0x70, 0xBF, 0x77, 0x10, 0xBF, 0xFC, 0x01, 0xF6,
  0x85, 0xD9, 0xA8, 0x44, 0x10, 0x58, 0x32, 0xA9, 0x75, 0x18, 0xD5, 0xD1,
  0xA2, 0xBE, 0x47, 0xE2, 0x27, 0x6A, 0xF4, 0x9A, 0x33, 0xF8, 0x49, 0x08,
  0x60, 0x8B, 0xD4, 0x5F, 0xB4, 0x3A, 0x84, 0xBF, 0xA1, 0xAA, 0x4A, 0x4C,
  0x7D, 0x3E, 0xCF, 0x4F, 0x5F, 0x6C, 0x76, 0x5E, 0xA0, 0x4B, 0x37, 0x91,
  0x9E, 0xDC, 0x22, 0xE6, 0x6D, 0xCE, 0x14, 0x1A, 0x8E, 0x6A, 0xCB, 0xFE,
  0xCD, 0xB3, 0x14, 0x64, 0x17, 0xC7, 0x5B, 0x29, 0x9E, 0x32, 0xBF, 0xF2,
  0xEE, 0xFA, 0xD3, 0x0B, 0x42, 0xD4, 0xAB, 0xB7, 0x41, 0x32, 0xDA, 0x0C,
  0xD4, 0xEF, 0xF8, 0x81, 0xD5, 0xBB, 0x8D, 0x58, 0x3F, 0xB5, 0x1B, 0xE8,
  0x49, 0x28, 0xA2, 0x70, 0xDA, 0x31, 0x04, 0xDD, 0xF7, 0xB2, 0x16, 0xF2,
  0x4C, 0x0A, 0x4E, 0x07, 0xA8, 0xED, 0x4A, 0x3D, 0x5E, 0xB5, 0x7F, 0xA3,
  0x90, 0xC3, 0xAF, 0x27
};

static const unsigned char TA0_RSA_E[] = {
  0x01, 0x00, 0x01
};

static const unsigned char TA1_DN[] = {
  0x30, 0x81, 0x84, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
  0x13, 0x02, 0x46, 0x52, 0x31, 0x11, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x04,
  0x08, 0x0C, 0x08, 0x42, 0x72, 0x65, 0x74, 0x61, 0x67, 0x6E, 0x65, 0x31,
  0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x06, 0x52, 0x65,
  0x6E, 0x6E, 0x65, 0x73, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04,
  0x0A, 0x0C, 0x06, 0x4F, 0x72, 0x61, 0x6E, 0x67, 0x65, 0x31, 0x14, 0x30,
  0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0B, 0x45, 0x43, 0x43, 0x5F,
  0x52, 0x4F, 0x4F, 0x54, 0x5F, 0x43, 0x41, 0x31, 0x2A, 0x30, 0x28, 0x06,
  0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x1B,
  0x66, 0x61, 0x62, 0x72, 0x69, 0x63, 0x65, 0x2E, 0x66, 0x6F, 0x6E, 0x74,
  0x61, 0x69, 0x6E, 0x65, 0x40, 0x6F, 0x72, 0x61, 0x6E, 0x67, 0x65, 0x2E,
  0x63, 0x6F, 0x6D
};

static const unsigned char TA1_EC_Q[] = {
  0x04, 0x08, 0x09, 0x21, 0x06, 0xF1, 0x7D, 0xFC, 0x2E, 0x43, 0xEA, 0xE0,
  0x8C, 0x1F, 0x6D, 0x31, 0x99, 0x65, 0xBE, 0xA3, 0x43, 0x51, 0xC1, 0x5D,
  0xFB, 0xB6, 0xF5, 0x24, 0x2A, 0xF3, 0x68, 0x85, 0xAA, 0xDB, 0x35, 0x83,
  0x9F, 0xDF, 0x76, 0x8E, 0x77, 0xE6, 0xB2, 0x16, 0xCF, 0xEE, 0xE0, 0xE9,
  0x53, 0xDF, 0x15, 0x8B, 0x95, 0xD3, 0x41, 0xC7, 0x07, 0x36, 0x55, 0x15,
  0x41, 0x93, 0x49, 0x54, 0x71
};

static const br_x509_trust_anchor TAs[1] = {
  {
    { (unsigned char *)TA0_DN, sizeof TA0_DN },
    BR_X509_TA_CA,
    {
      BR_KEYTYPE_RSA,
      { .rsa = {
        (unsigned char *)TA0_RSA_N, sizeof TA0_RSA_N,
        (unsigned char *)TA0_RSA_E, sizeof TA0_RSA_E,
      } }
    }
  }
};


#ifdef ETHERNET_ENABLED
#include <Ethernet.h>
#include <EthernetUdp.h>

unsigned int localPort = 8888;       // local port to listen for UDP packets

const char timeServer[] = "time.nist.gov"; // time.nist.gov NTP server

const int NTP_PACKET_SIZE = 48; // NTP time stamp is in the first 48 bytes of the message

byte packetBuffer[NTP_PACKET_SIZE]; // buffer to hold incoming and outgoing packets

// A UDP instance to let us send and receive packets over UDP
EthernetUDP Udp;

EthernetClient nbClient;
byte mac[] = { 0x90, 0xA2, 0xDA, 0x0E, 0xA5, 0x7E };
#else
GPRS gprs;
NBClient nbClient;
#endif

NBModem modem;
NB nbAccess;
IoTSAFE iotSAFE(IOT_SAFE_CUSTOM_AID, sizeof(IOT_SAFE_CUSTOM_AID));
BearSSLClient sslClient(nbClient,TAs,1);
MqttClient mqttClient(sslClient);

void connectionManager(bool _way);

size_t iot_safe_sign(const br_ec_impl *impl, const br_hash_class *hf,
  const void *hash_value, const br_ec_private_key *sk, void *sig)
{
  return iotSAFE.sign(IOT_SAFE_PRIVATE_KEY_ID, sizeof(IOT_SAFE_PRIVATE_KEY_ID),
    impl, hf, hash_value, sk, sig);
}

#ifdef ETHERNET_ENABLED
// send an NTP request to the time server at the given address
void sendNTPpacket(const char * address) {
  // set all bytes in the buffer to 0
  memset(packetBuffer, 0, NTP_PACKET_SIZE);
  // Initialize values needed to form NTP request
  // (see URL above for details on the packets)
  packetBuffer[0] = 0b11100011;   // LI, Version, Mode
  packetBuffer[1] = 0;     // Stratum, or type of clock
  packetBuffer[2] = 6;     // Polling Interval
  packetBuffer[3] = 0xEC;  // Peer Clock Precision
  // 8 bytes of zero for Root Delay & Root Dispersion
  packetBuffer[12]  = 49;
  packetBuffer[13]  = 0x4E;
  packetBuffer[14]  = 49;
  packetBuffer[15]  = 52;

  // all NTP fields have been given values, now
  // you can send a packet requesting a timestamp:
  Udp.beginPacket(address, 123); // NTP requests are to port 123
  Udp.write(packetBuffer, NTP_PACKET_SIZE);
  Udp.endPacket();
}
#endif

unsigned long getTime() {
#ifdef ETHERNET_ENABLED
  Serial.println("Getting time from NTP...");
  sendNTPpacket(timeServer); // send an NTP packet to a time server
   
  // wait to see if a reply is available
  delay(1000);
  if (Udp.parsePacket()) {
    // We've received a packet, read the data from it
    Udp.read(packetBuffer, NTP_PACKET_SIZE); // read the packet into the buffer

    // the timestamp starts at byte 40 of the received packet and is four bytes,
    // or two words, long. First, extract the two words:

    unsigned long highWord = word(packetBuffer[40], packetBuffer[41]);
    unsigned long lowWord = word(packetBuffer[42], packetBuffer[43]);
    // combine the four bytes (two words) into a long integer
    // this is NTP time (seconds since Jan 1 1900):
    unsigned long secsSince1900 = highWord << 16 | lowWord;
    
    // now convert NTP time into everyday time:
    // Unix time starts on Jan 1 1970. In seconds, that's 2208988800:
    const unsigned long seventyYears = 2208988800UL;
    // subtract seventy years:
    unsigned long epoch = secsSince1900 - seventyYears;
    return epoch;
  }
#else
  Serial.println("Getting time from the cellular module...");
  // get the current time from the cellular module
  return nbAccess.getTime();
#endif
}

void setup() {
  Serial.begin(9600);
  while (!Serial);

  // start modem test (reset and check response)
  Serial.print("Starting modem test...");
  if (modem.begin()) {
    Serial.println("modem.begin() succeeded");
  } else {
    Serial.println("ERROR, no modem answer.");
  }

#ifdef ETHERNET_ENABLED
  // start Ethernet and UDP
  Serial.println("Starting Ethernet...");
  if (Ethernet.begin(mac) == 0) {
    Serial.println("Failed to configure Ethernet using DHCP");
    // Check for Ethernet hardware present
    if (Ethernet.hardwareStatus() == EthernetNoHardware) {
      Serial.println("Ethernet shield was not found.  Sorry, can't run without hardware. :(");
    } else if (Ethernet.linkStatus() == LinkOFF) {
      Serial.println("Ethernet cable is not connected.");
    }
    // no point in carrying on, so do nothing forevermore:
    while (true) {
      delay(1);
    }
  }

  Serial.println("Starting UDP...");
  Udp.begin(localPort);
#endif
  // Set a callback to get the current time
  // used to validate the servers certificate
  ArduinoBearSSL.onGetTime(getTime);

  br_x509_certificate br_client_certificate =
    iotSAFE.readClientCertificate(IOT_SAFE_CLIENT_CERTIFICATE_FILE_ID,
      sizeof(IOT_SAFE_CLIENT_CERTIFICATE_FILE_ID));
  sslClient.setEccCert(br_client_certificate);
  sslClient.setEccSign(iot_safe_sign);

  mqttClient.setId(iotSAFE.getClientCertificateCommonName());
  mqttClient.setUsernamePassword(mqtt_user, mqtt_pass);
  mqttClient.onMessage(onMessageReceived);

  connectionManager(1);
  updateConfig();
}

void loop() {
  if (millis() - lastTransmission > transmissionFrequency) {
    // get data from sensors
    Serial.println("Sampling data");
    sampleData();

    // connect and send data to Live Objects
    Serial.println("Sending data to Live Objects");
#ifdef ETHERNET_ENABLED
    if (!mqttClient.connected())
#else
    if (nbAccess.status() != NB_READY || gprs.status() != GPRS_READY || !mqttClient.connected())
#endif
      connectionManager(1);

    sendData();
  }

    delay (1000);
    mqttClient.poll();
}

void connectionManager(bool _way = 1) {
  switch (_way) {
    case 1:
#ifndef ETHERNET_ENABLED
      Serial.println("Connecting to cellular network");
      while (nbAccess.begin(PIN_NUMBER) != NB_READY)
        Serial.print(".");
#endif

      Serial.println("\nYou're connected to the network");
      
      Serial.print("Connecting to MQTT broker '");
      Serial.print(mqtt_broker);
      Serial.print("'");
      
      while (!mqttClient.connect(mqtt_broker, mqtt_port))
        Serial.print(".");
      
      Serial.println("\nYou're connected to the MQTT broker");
      Serial.println();

      mqttClient.subscribe(mqtt_subcfg);
      mqttClient.poll();

      break;

    case 0:
      Serial.println("\nClosing MQTT connection...");
      mqttClient.stop();
      Serial.println("Disconnecting from cellular network...");
      nbAccess.shutdown();
      Serial.println("Offline.\n");
      break;
  }
}

void publishMessage(const char* topic, const char* _buffer) {
  Serial.print("Publishing message on topic '");
  mqttClient.beginMessage(topic);
  mqttClient.print(_buffer);
  mqttClient.endMessage();
  Serial.print(topic);
  Serial.println("':");
  Serial.println(_buffer);
}
  
void onMessageReceived(int messageSize) {
  String topic = mqttClient.messageTopic();
  Serial.print("Received a message with topic '");
  Serial.print(topic);
  Serial.println("':");

  char _buffer[300];
  
  byte i=0;
  while (mqttClient.available())
    _buffer[i++] = (char)mqttClient.read();
  _buffer[i]=0;
  Serial.println(_buffer);
  
  payload.clear();
  deserializeJson(payload, _buffer);

  if (topic == F("dev/cfg/upd"))
    updateConfig();
  else if (topic == F("dev/cmd"))
    //command();
    ;
}

void updateConfig() {
  if (payload.containsKey(F("cid"))) {
    if (payload[F("cfg")].containsKey(F("transmit frequency (s)"))) {
      transmissionFrequency = payload[F("cfg")][F("transmit frequency (s)")][F("v")].as<int>() * 1000;
      payload[F("cfg")][F("transmit frequency (s)")][F("v")] = transmissionFrequency / 1000;
    }
  }
  else {
    payload.clear();
    deserializeJson(payload, JSONcfg);
    payload[F("cfg")][F("transmit frequency (s)")][F("v")] = transmissionFrequency / 1000;
  }

  char _buffer[300];
  serializeJson(payload, _buffer);
  publishMessage(mqtt_pubcfg, _buffer);
}

void sampleData() {
  uptimeInSec = millis()/1000;
}

void sendData() {
  payload.clear();
  deserializeJson(payload, JSONdata);
 
  payload[F("value")][F("uptime")] = uptimeInSec;
  
  char _buffer[300];
  serializeJson(payload, _buffer);
  publishMessage(mqtt_pubdata, _buffer);
  lastTransmission = millis();
}
