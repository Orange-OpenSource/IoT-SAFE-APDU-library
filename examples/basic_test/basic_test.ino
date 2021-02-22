/*
 * Copyright (C) 2020 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file   basic_test.ino
 * @brief  Basic Arduino test sample
 */

#include <iot_safe.h>

#include <MKRNB.h>

NBModem modem;
NB nbAccess (true);

static const uint8_t IOT_SAFE_PRIVATE_KEY_ID[] = { 0x12, 0x34 };

static const uint8_t IOT_SAFE_PUBLIC_KEY_ID[] = { 0xAB, 0xCD };

static const uint8_t HASH_VALUE[] = {0xAB, 0xCD, 0xEF};

uint8_t FILE_ID[] = { 0x12, 0x34 };

static const unsigned char FILE_DATA[] = { 0xBB, 0xBB };

bool test_verify = true;
//bool test_verify = false;

//bool test_file = true;
bool test_file = false;

void iot_safe_test_verify()
{
  uint8_t channel = 0;
  uint8_t signature[256];
  uint16_t signature_length = 0;
  iot_safe_error_t ret;

  SerialUSB.println("\nEnter iot_safe_test_verify");

  memset(signature, 0, sizeof(signature));

  // Init communication channel
  iot_safe_init(IOT_SAFE_AID, sizeof(IOT_SAFE_AID), &channel);

  // Call iot_safe_get_object_list but don't display keys
  uint8_t number;
  iot_safe_get_object_list(channel, NULL, 0, &number, NULL, 0, &number, NULL, 0,
                           &number, NULL, 0, &number);

  // Sign
  iot_safe_sign(channel, IOT_SAFE_SIGNATURE_OPERATION_MODE_FULL_TEXT,
                IOT_SAFE_HASH_SHA_256, IOT_SAFE_SIGNATURE_ECDSA, IOT_SAFE_PRIVATE_KEY_ID,
                sizeof(IOT_SAFE_PRIVATE_KEY_ID), NULL, 0, HASH_VALUE, sizeof(HASH_VALUE),
                signature, sizeof(signature), &signature_length);

  // Verify
  ret = iot_safe_verify(channel, IOT_SAFE_SIGNATURE_OPERATION_MODE_FULL_TEXT,
                  IOT_SAFE_HASH_SHA_256, IOT_SAFE_SIGNATURE_ECDSA, IOT_SAFE_PUBLIC_KEY_ID,
                  sizeof(IOT_SAFE_PUBLIC_KEY_ID), NULL, 0, HASH_VALUE, sizeof(HASH_VALUE),
                  signature, signature_length);

  if (ret != IOT_SAFE_SUCCESS)
     SerialUSB.println("\nVerify failure\n");
  else
     SerialUSB.println("\nVerify success\n");
     
  iot_safe_finish(channel);
}

void iot_safe_test_file()
{
  uint8_t channel = 0;
  
  SerialUSB.println("\nEnter iot_safe_test_file");

  // Init communication channel
  iot_safe_init(IOT_SAFE_AID, sizeof(IOT_SAFE_AID), &channel);

  // Read file
  uint8_t read_data[sizeof(FILE_DATA)];
  memset(read_data, 0, sizeof(read_data));
  iot_safe_read_file(channel, FILE_ID, sizeof(FILE_ID), NULL, 0,
                     read_data, sizeof(read_data));

  iot_safe_finish(channel);
}

void setup() {
  SerialUSB.begin(9600);
  while (!SerialUSB);

  // start modem test (reset and check response)
  SerialUSB.print("Starting modem test...");
  if (modem.begin()) {
    SerialUSB.println("modem.begin() succeeded");
  } else {
    SerialUSB.println("ERROR, no modem answer.");
  }
  delay(5000);
}

void loop() {
  if (test_file)
    iot_safe_test_file();
  if (test_verify)
    iot_safe_test_verify();
  delay(10000);
}
