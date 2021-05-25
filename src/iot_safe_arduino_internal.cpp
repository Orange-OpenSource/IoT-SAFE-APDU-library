/*
 * Copyright (C) 2020 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file iot_safe_arduino_internal.cpp
 * @brief IoT SAFE arduino internal functions.
 */

#if defined(ARDUINO)

#include <Arduino.h>
#if defined(ARDUINO_SAMD_MKRNB1500)
#include <MKRNB.h>
#elif defined(ARDUINO_SAMD_MKRGSM1400)
#include <MKRGSM.h>
#else
#define TINY_GSM_MODEM_SEQUANS_MONARCH
#include <TinyGsmClient.h>
extern TinyGsm modem;
#endif

#include <stdarg.h>
#include <stdio.h>

#include "iot_safe_arduino_internal.h"
#include "iot_safe_internal.h"

#define IOT_SAFE_MSG_TAG  0x5A

#define IOT_SAFE_MAX_MSG_SIZE     256 * 2
#define IOT_SAFE_TAIL_MSG_SIZE    5

static char _trace_str[IOT_SAFE_MAX_MSG_SIZE + IOT_SAFE_TAIL_MSG_SIZE];

void iot_safe_arduino_printf(char const *format, ...)
{
  va_list ap;
  va_start(ap, format);

  char *pt_str = _trace_str;
  char *end_str = _trace_str + IOT_SAFE_MAX_MSG_SIZE;

  *end_str = IOT_SAFE_MSG_TAG;

  // add user data
  pt_str += vsnprintf(pt_str, end_str - pt_str, format, ap);

  if (pt_str >= end_str) {
    // Truncated message
    pt_str = end_str - 1;
    *pt_str = 0;
  }

  if (*end_str != IOT_SAFE_MSG_TAG) {
    return;
  }

  SERIAL_PORT_MONITOR.print(_trace_str);
}

iot_safe_error_t iot_safe_arduino_sendAT(const char *at, uint8_t *response,
  uint16_t response_size, uint16_t *response_length)
{
  iot_safe_error_t error_code = IOT_SAFE_ERROR_UNKNOWN;
  String raw_response;
  String string_response;
  uint16_t string_response_length = 0;
  char byte[3];
  int posData = 0;
  // By default, consider that CSIM answer doesn't have quote
  uint8_t quote = 0;
  uint8_t csim_start = 0;

#if defined(ARDUINO_SAMD_MKRNB1500) || defined(ARDUINO_SAMD_MKRGSM1400)
  quote = 1;
  MODEM.sendf("AT+CSIM=%d,\"%s\"", strlen(at), at);
#else
  modem.sendAT("+CSIM=", strlen(at), ",\"", at, "\"");
#endif
  delay(100);
#if defined(ARDUINO_SAMD_MKRNB1500) || defined(ARDUINO_SAMD_MKRGSM1400)
  if (MODEM.waitForResponse(IOT_SAFE_AT_TIMER, &raw_response) == 1)
  {
    if (!raw_response.startsWith("+CSIM: "))
    {
      IOT_SAFE_DEBUG("Response does not start with +CSIM: (try again)\r\n");
      // Try again (Arduino MKR NB 1500 modem seems to have a bug)
      MODEM.waitForResponse(IOT_SAFE_AT_TIMER, &raw_response);
      /*if ((MODEM.waitForResponse(IOT_SAFE_AT_TIMER, &raw_response) != 1) ||
        !raw_response.startsWith("+CSIM: "))*/
        //return IOT_SAFE_ERROR_UNKNOWN;
    }
#else
  if (modem.waitResponse(IOT_SAFE_AT_TIMER, raw_response) == 1)
  {
#endif
    raw_response.replace("\r\nOK\r\n", "");
    raw_response.replace("\rOK\r", "");
    raw_response.replace("\r\n", "");
    raw_response.replace("\r", "");
    raw_response.trim();

    // Sequans seems to concatenate previous answers ...
    csim_start = raw_response.indexOf("+CSIM: ");
    string_response = raw_response.substring(csim_start);

    posData = string_response.indexOf(",");
    string_response_length = string_response.substring(7, posData).toInt();

    string_response.substring(string_response.length()-4-quote,
      string_response.length()-2-quote).toCharArray(byte, sizeof(byte));
    error_code = strtoul(byte, 0, 16) << 8;

    string_response.substring(string_response.length()-2-quote,
      string_response.length()-quote).toCharArray(byte, sizeof(byte));
    error_code |= strtoul(byte, 0, 16);

    posData = posData + 1 + quote;

    // Extract data if requested
    if (response_size > 0)
    {
      *response_length = 0;
      for (size_t count = 0; count < response_size; count++) {

        // Error code has already been parsed
        if (posData >= string_response.length()-4-quote)
          break;

        string_response.substring(posData, posData+2).toCharArray(byte,
          sizeof(byte));
        response[count] = strtoul(byte, 0, 16);
        IOT_SAFE_DEBUG("%02X ", response[count]);
        posData += 2;
        *response_length++;
      }
      IOT_SAFE_DEBUG("\r\n");
    }
  } else
  {
    IOT_SAFE_DEBUG("No response\r\n");
  }
  return error_code;
}

#endif
