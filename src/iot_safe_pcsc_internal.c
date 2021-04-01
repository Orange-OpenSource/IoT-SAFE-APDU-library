/*
 * Copyright (C) 2020 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file   iot_safe_pcsc_internal.c
 * @brief  IoT SAFE PCSC internal functions
 */

#if !defined(ARDUINO)

#include "iot_safe_pcsc_internal.h"
#include "iot_safe_internal.h"

iot_safe_error_t iot_safe_pcsc_sendAPDU(uint8_t cla, uint8_t ins, uint8_t p1,
  uint8_t p2, uint8_t lc, const uint8_t *command, uint8_t le, uint8_t with_le,
  uint8_t *response, uint16_t response_size, uint16_t* response_length)
{
  iot_safe_error_t error_code = IOT_SAFE_ERROR_UNKNOWN;
  LONG rv;

  SCARDCONTEXT hContext;
  LPTSTR mszReaders;
  SCARDHANDLE hCard;
  DWORD dwReaders, dwActiveProtocol, dwRecvLength;

  SCARD_IO_REQUEST pioSendPci;
  BYTE pbRecvBuffer[IOT_SAFE_APDU_BUFFER_LEN];
  BYTE apdu_cmd[IOT_SAFE_APDU_BUFFER_LEN];
  uint8_t apdu_cmd_size = 0;

  uint8_t i = 0;
  memset(apdu_cmd, 0, sizeof(apdu_cmd));

  apdu_cmd[i] = cla;
  apdu_cmd[++i] = ins;
  apdu_cmd[++i] = p1;
  apdu_cmd[++i] = p2;

  if (lc > 0)
  {
    apdu_cmd[++i] = lc;
    memcpy(&apdu_cmd[++i], command, lc);
    i += lc;
  }

  if (with_le == 1)
    apdu_cmd[++i] = le;

  apdu_cmd_size = ++i;

  rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
  if (rv)
  {
    IOT_SAFE_DEBUG("SCardEstablishContext failed: %ld\n", rv);
    return IOT_SAFE_ERROR_UNKNOWN;
  }

#ifdef SCARD_AUTOALLOCATE
  dwReaders = SCARD_AUTOALLOCATE;

  rv = SCardListReaders(hContext, NULL, (LPTSTR)&mszReaders, &dwReaders);
  if (rv)
  {
    IOT_SAFE_DEBUG("Error on SCardListReaders: %ld\n", rv);
    return IOT_SAFE_ERROR_UNKNOWN;
  }
#else
  rv = SCardListReaders(hContext, NULL, NULL, &dwReaders);
  if (rv)
  {
    IOT_SAFE_DEBUG("Error on SCardListReaders: %ld\n", rv);
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  mszReaders = calloc(dwReaders, sizeof(char));
  rv = SCardListReaders(hContext, NULL, mszReaders, &dwReaders);
  if (rv)
  {
    IOT_SAFE_DEBUG("Error on SCardListReaders: %ld\n", rv);
    return IOT_SAFE_ERROR_UNKNOWN;
  }
#endif
  rv = SCardConnect(hContext, mszReaders, SCARD_SHARE_SHARED,
    SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
  if (rv)
  {
    IOT_SAFE_DEBUG("Error on SCardConnect: %ld\n", rv);
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  switch(dwActiveProtocol)
  {
   case SCARD_PROTOCOL_T0:
    pioSendPci = *SCARD_PCI_T0;
    break;

   case SCARD_PROTOCOL_T1:
    pioSendPci = *SCARD_PCI_T1;
    break;
  }
  dwRecvLength = sizeof(pbRecvBuffer);
  rv = SCardTransmit(hCard, &pioSendPci, apdu_cmd, apdu_cmd_size, NULL,
    pbRecvBuffer, &dwRecvLength);
  if (rv) {
    IOT_SAFE_DEBUG("Error on SCardTransmit: %ld\n", rv);
    return IOT_SAFE_ERROR_UNKNOWN;
  }

  IOT_SAFE_DEBUG("response: ");
  for(i=0; i<dwRecvLength; i++)
    IOT_SAFE_DEBUG("%02X ", pbRecvBuffer[i]);
  IOT_SAFE_DEBUG("\n");

  error_code =
    pbRecvBuffer[dwRecvLength - 2] << 8 | pbRecvBuffer[dwRecvLength-1];

  // Extract data if requested
  if (response_size > 0)
  {
    *response_length = dwRecvLength - 2;
    if (*response_length <= response_size)
      memcpy(response, pbRecvBuffer, *response_length);
    else
    {
      IOT_SAFE_DEBUG("Response too long for buffer (%d > %d)\n",
        *response_length, response_size);
      return IOT_SAFE_ERROR_UNKNOWN;
    }
  }

error:
  rv = SCardDisconnect(hCard, SCARD_LEAVE_CARD);
  if (rv)
  {
    IOT_SAFE_DEBUG("Error on SCardDisconnect: %ld\n", rv);
    return IOT_SAFE_ERROR_UNKNOWN;
  }

#ifdef SCARD_AUTOALLOCATE
  rv = SCardFreeMemory(hContext, mszReaders);
  if (rv)
  {
    IOT_SAFE_DEBUG("Error on SCardFreeMemory: %ld\n", rv);
    return IOT_SAFE_ERROR_UNKNOWN;
  }

#else
  free(mszReaders);
#endif

  rv = SCardReleaseContext(hContext);
  if (rv)
  {
    IOT_SAFE_DEBUG("SCardReleaseContext: %d\n", rv);
    return IOT_SAFE_ERROR_UNKNOWN;
  }
  
  return error_code;
}

#endif
