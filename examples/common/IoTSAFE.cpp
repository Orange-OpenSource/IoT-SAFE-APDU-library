/*
 * Copyright (C) 2020 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file   IoTSAFE.cpp
 * @brief  Wraps Arduino IoT SAFE for ArduinoBearSSL.
 */

#include "IoTSAFE.h"

#define IOT_SAFE_MAX_COMMON_NAME_SIZE 64

IoTSAFECertificate::IoTSAFECertificate()
    :
    m_nDataLength(0)
{}

IoTSAFECertificate::~IoTSAFECertificate()
{}

br_x509_certificate IoTSAFECertificate::getCertificate()
{
  br_x509_certificate br_cert = { (unsigned char *)m_Data, m_nDataLength };
  return br_cert;
}

String IoTSAFECertificate::getCertificateCommonName()
{
  char client_common_name[IOT_SAFE_MAX_COMMON_NAME_SIZE];

  memset(client_common_name, 0, sizeof(client_common_name));

  for (int i = 5; i < m_nDataLength; i++) {
    // Find common name
    if (m_Data[i-5] == 0x55 && m_Data[i-4] == 0x04 && m_Data[i-3] == 0x03)
    {

      if (m_Data[i-1] > sizeof(client_common_name))
        return String("");

      memcpy(client_common_name, &m_Data[i], m_Data[i-1]);
    }
  }
  return String(client_common_name);
}


IoTSAFE::IoTSAFE(const uint8_t* pAID, uint8_t nAIDLength)
    :
    m_AID(pAID),
    m_nAIDLength(nAIDLength),
    m_nChannel(0)
{}

IoTSAFE::~IoTSAFE()
{}

iot_safe_error_t IoTSAFE::init()
{
  return iot_safe_init(m_AID, m_nAIDLength, &m_nChannel);
}

void IoTSAFE::finish()
{
  iot_safe_finish(m_nChannel);
}

IoTSAFECertificate IoTSAFE::readCertificate(const uint8_t *pFileID,
  uint8_t nFileIDLength)
{
  IoTSAFECertificate certificate;

  if (init() == IOT_SAFE_SUCCESS)
  {
    iot_safe_read_file(m_nChannel, pFileID, nFileIDLength, NULL, 0,
      certificate.m_Data, sizeof(certificate.m_Data));

    finish();
  }
  
  // Consider that the file is finished as soon as there is a value
  // different from 0x00
  certificate.m_nDataLength = sizeof(certificate.m_Data);
  while (certificate.m_nDataLength > 0) {
    if (certificate.m_Data[certificate.m_nDataLength - 1] != 0x00)
      break;
    certificate.m_nDataLength--;
  }

  return certificate;
}

size_t IoTSAFE::sign(const uint8_t *pKeyID, uint8_t nKeyIDLength,
  const br_ec_impl *pImpl, const br_hash_class *pHF,
  const void *pHashValue, const br_ec_private_key *pSk, void *pSig)
{
  iot_safe_hash_t IoTSAFEHash = IOT_SAFE_HASH_SHA_256;
  uint8_t nHashSize = (pHF->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK;
  uint16_t nSignatureLength = 0;
 
  switch((pHF->desc >> BR_HASHDESC_ID_OFF) & BR_HASHDESC_ID_MASK) {
    case 0:
      SERIAL_PORT_MONITOR.println("IoT SAFE does not support none as an hash algorithm");
      return -1;
   case 1:
      SERIAL_PORT_MONITOR.println("IoT SAFE does not support the unsecure md5 hash algorithm");
      return -1;
    case 2:
      SERIAL_PORT_MONITOR.println("IoT SAFE does not support the unsecure sha1 hash algorithm");
      return -1;
    case 3:
      SERIAL_PORT_MONITOR.println("IoT SAFE does not support sha224 hash algorithm");
      return -1;
    case 4:
      IoTSAFEHash = IOT_SAFE_HASH_SHA_256;
      break;
    case 5:
      IoTSAFEHash = IOT_SAFE_HASH_SHA_384;
      break;
    case 6:
      IoTSAFEHash = IOT_SAFE_HASH_SHA_512;
      break;
    default:
      SERIAL_PORT_MONITOR.println("Unknown hash algorithm");
      return -1;
  }

  if (init() == IOT_SAFE_SUCCESS)
  {
    iot_safe_sign(m_nChannel, IOT_SAFE_SIGNATURE_OPERATION_MODE_PAD_AND_SIGN,
      IoTSAFEHash, IOT_SAFE_SIGNATURE_ECDSA, pKeyID, nKeyIDLength, NULL,  0,
      (uint8_t*)pHashValue, nHashSize, (uint8_t*)pSig, 72, &nSignatureLength);

    finish();
  }

  return br_ecdsa_raw_to_asn1(pSig, nSignatureLength);
}
