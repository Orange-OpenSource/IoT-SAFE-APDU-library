/*
 * Copyright (C) 2020 Orange
 *
 * This software is distributed under the terms and conditions of the 'BSD-3-Clause'
 * license which can be found in the file 'LICENSE' in this package distribution
 * or at 'https://opensource.org/licenses/BSD-3-Clause'.
 */

/**
 * @file   IoTSAFE.h
 * @brief  Wraps Arduino IoT SAFE for ArduinoBearSSL.
 */

#include <iot_safe.h>
#include <ArduinoBearSSL.h>

#define IOT_SAFE_MAX_FILE_SIZE 384

class IoTSAFECertificate
{
  public:
    IoTSAFECertificate();
    ~IoTSAFECertificate();
    br_x509_certificate getCertificate();
    String getCertificateCommonName();

    uint8_t m_Data[IOT_SAFE_MAX_FILE_SIZE];
    size_t m_nDataLength;
};

class IoTSAFE
{
  public:
    IoTSAFE(const uint8_t *pAID=IOT_SAFE_AID,
      uint8_t nAIDLength=sizeof(IOT_SAFE_AID));
    ~IoTSAFE();
    IoTSAFECertificate readCertificate(const uint8_t *pFileID,
      uint8_t nFileIDLength);
    size_t sign(const uint8_t *pKeyID, uint8_t nKeyIDLength,
      const br_ec_impl *pImpl, const br_hash_class *pHF,
      const void *pHashValue, const br_ec_private_key *pSk, void *pSig);
  private:
    iot_safe_error_t init();
    void finish();
  private:
    const uint8_t *m_AID;
    uint8_t m_nAIDLength;
    uint8_t m_nChannel;
};
