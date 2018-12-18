// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/utils.h>

#include <openenclave/internal/enclavelibc.h>
//#include "common.h"
#include <openenclave/internal/print.h>
#include <stdio.h>

// Using mbedtls to create an extended X.509 certificate
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>
#include <mbedtls/oid.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

#define MAX_CERT_SIZE 8*0124

//#include <mbedtls/net_sockets.h>

const size_t SHA256_DIGEST_SIZE = 32;

void _gen_sha256(char* data, size_t data_size, OE_SHA256* sha256)
{
    oe_sha256_context_t ctx = {0};
    oe_sha256_init(&ctx);
    oe_sha256_update(&ctx, data, data_size);
    oe_sha256_final(&ctx, sha256);
}

void sha256_rsa_pubkey(unsigned char hash[SHA256_DIGEST_SIZE],
                       const mbedtls_pk_context* pk) 
{
    static const int pk_der_size_max = 512;
    uint8_t pk_der[pk_der_size_max];
    oe_memset(pk_der, 0, pk_der_size_max);


    /* From the mbedtls documentation: Write a public key to a
       SubjectPublicKeyInfo DER structure Note: data is written at the
       end of the buffer! Use the return value to determine where you
       should start using the buffer. */
    int pk_der_size_byte = mbedtls_pk_write_pubkey_der((mbedtls_pk_context*) pk,
                                                       pk_der, pk_der_size_max);
    // Can only handle 2048 bit RSA keys for now. Other key sizes will
    // have a different pk_der_offset.
    //assert(pk_der_size_byte == 294);

    /* Move the data to the beginning of the buffer, to avoid pointer
       arithmetic from this point forward. */
 //Todo   memmove(pk_der, pk_der + pk_der_size_max - pk_der_size_byte, pk_der_size_byte);

    /* 24 since we skip the DER structure header (i.e, PKCS#1 header). */
    static const size_t pk_der_offset = 24;

    oe_memset(hash, 0, SHA256_DIGEST_SIZE);
    mbedtls_sha256_ret(pk_der + pk_der_offset,
                        (size_t)pk_der_size_byte - pk_der_offset,
                        hash, 0 /* is224 */);
}

oe_result_t generate_x509_cert( oe_cert_format_t cert_format,
                                uint8_t*key,
                                size_t key_size,
                                uint8_t** output_cert,
                                size_t* output_cert_size,
                                char* user_data,
                                size_t user_data_size)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* remote_report_buf = NULL;
    size_t remote_report_buf_size = OE_MAX_REPORT_SIZE;
    mbedtls_mpi serial;
    OE_SHA256 sha256 = {0};
    mbedtls_x509write_cert x509cert = { 0 };
    mbedtls_pk_context subject_key; // subject's public key
    int ret = 0;
    int bytes_written = 0;
    uint8_t *cert_buf = NULL;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_pk_init(&subject_key);
    mbedtls_mpi_init(&serial);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ret = mbedtls_pk_parse_public_key(&subject_key,
                                     (const unsigned char *)key,
                                      key_size);
    if (ret)
    {
        OE_TRACE_ERROR("Failed with 0x%x\n", ret);
        goto done;
    }

    //
    // get attestation data
    //

    // we can optionally add user data into the report via 
    // deposting the hash of user data in the sgx report_data field
    _gen_sha256(user_data, user_data_size, &sha256);

    // Generate a remote report for the public key so that the enclave that
    // receives the key can attest this enclave.
    remote_report_buf = (uint8_t*)oe_malloc(OE_MAX_REPORT_SIZE);
    if (remote_report_buf == NULL)
    {
        goto done;
    }

    result = oe_get_report(
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        sha256.buf,         // Store sha256 in report_data field
        sizeof(sha256.buf),
        NULL,               // opt_params must be null
        0,
        remote_report_buf,
        &remote_report_buf_size);
    if (result != OE_OK)
    {
        OE_TRACE_ERROR("oe_get_report failed with %s\n", oe_result_str(result));
        goto done;
    }

    // generate certificate 
    mbedtls_x509write_crt_init(&x509cert);
    mbedtls_x509write_crt_set_md_alg(&x509cert, MBEDTLS_MD_SHA256);

    // same key for both issuer and subject in the ceritificate
    mbedtls_x509write_crt_set_subject_key(&x509cert, &subject_key);
    mbedtls_x509write_crt_set_issuer_key(&x509cert, &subject_key);

    // Set the subject name for a Certificate Subject names should contain a comma-separated list of OID types and values:
    // e.g. "C=UK,O=ARM,CN=mbed TLS Server 1"

    ret = mbedtls_x509write_crt_set_subject_name(&x509cert, "CN=Open Encalve SDK,O=OESDK TLS,C=UK");
    if (ret)
    {
        OE_TRACE_ERROR("Failed with 0x%x ", ret);
        goto done;
    }

    //assert(ret == 0);
    ret = mbedtls_x509write_crt_set_issuer_name(&x509cert, "CN=Open Encalve SDK,O=OESDK TLS,C=UK");
    if (ret)
    {
        OE_TRACE_ERROR("Failed with 0x%x ", ret);
        goto done;
    }

    ret = mbedtls_mpi_read_string(&serial, 10, "1");
    if (ret)
    {
        OE_TRACE_ERROR("Failed with 0x%x ", ret);
        goto done;
    }

    ret = mbedtls_x509write_crt_set_serial(&x509cert, &serial);
    if (ret)
    {
        OE_TRACE_ERROR("Failed with 0x%x ", ret);
        goto done;
    }

    // Set the validity period for a Certificate Timestamps
    // get time from the host for not_before 
    // and plus 10 years for the not_after
    ret = mbedtls_x509write_crt_set_validity(&x509cert,
                                             "20180101000000", // not_before
                                             "20501231235959"); // not_after
    if (ret)
    {
        OE_TRACE_ERROR("Failed with 0x%x ", ret);
        goto done;
    }

    // Set the basicConstraints extension for a CRT
    ret = mbedtls_x509write_crt_set_basic_constraints(&x509cert, 
                                                     0, // is_ca
                                                     -1);
    if (ret)
    {
        OE_TRACE_ERROR("Failed with 0x%x ", ret);
        goto done;
    }
    // Set the subjectKeyIdentifier extension for a CRT Requires that
    // mbedtls_x509write_crt_set_subject_key() has been called before
    ret = mbedtls_x509write_crt_set_subject_key_identifier(&x509cert);
    if (ret)
    {
        OE_TRACE_ERROR("Failed with 0x%x ", ret);
        goto done;
    }

    // Set the authorityKeyIdentifier extension for a CRT Requires that
    // mbedtls_x509write_crt_set_issuer_key() has been called before.
    ret = mbedtls_x509write_crt_set_authority_key_identifier(&x509cert);
    if (ret)
    {
        OE_TRACE_ERROR("Failed with 0x%x ", ret);
        goto done;
    }
    //    1.2.840.113556.1000.1 (ISO assigned OIDs, ISO member body, USA, Microsoft)
    // Need to get a registered OID from the following site
    // https://www.alvestrand.no/objectid/1.2.840.113556.html

    // // 1.2.840.113741.1337.3
    // unsigned char oid_ias_sign_ca_cert[] = {0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, 0x03};
    
    unsigned char oid_oe_report[] = {0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, 0x01};
    ret = mbedtls_x509write_crt_set_extension(&x509cert,
                                              (char*) oid_oe_report,
                                              sizeof(oid_oe_report),
                                              0 /* criticial */,
                                              (const uint8_t*) remote_report_buf,
                                              remote_report_buf_size);
    if (ret)
    {
        OE_TRACE_ERROR("Failed with 0x%x ", ret);
        goto done;
    }

    // allocate memory for cert output buffer
    cert_buf = (uint8_t*)oe_malloc(MAX_CERT_SIZE);
    if (cert_buf == NULL)
            goto done;
    // if (report_buffer)
    //     oe_free(report_buffer);

    // Write a built up certificate to a X509 DER structure Note: data
    // is written at the end of the buffer! Use the return value to
    // determine where you should start using the buffer.
    if (OE_CERT_FORMAT_DER == cert_format) {
        bytes_written = mbedtls_x509write_crt_der(&x509cert, cert_buf, sizeof(cert_buf),
                                                  mbedtls_ctr_drbg_random, &ctr_drbg);
    } else if (OE_CERT_FORMAT_PEM == cert_format)
    {
        bytes_written = mbedtls_x509write_crt_pem(&x509cert, cert_buf, sizeof(cert_buf),
                                                  mbedtls_ctr_drbg_random, &ctr_drbg);
    } else{
        OE_TRACE_ERROR("Failed with 0x%x ", ret);
        goto done;
    } 

    if (bytes_written <= 0)
    {
        OE_RAISE_MSG(OE_FAILURE, "Failed with bytes_written = %d ", bytes_written);
    }

    *output_cert_size = (size_t)bytes_written;
    *output_cert = cert_buf;

done:
    mbedtls_mpi_free(&serial);
    mbedtls_x509write_crt_free(&x509cert);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    if (remote_report_buf)
        oe_free(remote_report_buf);

    if (ret)
    {
        result = OE_FAILURE;
    }
    return result;
}

//oe_result_t generate_public_key(mbedtls_pk_context *pkey)
// input: input_data and input_data_len
// output: key, key_size
oe_result_t generate_public_key(char* input_data, size_t input_data_len, uint8_t** key, size_t *key_size)
{
    oe_result_t result = OE_FAILURE;
    oe_asymmetric_key_params_t params = {0};

    // First, generate the key with a null user data.
    params.type = OE_ASYMMETRIC_KEY_EC_SECP256P1;  // MBEDTLS_ECP_DP_SECP256R1
    params.format = OE_ASYMMETRIC_KEY_PEM;
    params.user_data = input_data;
    params.user_data_size = input_data_len;
    result = oe_get_public_key_by_policy(
            OE_SEAL_POLICY_UNIQUE,
            &params,
            key,
            key_size,
            NULL,
            NULL);
    if (result != OE_OK)
    {
        goto done;
    }

done:

    return result;
}

oe_result_t oe_gen_x509cert_for_TLS(oe_cert_format_t cert_format,
                                    uint8_t** output_cert,
                                    size_t* output_cert_size)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* key = NULL;
    size_t key_size = 0;
    char user_data[] = "optional user data!";   
    size_t user_data_size = sizeof(user_data) - 1;

    //
    // generate public key
    //
    result = generate_public_key(user_data, user_data_size, &key, &key_size);
    if (result != OE_OK)
    {
        OE_TRACE_ERROR(" failed with %s\n", oe_result_str(result));
        goto done;
    }

    printf("key =[%s]\n", key);

    //
    // generate cert
    //
    result = generate_x509_cert(cert_format,
                                key,
                                key_size,
                                output_cert,
                                output_cert_size,
                                user_data, // optional data
                                user_data_size);
    if (result != OE_OK)
    {
        OE_TRACE_ERROR(" failed with %s\n", oe_result_str(result));
        goto done;
    }

done:
    return result;
}

void oe_free_x509cert_for_TLS(
    uint8_t* cert,
    size_t cert_size)
{
    if (cert)
    {
        oe_secure_zero_fill(cert, cert_size);
        oe_free(cert);
    }
}
    


// static oe_result_t _oe_parse_sgx_report_body(
//     const sgx_report_body_t* report_body,
//     bool remote,
//     oe_report_t* parsed_report)
// {
//     oe_result_t result = OE_UNEXPECTED;

//     oe_secure_zero_fill(parsed_report, sizeof(oe_report_t));

//     parsed_report->size = sizeof(oe_report_t);
//     parsed_report->type = OE_ENCLAVE_TYPE_SGX;

//     /*
//      * Parse identity.
//      */
//     parsed_report->identity.id_version = 0x0;
//     parsed_report->identity.security_version = report_body->isvsvn;

//     if (report_body->attributes.flags & SGX_FLAGS_DEBUG)
//         parsed_report->identity.attributes |= OE_REPORT_ATTRIBUTES_DEBUG;

//     if (remote)
//         parsed_report->identity.attributes |= OE_REPORT_ATTRIBUTES_REMOTE;

//     OE_STATIC_ASSERT(
//         sizeof(parsed_report->identity.unique_id) >=
//         sizeof(report_body->mrenclave));
//     OE_CHECK(
//         oe_memcpy_s(
//             parsed_report->identity.unique_id,
//             sizeof(parsed_report->identity.unique_id),
//             report_body->mrenclave,
//             sizeof(report_body->mrenclave)));

//     OE_STATIC_ASSERT(
//         sizeof(parsed_report->identity.signer_id) >=
//         sizeof(report_body->mrsigner));

//     OE_CHECK(
//         oe_memcpy_s(
//             parsed_report->identity.signer_id,
//             sizeof(parsed_report->identity.signer_id),
//             report_body->mrsigner,
//             sizeof(report_body->mrsigner)));

//     if (report_body->isvprodid > OE_INT8_MAX)
//         goto done;
//     parsed_report->identity.product_id[0] =
//         (uint8_t)report_body->isvprodid & 0xFF;
//     parsed_report->identity.product_id[1] =
//         (uint8_t)((report_body->isvprodid >> 8) & 0xFF);

//     /*
//      * Set pointer fields.
//      */
//     parsed_report->report_data = (uint8_t*)&report_body->report_data;
//     parsed_report->report_data_size = sizeof(sgx_report_data_t);
//     parsed_report->enclave_report = (uint8_t*)report_body;
//     parsed_report->enclave_report_size = sizeof(sgx_report_body_t);

//     result = OE_OK;
// done:
//     return result;
// }

// oe_result_t oe_parse_report(
//     const uint8_t* report,
//     size_t report_size,
//     oe_report_t* parsed_report)
// {
//     const sgx_report_t* sgx_report = NULL;
//     const sgx_quote_t* sgx_quote = NULL;
//     oe_report_header_t* header = (oe_report_header_t*)report;
//     oe_result_t result = OE_FAILURE;

//     if (report == NULL || parsed_report == NULL)
//         OE_RAISE(OE_INVALID_PARAMETER);

//     if (report_size < sizeof(oe_report_header_t))
//         OE_RAISE(OE_INVALID_PARAMETER);

//     if (header->version != OE_REPORT_HEADER_VERSION)
//         OE_RAISE(OE_INVALID_PARAMETER);

//     if (header->report_size + sizeof(oe_report_header_t) != report_size)
//         OE_RAISE(OE_FAILURE);

//     if (header->report_type == OE_REPORT_TYPE_SGX_LOCAL)
//     {
//         sgx_report = (const sgx_report_t*)header->report;
//         OE_CHECK(
//             _oe_parse_sgx_report_body(&sgx_report->body, false, parsed_report));
//         result = OE_OK;
//     }
//     else if (header->report_type == OE_REPORT_TYPE_SGX_REMOTE)
//     {
//         sgx_quote = (const sgx_quote_t*)header->report;
//         OE_CHECK(
//             _oe_parse_sgx_report_body(
//                 &sgx_quote->report_body, true, parsed_report));
//         result = OE_OK;
//     }
//     else
//     {
//         OE_RAISE(OE_REPORT_PARSE_ERROR);
//     }

// done:
//     return result;
// }

// static oe_result_t _oe_sgx_get_target_info(
//     const uint8_t* report,
//     size_t report_size,
//     void* target_info_buffer,
//     size_t* target_info_size)
// {
//     oe_result_t result = OE_FAILURE;
//     sgx_report_t* sgx_report = (sgx_report_t*)report;
//     sgx_target_info_t* info = (sgx_target_info_t*)target_info_buffer;

//     if (!report || report_size < sizeof(*sgx_report) || !target_info_size)
//         OE_RAISE(OE_INVALID_PARAMETER);

//     if (target_info_buffer == NULL || *target_info_size < sizeof(*info))
//     {
//         *target_info_size = sizeof(*info);
//         OE_RAISE(OE_BUFFER_TOO_SMALL);
//     }

//     OE_CHECK(oe_memset_s(info, sizeof(*info), 0, sizeof(*info)));

//     OE_CHECK(
//         oe_memcpy_s(
//             info->mrenclave,
//             sizeof(info->mrenclave),
//             sgx_report->body.mrenclave,
//             sizeof(sgx_report->body.mrenclave)));

//     info->attributes = sgx_report->body.attributes;
//     info->misc_select = sgx_report->body.miscselect;

//     *target_info_size = sizeof(*info);
//     result = OE_OK;

// done:
//     return result;
// }

// oe_result_t oe_get_target_info(
//     const uint8_t* report,
//     size_t report_size,
//     void* target_info_buffer,
//     size_t* target_info_size)
// {
//     oe_result_t result = OE_FAILURE;
//     oe_report_header_t* report_header = (oe_report_header_t*)report;

//     if (!report || report_size < sizeof(*report_header) || !target_info_size)
//         OE_RAISE(OE_INVALID_PARAMETER);

//     /* Validate the report header. */
//     if (report_header->version != OE_REPORT_HEADER_VERSION)
//         OE_RAISE(OE_INVALID_PARAMETER);

//     report_size -= OE_OFFSETOF(oe_report_header_t, report);
//     report += OE_OFFSETOF(oe_report_header_t, report);
//     switch (report_header->report_type)
//     {
//         case OE_REPORT_TYPE_SGX_LOCAL:
//         case OE_REPORT_TYPE_SGX_REMOTE:
//             OE_CHECK(
//                 _oe_sgx_get_target_info(
//                     report, report_size, target_info_buffer, target_info_size));
//             break;
//         default:
//             OE_RAISE(OE_INVALID_PARAMETER);
//     }

//     result = OE_OK;

// done:
//     return result;
// }
