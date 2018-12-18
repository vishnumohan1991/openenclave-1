// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>

// Using mbedtls to create an extended X.509 certificate
// #include <mbedtls/entropy.h>
// #include <mbedtls/ctr_drbg.h>
// #include <mbedtls/certs.h>
// #include <mbedtls/x509.h>
// #include <mbedtls/ssl.h>
// #include <mbedtls/error.h>
// #include <mbedtls/debug.h>
// #include <mbedtls/oid.h>
// #include <mbedtls/sha256.h>
// #include <mbedtls/x509_crt.h>

#define UNREFERENCE(x) (void(x)) // Prevent unused warning

OE_ECALL void Test(void* args_)
{
    uint8_t* output_cert = NULL;
    size_t output_cert_size = 0;
    oe_result_t result = OE_FAILURE;

    UNREFERENCE(args_);

    printf("called into onclave\n");
    fflush(stdout);

    result = oe_gen_x509cert_for_TLS(OE_CERT_FORMAT_PEM,
                                     &output_cert,
                                     &output_cert_size);

    if (result != OE_OK)
    {
        printf(" failed with %s\n", oe_result_str(result));
        goto done;
    }

done:
    oe_free_x509cert_for_TLS(output_cert, output_cert_size);
    OE_TRACE_ERROR("test from tls enclave");
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    128,  /* HeapPageCount */
    128,  /* StackPageCount */
    1);   /* TCSCount */
OE_DEFINE_EMPTY_ECALL_TABLE();



// struct ra_tls_options {
//     sgx_spid_t spid;
//     sgx_quote_sign_type_t quote_type;
//     /* \0 terminated file name; libcurl, used to interact with IAS,
//        basically expects a file name. It is super-complicated to pass
//        a memory buffer with the certificate and key to it. */
//     const char ias_key_file[512];
//     const char ias_cert_file[512];
//     /* \0 terminated string of domain name/IP and port, e.g.,
//        test-as.sgx.trustedservices.intel.com:443 */
//     const char ias_server[512];

// Add quote type (TrustZone, OE SGX)
// };

// pem_key

// // https://github.com/ARMmbed/mbedtls/tree/development/programs/ssl

// diff --git a/programs/ssl/ssl_server.c b/programs/ssl/ssl_server.c
// index fd54f17..9a2f1ea 100644
// --- a/programs/ssl/ssl_server.c
// +++ b/programs/ssl/ssl_server.c
// @@ -73,13 +73,13 @@ int main( void )
//  #include "mbedtls/ssl_cache.h"
//  #endif
 
// -#define HTTP_RESPONSE \
// -    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
// -    "<h2>mbed TLS Test Server</h2>\r\n" \
// -    "<p>Successful connection using: %s</p>\r\n"
// -
//  #define DEBUG_LEVEL 0
 
// +#include <sgx_quote.h>
// +
// +#include "mbedtls-ra-attester.h"
// +#include "ra-challenger.h"
// +
//  static void my_debug( void *ctx, int level,
//                        const char *file, int line,
//                        const char *str )
// @@ -90,6 +90,8 @@ static void my_debug( void *ctx, int level,
//      fflush(  (FILE *) ctx  );
//  }
 
// +extern struct ra_tls_options my_ra_tls_options;
// +
//  int main( void )
//  {
//      int ret, len;
// @@ -119,54 +121,25 @@ int main( void )
//      mbedtls_entropy_init( &entropy );
//      mbedtls_ctr_drbg_init( &ctr_drbg );
 
// -#if defined(MBEDTLS_DEBUG_C)
//      mbedtls_debug_set_threshold( DEBUG_LEVEL );
// -#endif
 
//      /*
// -     * 1. Load the certificates and private RSA key
// +     * 1. Generate the certificate and private RSA key
//       */
// -    mbedtls_printf( "\n  . Loading the server cert. and key..." );
// +    mbedtls_printf( "\n  . Generating the server cert. and key..." );
//      fflush( stdout );
 
// -    /*
// -     * This demonstration program uses embedded test certificates.
// -     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
// -     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
// -     */
// -    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_srv_crt,
// -                          mbedtls_test_srv_crt_len );
// -    if( ret != 0 )
// -    {
// -        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
// -        goto exit;
// -    }
// -
// -    ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_cas_pem,
// -                          mbedtls_test_cas_pem_len );
// -    if( ret != 0 )
// -    {
// -        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
// -        goto exit;
// -    }
// -
// -    ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) mbedtls_test_srv_key,
// -                         mbedtls_test_srv_key_len, NULL, 0 );
// -    if( ret != 0 )
// -    {
// -        mbedtls_printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
// -        goto exit;
// -    }
// +    mbedtls_create_key_and_x509(&pkey, &srvcert, &my_ra_tls_options);
 
//      mbedtls_printf( " ok\n" );
 
//      /*
//       * 2. Setup the listening TCP socket
//       */
// -    mbedtls_printf( "  . Bind on https://localhost:4433/ ..." );
// +    mbedtls_printf( "  . Bind on https://localhost:11111/ ..." );
//      fflush( stdout );
 
// -    if( ( ret = mbedtls_net_bind( &listen_fd, NULL, "4433", MBEDTLS_NET_PROTO_TCP ) ) != 0 )
// +    if( ( ret = mbedtls_net_bind( &listen_fd, "127.0.0.1", "11111", MBEDTLS_NET_PROTO_TCP ) ) != 0 )
//      {
//          mbedtls_printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
//          goto exit;
// @@ -252,7 +225,10 @@ reset:
//      if( ( ret = mbedtls_net_accept( &listen_fd, &client_fd,
//                                      NULL, 0, NULL ) ) != 0 )
//      {
// +        char errbuf[512];
// +        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
//          mbedtls_printf( " failed\n  ! mbedtls_net_accept returned %d\n\n", ret );
// +        mbedtls_printf("%s\n", errbuf);
//          goto exit;
//      }
 
// @@ -326,8 +302,25 @@ reset:
//      mbedtls_printf( "  > Write to client:" );
//      fflush( stdout );
 
// -    len = sprintf( (char *) buf, HTTP_RESPONSE,
// -                   mbedtls_ssl_get_ciphersuite( &ssl ) );
// +    sgx_quote_t quote;
// +    get_quote_from_cert(srvcert.raw.p, srvcert.raw.len, &quote);
// +    sgx_report_body_t* body = &quote.report_body;
// +
// +    char mrenclave_hex_str[SGX_HASH_SIZE * 2 + 1] = {0, };
// +    char mrsigner_hex_str[SGX_HASH_SIZE * 2 + 1] = {0, };
// +    for (int i = 0; i < SGX_HASH_SIZE; ++i) {
// +        sprintf(&mrenclave_hex_str[i*2], "%02x", body->mr_enclave.m[i]);
// +        sprintf(&mrsigner_hex_str[i*2], "%02x", body->mr_signer.m[i]);
// +    }
// +    
// +    const char* http_response = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
// +        "<h2>mbed TLS Test Server</h2>\r\n"                             \
// +        "<p>Successful connection using: %s</br>\r\n"                   \
// +        "MRENCLAVE is %s</br>\r\nMRSIGNER is %s</p>\r\n";
// +
// +    len = snprintf((char *) buf, sizeof (buf) - 1, http_response,
// +                   mbedtls_ssl_get_ciphersuite(&ssl),
// +                   mrenclave_hex_str, mrsigner_hex_str);
 
//      while( ( ret = mbedtls_ssl_write( &ssl, buf, len ) ) <= 0 )
//      {
// @@ -345,7 +338,7 @@ reset:
//      }
 
//      len = ret;
// -    mbedtls_printf( " %d bytes written\n\n%s\n", len, (char *) buf );
// +    mbedtls_printf(" %d bytes written\n", len);
 
//      mbedtls_printf( "  . Closing the connection..." );
 
//      }




//https://github.com/ARMmbed/mbedtls/blob/development/programs/ssl/ssl_server.c
/*
*  SSL server demonstration program
*
*  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
*  SPDX-License-Identifier: Apache-2.0
*
*  Licensed under the Apache License, Version 2.0 (the "License"); you may
*  not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*  http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
*  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*
*  This file is part of mbed TLS (https://tls.mbed.org)
*/

// #if !defined(MBEDTLS_CONFIG_FILE)
// #include "mbedtls/config.h"
// #else
// #include MBEDTLS_CONFIG_FILE
// #endif

// #if defined(MBEDTLS_PLATFORM_C)
// #include "mbedtls/platform.h"
// #else
// #include <stdio.h>
// #include <stdlib.h>
// #define mbedtls_time       time
// #define mbedtls_time_t     time_t
// #define mbedtls_fprintf    fprintf
// #define mbedtls_printf     printf
// #endif

// #if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_CERTS_C) ||    \
//     !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_SSL_TLS_C) || \
//     !defined(MBEDTLS_SSL_SRV_C) || !defined(MBEDTLS_NET_C) ||     \
//     !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_CTR_DRBG_C) ||    \
//     !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO) || \
//     !defined(MBEDTLS_PEM_PARSE_C)
// int main(void)
// {
// 	mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_CERTS_C and/or MBEDTLS_ENTROPY_C "
// 		"and/or MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_SRV_C and/or "
// 		"MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
// 		"MBEDTLS_CTR_DRBG_C and/or MBEDTLS_X509_CRT_PARSE_C "
// 		"and/or MBEDTLS_PEM_PARSE_C not defined.\n");
// 	return(0);
// }
// #else

// #include <stdlib.h>
// #include <string.h>

// #if defined(_WIN32)
// #include <windows.h>
// #endif

// #include "mbedtls/entropy.h"
// #include "mbedtls/ctr_drbg.h"
// #include "mbedtls/certs.h"
// #include "mbedtls/x509.h"
// #include "mbedtls/ssl.h"
// #include "mbedtls/net_sockets.h"
// #include "mbedtls/error.h"
// #include "mbedtls/debug.h"

// #if defined(MBEDTLS_SSL_CACHE_C)
// #include "mbedtls/ssl_cache.h"
// #endif

// #define HTTP_RESPONSE \
//     "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
//     "<h2>mbed TLS Test Server</h2>\r\n" \
//     "<p>Successful connection using: %s</p>\r\n"

// #define DEBUG_LEVEL 0

// static void my_debug(void *ctx, int level,
// 	const char *file, int line,
// 	const char *str)
// {
// 	((void)level);

// 	mbedtls_fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
// 	fflush((FILE *)ctx);
// }

// int main(void)
// {
// 	int ret, len;
// 	mbedtls_net_context listen_fd, client_fd;
// 	unsigned char buf[1024];
// 	const char *pers = "ssl_server";

// 	mbedtls_entropy_context entropy;
// 	mbedtls_ctr_drbg_context ctr_drbg;
// 	mbedtls_ssl_context ssl;
// 	mbedtls_ssl_config conf;
// 	mbedtls_x509_crt srvcert;
// 	mbedtls_pk_context pkey;
// #if defined(MBEDTLS_SSL_CACHE_C)
// 	mbedtls_ssl_cache_context cache;
// #endif

// 	mbedtls_net_init(&listen_fd);
// 	mbedtls_net_init(&client_fd);
// 	mbedtls_ssl_init(&ssl);
// 	mbedtls_ssl_config_init(&conf);
// #if defined(MBEDTLS_SSL_CACHE_C)
// 	mbedtls_ssl_cache_init(&cache);
// #endif
// 	mbedtls_x509_crt_init(&srvcert);
// 	mbedtls_pk_init(&pkey);
// 	mbedtls_entropy_init(&entropy);
// 	mbedtls_ctr_drbg_init(&ctr_drbg);

// #if defined(MBEDTLS_DEBUG_C)
// 	mbedtls_debug_set_threshold(DEBUG_LEVEL);
// #endif

// 	/*
// 	* 1. Load the certificates and private RSA key
// 	*/
// 	mbedtls_printf("\n  . Loading the server cert. and key...");
// 	fflush(stdout);

// 	/*
// 	* This demonstration program uses embedded test certificates.
// 	* Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
// 	* server and CA certificates, as well as mbedtls_pk_parse_keyfile().
// 	*/

// // const char mbedtls_test_srv_crt_ec[] =
// // "-----BEGIN CERTIFICATE-----\r\n"
// // "MIICHzCCAaWgAwIBAgIBCTAKBggqhkjOPQQDAjA+MQswCQYDVQQGEwJOTDERMA8G\r\n"
// // "A1UEChMIUG9sYXJTU0wxHDAaBgNVBAMTE1BvbGFyc3NsIFRlc3QgRUMgQ0EwHhcN\r\n"
// // "MTMwOTI0MTU1MjA0WhcNMjMwOTIyMTU1MjA0WjA0MQswCQYDVQQGEwJOTDERMA8G\r\n"
// // "A1UEChMIUG9sYXJTU0wxEjAQBgNVBAMTCWxvY2FsaG9zdDBZMBMGByqGSM49AgEG\r\n"
// // "CCqGSM49AwEHA0IABDfMVtl2CR5acj7HWS3/IG7ufPkGkXTQrRS192giWWKSTuUA\r\n"
// // "2CMR/+ov0jRdXRa9iojCa3cNVc2KKg76Aci07f+jgZ0wgZowCQYDVR0TBAIwADAd\r\n"
// // "BgNVHQ4EFgQUUGGlj9QH2deCAQzlZX+MY0anE74wbgYDVR0jBGcwZYAUnW0gJEkB\r\n"
// // "PyvLeLUZvH4kydv7NnyhQqRAMD4xCzAJBgNVBAYTAk5MMREwDwYDVQQKEwhQb2xh\r\n"
// // "clNTTDEcMBoGA1UEAxMTUG9sYXJzc2wgVGVzdCBFQyBDQYIJAMFD4n5iQ8zoMAoG\r\n"
// // "CCqGSM49BAMCA2gAMGUCMQCaLFzXptui5WQN8LlO3ddh1hMxx6tzgLvT03MTVK2S\r\n"
// // "C12r0Lz3ri/moSEpNZWqPjkCMCE2f53GXcYLqyfyJR078c/xNSUU5+Xxl7VZ414V\r\n"
// // "fGa5kHvHARBPc8YAIVIqDvHH1Q==\r\n"

// 	ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *)mbedtls_test_srv_crt,
// 		mbedtls_test_srv_crt_len);
// 	if (ret != 0)
// 	{
// 		mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
// 		goto exit;
// 	}

// 	ret = mbedtls_x509_crt_parse(&srvcert, (const unsigned char *)mbedtls_test_cas_pem,
// 		mbedtls_test_cas_pem_len);
// 	if (ret != 0)
// 	{
// 		mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
// 		goto exit;
// 	}

// // const char mbedtls_test_srv_key_ec[] =
// // "-----BEGIN EC PRIVATE KEY-----\r\n"
// // "MHcCAQEEIPEqEyB2AnCoPL/9U/YDHvdqXYbIogTywwyp6/UfDw6noAoGCCqGSM49\r\n"
// // "AwEHoUQDQgAEN8xW2XYJHlpyPsdZLf8gbu58+QaRdNCtFLX3aCJZYpJO5QDYIxH/\r\n"
// // "6i/SNF1dFr2KiMJrdw1VzYoqDvoByLTt/w==\r\n"

// 	ret = mbedtls_pk_parse_key(&pkey, (const unsigned char *)mbedtls_test_srv_key,
// 		mbedtls_test_srv_key_len, NULL, 0);
// 	if (ret != 0)
// 	{
// 		mbedtls_printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
// 		goto exit;
// 	}

// 	mbedtls_printf(" ok\n");

// 	/*
// 	* 2. Setup the listening TCP socket
// 	*/
// 	mbedtls_printf("  . Bind on https://localhost:4433/ ...");
// 	fflush(stdout);

// 	if ((ret = mbedtls_net_bind(&listen_fd, NULL, "4433", MBEDTLS_NET_PROTO_TCP)) != 0)
// 	{
// 		mbedtls_printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
// 		goto exit;
// 	}

// 	mbedtls_printf(" ok\n");

// 	/*
// 	* 3. Seed the RNG
// 	*/
// 	mbedtls_printf("  . Seeding the random number generator...");
// 	fflush(stdout);

// 	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
// 		(const unsigned char *)pers,
// 		strlen(pers))) != 0)
// 	{
// 		mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
// 		goto exit;
// 	}

// 	mbedtls_printf(" ok\n");

// 	/*
// 	* 4. Setup stuff
// 	*/
// 	mbedtls_printf("  . Setting up the SSL data....");
// 	fflush(stdout);

// 	if ((ret = mbedtls_ssl_config_defaults(&conf,
// 		MBEDTLS_SSL_IS_SERVER,
// 		MBEDTLS_SSL_TRANSPORT_STREAM,
// 		MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
// 	{
// 		mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
// 		goto exit;
// 	}

// 	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
// 	mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

// #if defined(MBEDTLS_SSL_CACHE_C)
// 	mbedtls_ssl_conf_session_cache(&conf, &cache,
// 		mbedtls_ssl_cache_get,
// 		mbedtls_ssl_cache_set);
// #endif

// 	mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
// 	if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0)
// 	{
// 		mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
// 		goto exit;
// 	}

// 	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
// 	{
// 		mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
// 		goto exit;
// 	}

// 	mbedtls_printf(" ok\n");

// reset:
// #ifdef MBEDTLS_ERROR_C
// 	if (ret != 0)
// 	{
// 		char error_buf[100];
// 		mbedtls_strerror(ret, error_buf, 100);
// 		mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
// 	}
// #endif

// 	mbedtls_net_free(&client_fd);

// 	mbedtls_ssl_session_reset(&ssl);

// 	/*
// 	* 3. Wait until a client connects
// 	*/
// 	mbedtls_printf("  . Waiting for a remote connection ...");
// 	fflush(stdout);

// 	if ((ret = mbedtls_net_accept(&listen_fd, &client_fd,
// 		NULL, 0, NULL)) != 0)
// 	{
// 		mbedtls_printf(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
// 		goto exit;
// 	}

// 	mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

// 	mbedtls_printf(" ok\n");

// 	/*
// 	* 5. Handshake
// 	*/
// 	mbedtls_printf("  . Performing the SSL/TLS handshake...");
// 	fflush(stdout);

// 	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
// 	{
// 		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
// 		{
// 			mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret);
// 			goto reset;
// 		}
// 	}

// 	mbedtls_printf(" ok\n");

// 	/*
// 	* 6. Read the HTTP Request
// 	*/
// 	mbedtls_printf("  < Read from client:");
// 	fflush(stdout);

// 	do
// 	{
// 		len = sizeof(buf) - 1;
// 		memset(buf, 0, sizeof(buf));
// 		ret = mbedtls_ssl_read(&ssl, buf, len);

// 		if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
// 			continue;

// 		if (ret <= 0)
// 		{
// 			switch (ret)
// 			{
// 			case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
// 				mbedtls_printf(" connection was closed gracefully\n");
// 				break;

// 			case MBEDTLS_ERR_NET_CONN_RESET:
// 				mbedtls_printf(" connection was reset by peer\n");
// 				break;

// 			default:
// 				mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", -ret);
// 				break;
// 			}

// 			break;
// 		}

// 		len = ret;
// 		mbedtls_printf(" %d bytes read\n\n%s", len, (char *)buf);

// 		if (ret > 0)
// 			break;
// 	} while (1);

// 	/*
// 	* 7. Write the 200 Response
// 	*/
// 	mbedtls_printf("  > Write to client:");
// 	fflush(stdout);

// 	len = sprintf((char *)buf, HTTP_RESPONSE,
// 		mbedtls_ssl_get_ciphersuite(&ssl));

// 	while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0)
// 	{
// 		if (ret == MBEDTLS_ERR_NET_CONN_RESET)
// 		{
// 			mbedtls_printf(" failed\n  ! peer closed the connection\n\n");
// 			goto reset;
// 		}

// 		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
// 		{
// 			mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
// 			goto exit;
// 		}
// 	}

// 	len = ret;
// 	mbedtls_printf(" %d bytes written\n\n%s\n", len, (char *)buf);

// 	mbedtls_printf("  . Closing the connection...");

// 	while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0)
// 	{
// 		if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
// 			ret != MBEDTLS_ERR_SSL_WANT_WRITE)
// 		{
// 			mbedtls_printf(" failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret);
// 			goto reset;
// 		}
// 	}

// 	mbedtls_printf(" ok\n");

// 	ret = 0;
// 	goto reset;

// exit:

// #ifdef MBEDTLS_ERROR_C
// 	if (ret != 0)
// 	{
// 		char error_buf[100];
// 		mbedtls_strerror(ret, error_buf, 100);
// 		mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
// 	}
// #endif

// 	mbedtls_net_free(&client_fd);
// 	mbedtls_net_free(&listen_fd);

// 	mbedtls_x509_crt_free(&srvcert);
// 	mbedtls_pk_free(&pkey);
// 	mbedtls_ssl_free(&ssl);
// 	mbedtls_ssl_config_free(&conf);
// #if defined(MBEDTLS_SSL_CACHE_C)
// 	mbedtls_ssl_cache_free(&cache);
// #endif
// 	mbedtls_ctr_drbg_free(&ctr_drbg);
// 	mbedtls_entropy_free(&entropy);

// #if defined(_WIN32)
// 	mbedtls_printf("  Press Enter to exit this program.\n");
// 	fflush(stdout); getchar();
// #endif

// 	return(ret);
// }
// #endif /* MBEDTLS_BIGNUM_C && MBEDTLS_CERTS_C && MBEDTLS_ENTROPY_C &&
// MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_SRV_C && MBEDTLS_NET_C &&
// MBEDTLS_RSA_C && MBEDTLS_CTR_DRBG_C && MBEDTLS_X509_CRT_PARSE_C
// && MBEDTLS_FS_IO && MBEDTLS_PEM_PARSE_C */
