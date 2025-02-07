#ifndef SSL_H
#define SSL_H

#include <stdio.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>


#define THREAD_SAFE 0    
#define MAX_THREADS 2
#define DEBUG_ON  1



#define SSL_DEBUG_MSG(bio, level, func_name, type, msg, ...) \
    do { \
        if ((level) == SSL_DEBUG_ON) { \
            BIO_printf((bio), "func: %s [" type "]: " msg "\n", \
                      func_name, ##__VA_ARGS__); \
        } \
    } while(0)

#define SSL_DEBUG_ERROR(bio, level, func_name, msg, ...) \
    SSL_DEBUG_MSG(bio, level, func_name, "[ERROR]", msg, ##__VA_ARGS__)

#define SSL_DEBUG_SUCCESS(bio, level, func_name, msg, ...) \
    SSL_DEBUG_MSG(bio, level, func_name, "[SUCCESS]", msg, ##__VA_ARGS__)


typedef enum 
{
    SSL_SUCCESS                     =  0,
    SSL_ERROR_INVALID_PARAMS        = -1,
    SSL_ERROR_OPENSSL_INIT          = -2,
    SSL_ERROR_KEY_GENERATION        = -3,
    SSL_ERROR_CSR_GENERATION        = -4,
    SSL_ERROR_FILE_OPERATION        = -5,
    SSL_ERROR_MEMORY                = -6

} SSLStatus;


typedef enum 
{
    SSL_DEBUG_OFF =  0,
    SSL_DEBUG_ON  =  1

} SSLDebugLevel;


typedef struct SSL_config 
{
    EVP_PKEY            *pkey;
    EVP_PKEY_CTX        *pctx;   
    BIO                 *bio_out;       // Defalt output stream. 
    SSLDebugLevel       debug_level;    // Default SSL_DEBUG_OFF
} SSL_config;

/*
typedef struct 
{
    char    *commonName;            // Required
    char    *countryName;
    char    *localityName;
    char    *organizationName;
    char    *emailAddress;
    int     keyBits;                // Default: 2048
    int     keyVersion;             // Default: 0
    char    *keyPath;               // Path to save private key
    char    *csrPath;               // Path to save CSR

	RSA				*r = NULL;
	BIGNUM			*bne = NULL;

	int				nVersion = 0;
	int				bits = 2048;
	unsigned long	e = RSA_F4;

	X509_REQ		*x509_req = NULL;
	X509_NAME		*x509_name = NULL;
	EVP_PKEY		*pKey = NULL;
	RSA				*tem = NULL;
	BIO				*out = NULL, *bio_err = NULL;

	const char		*szCountry = "CA";
	const char		*szProvince = "BC";
	const char		*szCity = "Vancouver";
	const char		*szOrganization = "Dynamsoft";
	const char		*szCommon = "localhost";

	const char		*szPath = "x509Req.pem";

} SSL_CSRParameters;

*/

SSLStatus SSL_init(BIO             *bio_out,      
                   SSLDebugLevel   debug_level);


SSLStatus SSL_cleanup();



// Function to generate an RSA private key
// Parameters:
//   bio_out: A BIO object to write the key material if private_key is NULL
//   bits: The size of the RSA key to generate, in bits
//   hd: A handle to verify the claim on the service that this function provides
//   private_key: Pointer to an EVP_PKEY structure where the generated private key will be stored
// Return Value:
//   SSLStatus: Return status code indicating success or failure of the operation
SSLStatus
SSL_gen_RSAkey(unsigned int *hd,
               BIO          *bio_out, 
               unsigned int bits,
               EVP_PKEY     **private_key);


SSLStatus
SSL_gen_PUBkey(unsigned int *hd,
               BIO          *bio_out, 
               EVP_PKEY     *private_key, 
               EVP_PKEY     **public_key);



SSLStatus
SSL_gen_X509req(BIO *bio_out, EVP_PKEY *private_key, EVP_PKEY *public_key, unsigned int *hd);


#endif









