#include "ssl.h"

int main() {
    // Create a BIO object to capture output (e.g., stderr or stdout)
    BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE); 
    if (bio_out == NULL) {
        fprintf(stderr, "Failed to create BIO object.\n");
        return 1;
    }

    // Initialize the SSL library
    SSLStatus status = SSL_init(bio_out, SSL_DEBUG_ON);
    if (status != SSL_SUCCESS) {
        fprintf(stderr, "SSL initialization failed with error code: %d\n", status);
        BIO_free_all(bio_out);
        return 1;
    }

    // Prepare for RSA key generation
    unsigned int handle = 0;  // Handle for service claim verification (could be used for multithreading)
    EVP_PKEY *private_key = NULL;  // Will hold the generated private key

    // Generate RSA key with 2048 bits
    status = SSL_gen_RSAkey(bio_out, 2048, &handle, &private_key);
    if (status == SSL_SUCCESS) {
        SSL_DEBUG_SUCCESS(bio_out, SSL_DEBUG_ON, "main", "RSA private key generated successfully.");
    } else {
        SSL_DEBUG_ERROR(bio_out, SSL_DEBUG_ON, "main", "Failed to generate RSA private key.");
    }

    // Clean up and free resources
    SSL_cleanup();
    BIO_free_all(bio_out);

    return 0;
}
