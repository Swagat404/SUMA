#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

/**
let' create a user
 */
void generate_rsa_key_and_csr(const char *key_file, const char *csr_file) {
    RSA *rsa = NULL;
    EVP_PKEY *pkey = NULL;
    X509_REQ *req = NULL;
    FILE *key_fp = NULL;
    FILE *csr_fp = NULL;
    BIGNUM *bn = BN_new();
    
    if (!BN_set_word(bn, RSA_F4)) {
        fprintf(stderr, "Error setting exponent.\n");
        goto cleanup;
    }

    // Generate RSA key
    rsa = RSA_new();
    if (RSA_generate_key_ex(rsa, 2048, bn, NULL) != 1) {
        fprintf(stderr, "Error generating RSA key.\n");
        goto cleanup;
    }

    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        fprintf(stderr, "Error assigning RSA to EVP_PKEY.\n");
        goto cleanup;
    }
    rsa = NULL; // pkey owns rsa now

    // Write private key to file
    key_fp = fopen(key_file, "wb");
    if (!key_fp || !PEM_write_PrivateKey(key_fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Error writing private key to file.\n");
        goto cleanup;
    }
    fclose(key_fp);
    key_fp = NULL;

    // Create a new CSR
    req = X509_REQ_new();
    if (!req) {
        fprintf(stderr, "Error creating new X509_REQ.\n");
        goto cleanup;
    }

    X509_REQ_set_version(req, 1); // Version 1

    // Set the subject name
    X509_NAME *name = X509_NAME_new();
    if (!name) {
        fprintf(stderr, "Error creating X509_NAME.\n");
        goto cleanup;
    }

    // Add Common Name (CN) to the subject
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"myuser", -1, -1, 0);
    X509_REQ_set_subject_name(req, name);
    X509_NAME_free(name);

    // Set the public key for the CSR
    if (!X509_REQ_set_pubkey(req, pkey)) {
        fprintf(stderr, "Error setting public key.\n");
        goto cleanup;
    }

    // Sign the CSR with the private key
    if (!X509_REQ_sign(req, pkey, EVP_sha256())) {
        fprintf(stderr, "Error signing CSR.\n");
        goto cleanup;
    }

    // Write the CSR to a file
    csr_fp = fopen(csr_file, "wb");
    if (!csr_fp || !PEM_write_X509_REQ(csr_fp, req)) {
        fprintf(stderr, "Error writing CSR to file.\n");
        goto cleanup;
    }

    printf("RSA key and CSR generated successfully.\n");

cleanup:
    if (rsa) RSA_free(rsa);
    if (pkey) EVP_PKEY_free(pkey);
    if (req) X509_REQ_free(req);
    if (key_fp) fclose(key_fp);
    if (csr_fp) fclose(csr_fp);
    if (bn) BN_free(bn);
}

int main() {
    generate_rsa_key_and_csr("myuser.key", "myuser.csr");
    return 0;
}
