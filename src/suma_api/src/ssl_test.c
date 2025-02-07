#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <stdlib.h>
#include <string.h>

// Structure to hold PEM formatted data
typedef struct {
    char* private_key;
    char* public_key;
    char* csr;
} PEMData;

// Helper function to get data from BIO
char* bio_to_string(BIO* bio) {
    if (!bio) return NULL;
    
    char* data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    if (len <= 0 || !data) return NULL;
    
    char* result = (char*)malloc(len + 1);
    if (!result) return NULL;
    
    memcpy(result, data, len);
    result[len] = '\0';
    
    return result;
}

// Generate RSA key pair and return as EVP_PKEY
EVP_PKEY* generate_rsa_key() {
    int ret = 0;
    RSA *r = NULL;
    BIGNUM *bne = NULL;
    EVP_PKEY *pKey = NULL;
    
    // Generate RSA key
    bne = BN_new();
    ret = BN_set_word(bne, RSA_F4);
    if(ret != 1) {
        BN_free(bne);
        return NULL;
    }
    
    r = RSA_new();
    ret = RSA_generate_key_ex(r, 2048, bne, NULL);
    BN_free(bne);
    
    if(ret != 1) {
        RSA_free(r);
        return NULL;
    }
    
    // Convert to EVP_PKEY
    pKey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pKey, r);
    
    return pKey;
}

// Generate CSR with given key and details
X509_REQ* generate_csr(EVP_PKEY *pKey, const char *country, const char *province, 
                      const char *city, const char *org, const char *common) {
    X509_REQ *x509_req = NULL;
    X509_NAME *x509_name = NULL;
    int ret;
    
    // Create X509 request structure
    x509_req = X509_REQ_new();
    ret = X509_REQ_set_version(x509_req, 0);
    if (ret != 1) {
        X509_REQ_free(x509_req);
        return NULL;
    }
    
    // Set subject name
    x509_name = X509_REQ_get_subject_name(x509_req);
    ret = X509_NAME_add_entry_by_txt(x509_name, "C", MBSTRING_ASC, 
                                    (const unsigned char*)country, -1, -1, 0);
    if (ret != 1) goto error;
    
    ret = X509_NAME_add_entry_by_txt(x509_name, "ST", MBSTRING_ASC,
                                    (const unsigned char*)province, -1, -1, 0);
    if (ret != 1) goto error;
    
    ret = X509_NAME_add_entry_by_txt(x509_name, "L", MBSTRING_ASC,
                                    (const unsigned char*)city, -1, -1, 0);
    if (ret != 1) goto error;
    
    ret = X509_NAME_add_entry_by_txt(x509_name, "O", MBSTRING_ASC,
                                    (const unsigned char*)org, -1, -1, 0);
    if (ret != 1) goto error;
    
    ret = X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC,
                                    (const unsigned char*)common, -1, -1, 0);
    if (ret != 1) goto error;
    
    // Set public key
    ret = X509_REQ_set_pubkey(x509_req, pKey);
    if (ret != 1) goto error;
    
    // Sign the request
    ret = X509_REQ_sign(x509_req, pKey, EVP_sha256());
    if (ret <= 0) goto error;
    
    return x509_req;
    
error:
    X509_REQ_free(x509_req);
    return NULL;
}

// Generate keys and CSR and return as PEM strings
PEMData* generate_key_and_csr(const char *country, const char *province,
                             const char *city, const char *organization,
                             const char *common) {
    PEMData* result = (PEMData*)calloc(1, sizeof(PEMData));
    if (!result) return NULL;
    
    EVP_PKEY *pKey = NULL;
    X509_REQ *req = NULL;
    BIO *bio = NULL;
    
    // Generate key pair
    pKey = generate_rsa_key();
    if (!pKey) goto cleanup;
    
    // Generate CSR
    req = generate_csr(pKey, country, province, city, organization, common);
    if (!req) goto cleanup;
    
    // Convert private key to PEM
    bio = BIO_new(BIO_s_mem());
    if (!bio) goto cleanup;
    PEM_write_bio_PrivateKey(bio, pKey, NULL, NULL, 0, NULL, NULL);
    result->private_key = bio_to_string(bio);
    BIO_free(bio);
    
    // Convert public key to PEM
    bio = BIO_new(BIO_s_mem());
    if (!bio) goto cleanup;
    PEM_write_bio_PUBKEY(bio, pKey);
    result->public_key = bio_to_string(bio);
    BIO_free(bio);
    
    // Convert CSR to PEM
    bio = BIO_new(BIO_s_mem());
    if (!bio) goto cleanup;
    PEM_write_bio_X509_REQ(bio, req);
    result->csr = bio_to_string(bio);
    BIO_free(bio);
    
    EVP_PKEY_free(pKey);
    X509_REQ_free(req);
    return result;
    
cleanup:
    if (pKey) EVP_PKEY_free(pKey);
    if (req) X509_REQ_free(req);
    if (bio) BIO_free(bio);
    if (result) {
        free(result->private_key);
        free(result->public_key);
        free(result->csr);
        free(result);
    }
    return NULL;
}

// Function to write PEM data to files
int write_pem_to_files(const PEMData* pem_data, 
                      const char* private_key_file,
                      const char* public_key_file,
                      const char* csr_file) {
    FILE *fp;
    int success = 1;
    
    if (private_key_file && pem_data->private_key) {
        fp = fopen(private_key_file, "w");
        if (fp) {
            fprintf(fp, "%s", pem_data->private_key);
            fclose(fp);
        } else {
            success = 0;
        }
    }
    
    if (public_key_file && pem_data->public_key) {
        fp = fopen(public_key_file, "w");
        if (fp) {
            fprintf(fp, "%s", pem_data->public_key);
            fclose(fp);
        } else {
            success = 0;
        }
    }
    
    if (csr_file && pem_data->csr) {
        fp = fopen(csr_file, "w");
        if (fp) {
            fprintf(fp, "%s", pem_data->csr);
            fclose(fp);
        } else {
            success = 0;
        }
    }
    
    return success;
}

// Function to free PEM data
void free_pem_data(PEMData* pem_data) {
    if (pem_data) {
        free(pem_data->private_key);
        free(pem_data->public_key);
        free(pem_data->csr);
        free(pem_data);
    }
}

int main() {
    // Generate keys and CSR
    PEMData* pem_data = generate_key_and_csr(
        "CA",          // Country
        "BC",          // Province
        "Vancouver",   // City
        "MyCompany",   // Organization
        "localhost"    // Common Name
    );
    
    if (pem_data) {
        // Print the generated data
        printf("Private Key:\n%s\n", pem_data->private_key);
        printf("Public Key:\n%s\n", pem_data->public_key);
        printf("CSR:\n%s\n", pem_data->csr);
        
        // Optionally write to files
        write_pem_to_files(pem_data, 
                          "private.pem",
                          "public.pem",
                          "request.csr");
        
        // Free the memory
        free_pem_data(pem_data);
    }
    
    return 0;
}