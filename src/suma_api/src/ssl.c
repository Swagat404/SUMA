#include "ssl.h"


static SSL_config g_config = {NULL, NULL, NULL, SSL_DEBUG_OFF};
static int initialized = 0;

/*
on the user end we can create a private and public key, then a certified user will be provided with a vpn config file. using the vpn config file 
a user can join the clustor. A kube-config file will be provided whihc allows a user to submit a scr request. csr request will be aprroved. After approval
a new kube-config will be shared that will be valid for ceratin amount of time with the user. After it expires a new csr must be submitted. 

so technically after the user have been authorised and connected to the vpn. he can be given the join token and allowed ot join the clustor. he must join with a specific 
hostname. let all the authentication happen at the gateway. for now once a user is in the network. any one can request a csr. anyone whi does this will be
provided a admin access to a namespace. also with an id that others can use to join there namespace.
*/

SSLStatus SSL_init(BIO *bio_out, SSLDebugLevel debug_level) {

    if (initialized) {
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_init()", "Library is already initialized.");
        return SSL_SUCCESS;
    }

    if (!bio_out || (debug_level != SSL_DEBUG_ON && debug_level != SSL_DEBUG_OFF)) {
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_init()", "Invalid parameters provided.");
        return SSL_ERROR_INVALID_PARAMS;
    }

    
  
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    g_config.pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!g_config.pctx) {
        SSL_DEBUG_ERROR(bio_out, debug_level, "SSL_init()", "Failed to create EVP_PKEY_CTX.");
        return SSL_ERROR_OPENSSL_INIT;
    }

    if (0 >= EVP_PKEY_keygen_init(g_config.pctx) ) {
        SSL_DEBUG_ERROR(bio_out, debug_level, "SSL_init", "Failed to initialize key generation.");
        EVP_PKEY_CTX_free(g_config.pctx);
        g_config.pctx = NULL;
        return SSL_ERROR_KEY_GENERATION;
    }

    g_config.pkey = NULL;
    g_config.bio_out = bio_out;
    g_config.debug_level = debug_level;

    initialized = 1;
    fprintf(stderr, "SSL Library initialized successfully.\n");
    
    return SSL_SUCCESS;
}




SSLStatus SSL_cleanup() 
{
    if (!initialized) {
        fprintf(stderr, "SSL_cleanup called but library was not initialized.\n");
        return SSL_ERROR_OPENSSL_INIT ;
    }

    if (g_config.pctx) {
        EVP_PKEY_CTX_free(g_config.pctx);
        g_config.pctx = NULL;
    }

    if (g_config.pkey) {
        EVP_PKEY_free(g_config.pkey);
        g_config.pkey = NULL;
    }

    if (g_config.bio_out) {
        BIO_free_all(g_config.bio_out);
        g_config.bio_out = NULL;
    }


    EVP_cleanup();                 // Cleans up EVP API
    CRYPTO_cleanup_all_ex_data();  // Cleans up ex_data
    ERR_free_strings();            // Frees all loaded error strings
   


    initialized = 0;

    fprintf(stderr, "SSL library resources cleaned up successfully.\n");
}


RSA * createRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }

    return rsa;
}

RSA * createRSAWithFilename(char * filename,int public)
{
    FILE * fp = fopen(filename,"rb");

    if(fp == NULL)
    {
        printf("Unable to open file %s \n",filename);
        return NULL;    
    }
    RSA *rsa= RSA_new() ;

    if(public)
    {
        rsa = PEM_read_RSA_PUBKEY(fp, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_RSAPrivateKey(fp, &rsa,NULL, NULL);
    }

    return rsa;
}


/*
memory issues here, in the sense that if pkey is free and some thread was still using a reference to it.
need to use shared pointer here. 
*/
SSLStatus
SSL_gen_RSAkey(unsigned int *hd,
               BIO          *bio_out, 
               unsigned int bits,
               EVP_PKEY     **private_key)
{
     if (!bio_out && !private_key){
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_gen_RSAkey", 
            "Invalid input parameters (at least on bio_out and private_key must be provided)");
        return SSL_ERROR_INVALID_PARAMS;
    }

    if (!hd) {  //verify the hanlde
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_gen_RSAkey", 
            "Invalid input parameters (NULL pointers)");
        return SSL_ERROR_INVALID_PARAMS;
    }

    if (bits < 2048) {
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_gen_RSAkey", 
            "Invalid input parameters (key size < 2048)");
        return SSL_ERROR_INVALID_PARAMS;
    }

    if (0 >= EVP_PKEY_CTX_set_rsa_keygen_bits(g_config.pctx, bits)) {
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_gen_RSAkey", 
            "Failed to set key length to %u bits", bits);
        return SSL_ERROR_KEY_GENERATION;
    }

    EVP_PKEY *pkey = NULL;

    if (0 >= EVP_PKEY_generate(g_config.pctx, &pkey)) {
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_gen_RSAkey", 
            "Failed to generate RSA key");
        return SSL_ERROR_KEY_GENERATION;
    }

    if (private_key != NULL) {
        *private_key = pkey;
        SSL_DEBUG_SUCCESS(g_config.bio_out, g_config.debug_level, "SSL_gen_RSAkey", 
            "Key generated successfully");
    } 
   
    if (PEM_write_bio_PrivateKey(bio_out, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_gen_RSAkey()", 
            "Failed to write key to BIO");
        EVP_PKEY_free(pkey);            //if the client has a reference to the key and currently using it this would cause problems,
        return SSL_ERROR_KEY_GENERATION;
    }

    SSL_DEBUG_SUCCESS(bio_out, g_config.debug_level, "SSL_gen_RSAkey()",
                      "Private key successfully generated.");
    return SSL_SUCCESS;
}




SSLStatus SSL_gen_PUBkey(unsigned int *hd,
    BIO *bio_out,
    EVP_PKEY *private_key,
    EVP_PKEY **public_key)
{
    if (!bio_out && !public_key) {
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_gen_RSAkey",
            "Invalid input parameters (at least one bio_out and public_key must be provided)");
        return SSL_ERROR_INVALID_PARAMS;
    }
    if (!private_key) {
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_gen_PUBkey()",
            "Invalid parameters. A valid private key is required");
        return SSL_ERROR_INVALID_PARAMS;
    }

    // Create a new public key
    EVP_PKEY *pub_key = NULL;
    BIGNUM *n = NULL, *e = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    
    // Get the provider from the private key
    const char *prov_name = EVP_PKEY_get0_provider_name(private_key);
    
    // Create a new context with the same provider
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, private_key, prov_name);
    if (!ctx) {
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_gen_PUBkey()",
            "Failed to create key context");
        return SSL_ERROR_KEY_GENERATION;
    }

    // Extract the public key using the appropriate provider
    if (EVP_PKEY_copy_parameters(pub_key, private_key) <= 0) {
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_gen_PUBkey()",
            "Failed to copy key parameters");
        EVP_PKEY_CTX_free(ctx);
        return SSL_ERROR_KEY_GENERATION;
    }

    // Get modulus and public exponent
    EVP_PKEY_get_bn_param(private_key, OSSL_PKEY_PARAM_RSA_N, &n);
    EVP_PKEY_get_bn_param(private_key, OSSL_PKEY_PARAM_RSA_E, &e);

    if (!n || !e) {
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_gen_PUBkey()",
            "Failed to extract key components");
        BN_free(n);
        BN_free(e);
        EVP_PKEY_CTX_free(ctx);
        return SSL_ERROR_KEY_GENERATION;
    }

    // Create public key parameters
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_gen_PUBkey()",
            "Failed to create parameter builder");
        BN_free(n);
        BN_free(e);
        EVP_PKEY_CTX_free(ctx);
        return SSL_ERROR_MEMORY;
    }

    // Add parameters
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e)) {
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_gen_PUBkey()",
            "Failed to add key parameters");
        OSSL_PARAM_BLD_free(bld);
        BN_free(n);
        BN_free(e);
        EVP_PKEY_CTX_free(ctx);
        return SSL_ERROR_KEY_GENERATION;
    }

    // Create parameter array
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) {
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_gen_PUBkey()",
            "Failed to create parameter array");
        OSSL_PARAM_BLD_free(bld);
        BN_free(n);
        BN_free(e);
        EVP_PKEY_CTX_free(ctx);
        return SSL_ERROR_KEY_GENERATION;
    }

    // Create the public key
    pub_key = EVP_PKEY_new();
    if (!pub_key || EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &pub_key, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_gen_PUBkey()",
            "Failed to create public key from parameters");
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        BN_free(n);
        BN_free(e);
        EVP_PKEY_CTX_free(ctx);
        if (pub_key) EVP_PKEY_free(pub_key);
        return SSL_ERROR_KEY_GENERATION;
    }

    if (public_key != NULL) {
        *public_key = pub_key;
        SSL_DEBUG_SUCCESS(g_config.bio_out, g_config.debug_level, "SSL_gen_RSAkey",
            "Key generated successfully");
    }

    // Write the public key to the BIO if provided
    if (bio_out && PEM_write_bio_PUBKEY(bio_out, pub_key) != 1) {
        SSL_DEBUG_ERROR(g_config.bio_out, g_config.debug_level, "SSL_gen_PUBkey()",
            "Failed to write key to BIO");
        EVP_PKEY_free(pub_key);
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        BN_free(n);
        BN_free(e);
        EVP_PKEY_CTX_free(ctx);
        return SSL_ERROR_KEY_GENERATION;
    }

    // Clean up
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(n);
    BN_free(e);
    EVP_PKEY_CTX_free(ctx);

    SSL_DEBUG_SUCCESS(bio_out, g_config.debug_level, "SSL_generate_public_key_from_private",
        "Public key successfully extracted.");

    return SSL_SUCCESS;
}

SSLStatus
SSL_gen_X509req(BIO *bio_out, EVP_PKEY *private_key, EVP_PKEY *public_key, unsigned int *hd) {
    if (!bio_out || !private_key || !public_key || !hd) {
        SSL_DEBUG_ERROR(bio_out, g_config.debug_level, "SSL_gen_X509req",
                        "Invalid parameters (NULL pointers).");
        return SSL_ERROR_INVALID_PARAMS;
    }

    X509_REQ *csr = X509_REQ_new();
    if (!csr) {
        SSL_DEBUG_ERROR(bio_out, g_config.debug_level, "SSL_gen_X509req",
                        "Failed to allocate X509_REQ structure.");
        return SSL_ERROR_CSR_GENERATION;
    }

    if (X509_REQ_set_version(csr, 1) != 1) {
        SSL_DEBUG_ERROR(bio_out, g_config.debug_level, "SSL_gen_X509req",
                        "Failed to set CSR version.");
        X509_REQ_free(csr);
        return SSL_ERROR_CSR_GENERATION;
    }

    X509_NAME *name = X509_NAME_new();
    if (!name) {
        SSL_DEBUG_ERROR(bio_out, g_config.debug_level, "SSL_gen_X509req",
                        "Failed to allocate X509_NAME structure.");
        X509_REQ_free(csr);
        return SSL_ERROR_MEMORY;
    }

    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, 
                                   (unsigned char *)"Example Common Name", -1, -1, 0) != 1) {
        SSL_DEBUG_ERROR(bio_out, g_config.debug_level, "SSL_gen_X509req",
                        "Failed to set common name in CSR.");
        X509_NAME_free(name);
        X509_REQ_free(csr);
        return SSL_ERROR_CSR_GENERATION;
    }

    if (X509_REQ_set_subject_name(csr, name) != 1) {
        SSL_DEBUG_ERROR(bio_out, g_config.debug_level, "SSL_gen_X509req",
                        "Failed to set subject name in CSR.");
        X509_NAME_free(name);
        X509_REQ_free(csr);
        return SSL_ERROR_CSR_GENERATION;
    }
    X509_NAME_free(name);

    if (X509_REQ_set_pubkey(csr, public_key) != 1) {
        SSL_DEBUG_ERROR(bio_out, g_config.debug_level, "SSL_gen_X509req",
                        "Failed to set public key in CSR.");
        X509_REQ_free(csr);
        return SSL_ERROR_CSR_GENERATION;
    }

    if (X509_REQ_sign(csr, private_key, EVP_sha256()) <= 0) {
        SSL_DEBUG_ERROR(bio_out, g_config.debug_level, "SSL_gen_X509req",
                        "Failed to sign CSR.");
        X509_REQ_free(csr);
        return SSL_ERROR_CSR_GENERATION;
    }

    if (PEM_write_bio_X509_REQ(bio_out, csr) != 1) {
        SSL_DEBUG_ERROR(bio_out, g_config.debug_level, "SSL_gen_X509req",
                        "Failed to write CSR to BIO.");
        X509_REQ_free(csr);
        return SSL_ERROR_FILE_OPERATION;
    }

    *hd = (unsigned int)(uintptr_t)csr;  // Return the handle for further use.
    SSL_DEBUG_SUCCESS(bio_out, g_config.debug_level, "SSL_gen_X509req",
                      "CSR generated successfully.");

    return SSL_SUCCESS;
}




/*



uint32_t SSL_gen_X509req()
{
	int				ret = 0;
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

	// 1. generate rsa key
	bne = BN_new();
	ret = BN_set_word(bne,e);
	if(ret != 1){
		goto free_all;
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if(ret != 1){
		goto free_all;
	}

	// 2. set version of x509 req
	x509_req = X509_REQ_new();
	ret = X509_REQ_set_version(x509_req, nVersion);
	if (ret != 1){
		goto free_all;
	}

	// 3. set subject of x509 req
	x509_name = X509_REQ_get_subject_name(x509_req);

	ret = X509_NAME_add_entry_by_txt(x509_name,"C", MBSTRING_ASC, (const unsigned char*)szCountry, -1, -1, 0);
	if (ret != 1){
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name,"ST", MBSTRING_ASC, (const unsigned char*)szProvince, -1, -1, 0);
	if (ret != 1){
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name,"L", MBSTRING_ASC, (const unsigned char*)szCity, -1, -1, 0);
	if (ret != 1){
		goto free_all;
	}	

	ret = X509_NAME_add_entry_by_txt(x509_name,"O", MBSTRING_ASC, (const unsigned char*)szOrganization, -1, -1, 0);
	if (ret != 1){
		goto free_all;
	}

	ret = X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC, (const unsigned char*)szCommon, -1, -1, 0);
	if (ret != 1){
		goto free_all;
	}

	// 4. set public key of x509 req
	pKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pKey, r);
	r = NULL;	// will be free rsa when EVP_PKEY_free(pKey)

	ret = X509_REQ_set_pubkey(x509_req, pKey);
	if (ret != 1){
		goto free_all;
	}

	// 5. set sign key of x509 req
	ret = X509_REQ_sign(x509_req, pKey, EVP_sha1());	// return x509_req->signature->length
	if (ret <= 0){
		goto free_all;
	}

	out = BIO_new_file(szPath,"w");
	ret = PEM_write_bio_X509_REQ(out, x509_req);

	// 6. free
free_all:
	X509_REQ_free(x509_req);
	BIO_free_all(out);

	EVP_PKEY_free(pKey);
	BN_free(bne);

	return (ret == 1);
}


*/