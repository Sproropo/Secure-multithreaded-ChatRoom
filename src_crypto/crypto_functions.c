#include "crypto_functions.h"
int dig_env_encr(const EVP_CIPHER* cipher, EVP_PKEY* public_key, unsigned char* pt, int pt_len, unsigned char* encrypted_sym_key, int encrypted_sym_key_len, unsigned char* iv, unsigned char* ct){

    int ret = 0;
    int outlen = 0;
    int ct_len = 0;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
      perror("Error in crypto\n");
      return 0;
    }

    /* Generate the IV and the symmetric key and encrypt the symmetric key */
    ret = EVP_SealInit(ctx, cipher, &encrypted_sym_key, &encrypted_sym_key_len, iv, &public_key, 1);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }

    /* Encrypt the plaintext */
    ret = EVP_SealUpdate(ctx, ct, &outlen, (unsigned char*)pt, pt_len);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }
    ct_len = outlen;

    /* Finalize the encryption and add the padding */
    ret = EVP_SealFinal(ctx, ct + ct_len, &outlen);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }
    ct_len += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return ct_len;

}
int dig_env_decr(const EVP_CIPHER* cipher, EVP_PKEY* private_key, unsigned char* ct, int ct_len, unsigned char* encrypted_sym_key, int encrypted_sym_key_len, unsigned char* iv, unsigned char* pt){

    int ret = 0;
    int outlen = 0;
    int pt_len = 0;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
      perror("Error in crypto\n");
      return 0;
    }

    /* Decrypt the symmetric key that will be used to decrypt the ciphertext */
    ret = EVP_OpenInit(ctx, cipher, encrypted_sym_key, encrypted_sym_key_len, iv, private_key);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }

    /* Decrypt the ciphertext */
    ret = EVP_OpenUpdate(ctx, pt, &outlen, ct, ct_len);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }
    pt_len += outlen;

    ret = EVP_OpenFinal(ctx, pt + pt_len, &outlen);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }

    pt_len += outlen;

    EVP_CIPHER_CTX_free(ctx);

    return pt_len;

}
int dig_sign_verif( const EVP_MD* md,  EVP_PKEY* public_key, unsigned char* sign, int sign_size, unsigned char* pt, int pt_len){

    int ret = 0;

    // Create the signature context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx) {
      perror("Error in crypto\n");
      return 0;
    }

    // Initialize the contex to verify digital siganture
    ret = EVP_VerifyInit(md_ctx, md);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_MD_CTX_free(md_ctx);
      return 0;
    }

    // Update the context
    ret = EVP_VerifyUpdate(md_ctx, pt, pt_len);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_MD_CTX_free(md_ctx);
      return 0;
    }

    // Finalize the context and verify the signature
    int verification_result = EVP_VerifyFinal(md_ctx, sign, sign_size, public_key);

    EVP_MD_CTX_free(md_ctx);

    // Return the verification (0 if invalid signature, -1 if some other error, 1 if success)
    return verification_result;
}
int dig_sign_sgn(const EVP_MD* md, EVP_PKEY* private_key, unsigned char* pt, int pt_len, unsigned char* sign){

    int ret = 0;

    /* Creating context */
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx) {
      perror("Error in crypto\n");
      return 0;
    }

    /* Initialized the context for digital signature */
    ret = EVP_SignInit(md_ctx, md);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_MD_CTX_free(md_ctx);
      return 0;
    }

    /* Update the context */
    ret = EVP_SignUpdate(md_ctx, pt, pt_len);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_MD_CTX_free(md_ctx);
      return 0;
    }

    /* Finalize the context and compute the digital signature */
    unsigned int sign_len = 0;
    ret = EVP_SignFinal(md_ctx, sign, &sign_len, private_key);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_MD_CTX_free(md_ctx);
      return 0;
    }

    EVP_MD_CTX_free(md_ctx);

    return sign_len;

}
int sym_auth_encr(const EVP_CIPHER* cipher, unsigned char* pt, int pt_len, unsigned char* key, unsigned char* iv, unsigned char* aad, int aad_len, unsigned char* ct, int tag_len, unsigned char* tag){

    int ret = 0;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
      perror("Error in crypto\n");
      return 0;
    }

    /* Encrypt init, it must be done only once */
    ret = EVP_EncryptInit(ctx, cipher, key, iv);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }

    int ct_len = 0;
    int written = 0;

    /* Aggiungo dati per authenticazione AAD */
    ret = EVP_EncryptUpdate(ctx, NULL, &written, aad, aad_len);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }

    /* Message encryption */
    ret = EVP_EncryptUpdate(ctx, ct, &written, pt, pt_len);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }

    /* Update ciphertext len */
    ct_len = ct_len + written;

    /* Encrypt Final, finalize the encryption and adds the padding */
    ret = EVP_EncryptFinal(ctx, ct + written, &written);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }

    /* Retrieves computed tag, and stores it in preallocated buffer tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag);

    ct_len = ct_len + written;

    /* Context free */
    EVP_CIPHER_CTX_free(ctx);

    return ct_len;
}
int sym_auth_decr(const EVP_CIPHER* cipher, unsigned char *ct, int ct_len, unsigned char *key, unsigned char *iv, unsigned char* aad, int aad_len, unsigned char *pt, int tag_len, unsigned char* tag){

    int ret = 0;
    int written = 0;

    /* Create and initialise the context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
      if(!ctx) {
      perror("Error in crypto\n");
      return 0;
    }

    /* Decrypt init, it must be done only once */
    ret = EVP_DecryptInit(ctx, cipher, key, iv);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }

    /* Add authentication data AAD */
    ret = EVP_DecryptUpdate(ctx, NULL, &written, aad, aad_len);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }

    /* Decrypt Update*/
    ret = EVP_DecryptUpdate(ctx, pt, &written, ct, ct_len);
    if(!ret) {
      perror("Error in crypto\n");
      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }

    /* Set received tag from buffer tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, tag);

    /* Decrypt Final, finalize the decryption and removes the padding */
    ret = EVP_DecryptFinal(ctx, pt + written, &written);
    if(ret == 0){ // tag mismatch
      return 0;
    }

    EVP_CIPHER_CTX_free(ctx);

    return 1;

}