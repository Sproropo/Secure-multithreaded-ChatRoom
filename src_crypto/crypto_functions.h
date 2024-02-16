#ifndef CRYPTO_FUNCTIONS_H
#define CRYPTO_FUNCTIONS_H
#include "../utility_fun.h"
#include "../macro.h"
int dig_env_encr(const EVP_CIPHER* cipher, EVP_PKEY* public_key, unsigned char* pt, int pt_len, unsigned char* encrypted_sym_key, int encrypted_sym_key_len, unsigned char* iv, unsigned char* ct);
int dig_env_decr(const EVP_CIPHER* cipher, EVP_PKEY* private_key, unsigned char* ct, int ct_len, unsigned char* encrypted_sym_key, int encrypted_sym_key_len, unsigned char* iv, unsigned char* pt);
int dig_sign_sgn(const EVP_MD* md, EVP_PKEY* private_key, unsigned char* pt, int pt_len, unsigned char* sign);
int dig_sign_verif( const EVP_MD* md,  EVP_PKEY* public_key, unsigned char* sign, int sign_size, unsigned char* pt, int pt_len);
int sym_auth_encr(const EVP_CIPHER* cipher, unsigned char* pt, int pt_len, unsigned char* key, unsigned char* iv, unsigned char* aad, int aad_len, unsigned char* ct, int tag_len, unsigned char* tag);
int sym_auth_decr(const EVP_CIPHER* cipher, unsigned char *ct, int ct_len, unsigned char *key, unsigned char *iv, unsigned char* aad, int aad_len, unsigned char *pt, int tag_len, unsigned char* tag);

#endif