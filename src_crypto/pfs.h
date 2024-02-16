#ifndef PFS_H
#define PFS_H

#include "../src_server/server_client_lists.h"
#include "../utility_fun.c"
#include "crypto_functions.c"
#include "cert_fun.c"

// client-server auth
int send_random_nonce(int sock, unsigned char *usr_name); 
char *read_nonce(int sock, int* nonce); 

void generate_ephemeral_keys(EVP_PKEY** prv, EVP_PKEY** pub); 
int send_ephemeral_public_key(int sock, EVP_PKEY* ephemeral_pub_key, int nonce);
EVP_PKEY* read_ephemeral_public_key(int sock, int nonce, unsigned char* header);

int send_session_key(int sock, unsigned char* session_key, EVP_PKEY* eph_pubkey, unsigned char *usr_name, char *passcode); 
unsigned char* read_session_key(int sock, EVP_PKEY* eph_priv_key, EVP_PKEY* eph_pubkey, unsigned char *usr_name, int* session_key_len);

int message_exchange_send(unsigned char *message, client_info *user, int sock, unsigned char *session_key, int cont, int len, int control); 
unsigned char *message_exchange_read(unsigned char* payload, client_info *user, unsigned char *session_key, int cont, int control, int *len_msg_rcv); 

int message_exchange_send_pub_key(char *path_pub_key, client_info *user); 

// client-client auth
unsigned char* send_random_nonce_client(int *nonce, int *len);
int read_random_nonce_client(unsigned char *msg_rcv, int *nonce);
unsigned char* send_ephemeral_public_key_client(EVP_PKEY* ephemeral_pub_key, int nonce, char *name, char* passcode, int *len);
EVP_PKEY* read_ephemeral_public_key_client(unsigned char*msg_rcv, int nonce, EVP_PKEY *client_public_key);
unsigned char* send_session_key_client(unsigned char* session_key, EVP_PKEY* eph_pubkey, unsigned char *usr_name, char *passcode, int *len);
unsigned char* read_session_key_client(unsigned char* msg_rcv, EVP_PKEY* eph_priv_key, EVP_PKEY* eph_pubkey,EVP_PKEY* other_client_pub_key, int* session_key_len);
unsigned char *prepare_message(unsigned char *message, unsigned char *session_key, int cont, int *len);
unsigned char *retrieve_message(unsigned char* msg, unsigned char *session_key, int cont);
int message_exchange_send_exit(unsigned char *message, client_info *user);
#endif