#ifndef SERVER_HANDLE_CLIENT_H
#define SERVER_HANDLE_CLIENT_H
#include "../utility_fun.h"
#include "../src_crypto/crypto_functions.h"
#include "../src_crypto/cert_fun.h"
#include "server_client_lists.c"
#include "../src_crypto/pfs.c"
void *handle_client(void *arg); 

#endif