#ifndef UTILITY_FUN_H
#define UTILITY_FUN_H
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/socket.h> //send
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stddef.h> //size_t 
#include <errno.h> 
#include <signal.h> //pipe
#include "macro.h"
void int_to_byte(int i, unsigned char* c);
int sendn(int sock, void *buf, size_t size);
int readn(int sock, void *buf, size_t size);
EVP_PKEY* get_public_key_to_PKEY(unsigned char* public_key, int len);
EVP_PKEY* read_private_key(char *file_name, char *passcode);
unsigned char* generate_random_bytes(int len);
unsigned char* get_public_key_to_byte(EVP_PKEY *public_key, int* pub_key_len);
EVP_PKEY* read_pub_key(char *file_name);
char *retrieve_passcode(char *passcode, char *filename);
unsigned char *malloc_and_check(unsigned char *pointer, int len_pointer);
char *malloc_and_check_s(char *pointer, int len_pointer);
#endif