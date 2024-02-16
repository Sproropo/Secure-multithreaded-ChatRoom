#ifndef CERT_FUN_H
#define CERT_FUN_H
#include "../utility_fun.h"

unsigned char* read_certificate(char *cert_file_path, int* buff_cert_size);
int cert_verification(char *CA_cert_filepath, char *CA_CRL_filepath, X509* server_cert);
X509* deserialize_cert(unsigned char* cert_buff, int cert_size);



#endif