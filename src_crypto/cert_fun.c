#include "cert_fun.h"
// #include "macro.h"

unsigned char* read_certificate(char *cert_file_path, int* buff_cert_size){

    // Reading certificate from file
    FILE* f_cert = fopen(cert_file_path, "r");
    if(!f_cert){ 
      perror("Error in certification\n");
      return NULL; 
      }

    X509* server_cert = PEM_read_X509(f_cert, NULL, NULL, NULL);
    if(!server_cert){ 
      perror("Error in certification\n");
      return NULL; 
     }
    fclose(f_cert);


    // Memory bio that has inside a memory buffer structured as a queue of bytes
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, server_cert); 


    // Serialize the certificate
    unsigned char* buff_cert = NULL;
    *buff_cert_size = BIO_get_mem_data(bio, &buff_cert);
    if((*buff_cert_size) < 0){
      perror("Error in certification\n");
      return NULL;
    }

    return buff_cert;

}

int cert_verification(char *CA_cert_filepath, char *CA_CRL_filepath, X509* server_cert){

    int ret = 0;

    // Loading CA's certificate file
    FILE* CA_server_cert_file = fopen(CA_cert_filepath, "r");
    if(!CA_server_cert_file) {
      perror("Error in certification\n");
      return 0;
    }

    // Reading CA's certificate from file
    X509* CA_cert = PEM_read_X509(CA_server_cert_file, NULL, NULL, NULL);
    fclose(CA_server_cert_file);
    if(!CA_cert) {
      perror("Error in certification\n");
      return 0;
    }
    

    // Loading CRL
    FILE* CRL_file = fopen(CA_CRL_filepath, "r");
    if(!CRL_file) {
      perror("Error in certification\n");
      return 0;
    }

    // Reading CRL from file
    X509_CRL* crl = PEM_read_X509_CRL(CRL_file, NULL, NULL, NULL);
    fclose(CRL_file);
    if(!crl) {
      perror("Error in certification\n");
      return 0;
    }

    // Build a store with the CA's certificate and the CRL
    X509_STORE* store = X509_STORE_new();
    if(!store) {
      perror("Error in certification\n");
      return 0;
    }

    // Adding CA's certificate to the store
    ret = X509_STORE_add_cert(store, CA_cert);
    if(!ret) {
      perror("Error in certification\n");
      return 0;
    }

    // Adding CA's CRL to the store
    ret = X509_STORE_add_crl(store, crl);
    if(!ret) {
      perror("Error in certification\n");
      return 0;
    }

    // Setting flag to use CRL
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(!ret) {
      perror("Error in certification\n");
      return 0;
    }


    // Verify the peer's certificate
    X509_STORE_CTX* cert_verif_ctx = X509_STORE_CTX_new();
    if(!cert_verif_ctx) {
      perror("Error in certification\n");
      return 0;
    }

    // Initialize the context for verfication
    ret = X509_STORE_CTX_init(cert_verif_ctx, store, server_cert, NULL);
    if(!ret) {
      perror("Error in certification\n");
      return 0;
    }

    // Verify peer's certificate
    ret = X509_verify_cert(cert_verif_ctx);
    if(ret != 1) {
        perror("ERROR: X509_verify_cert fails!\n");
        return 0;
    }

    return 1;
}
X509* deserialize_cert(unsigned char* cert_buff, int cert_size){

    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, cert_buff, cert_size);

    X509* server_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    BIO_free(bio);
    return server_cert;

}
