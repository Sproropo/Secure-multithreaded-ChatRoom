#include "utility_fun.h"
void int_to_byte(int i, unsigned char* c){
  c[0] =  i & 0xFF;
  c[1] = (i>>8) & 0xFF;
  c[2] = (i>>16) & 0xFF;
  c[3] = (i>>24) & 0xFF;
}

int sendn(int sock, void *buf, size_t size) {
    size_t left = size;
    int r;
    int read = 0;
    char *bufptr = (char*)buf;

    while(left > 0) {
        if ((r = send(sock, bufptr, left, 0)) == -1 ) {
            if (errno == EINTR) continue;
            return -1;
        }

        if (r == 0) return 0;

        left    -= r;
        bufptr  += r;
        read = read + r;
    }
    return read;
}

int readn(int sock, void *buf, size_t size) {
    size_t left = size;
    int r = 0;
    int read = 0;
    char *bufptr = (char*)buf;

    while(left > 0) {
        if ((r = recv(sock ,bufptr,left,0)) == -1) {
            if (errno == EINTR){
                continue;
            }
            else{
                // if(errno == EAGAIN || errno == EWOULDBLOCK){ // to handle timeout on the socket
                //     return -2;
                // }
                  return -1; // generic error
            }
        }
        if (r == 0){ return -1; }   // handling socket close

        left    -= r;
        bufptr  += r;
        read = read + r;
    }
    return read;
}

EVP_PKEY* get_public_key_to_PKEY(unsigned char* public_key, int len){

    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, public_key, len);

    EVP_PKEY* pk = NULL;
    pk =  PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
    BIO_free(mbio);

    return pk;

}
EVP_PKEY* read_pub_key(char *file_name){
    FILE* fd_pub_key = fopen(file_name, "r");
    if(fd_pub_key == NULL){
      return NULL;
    }

    EVP_PKEY* public_key = PEM_read_PUBKEY(fd_pub_key, NULL, NULL, NULL);
    if(public_key == NULL){
      return NULL;
    }

    fclose(fd_pub_key);

    return public_key;

}

EVP_PKEY* read_private_key(char *file_name, char* passcode){

    FILE* fd_priv_key = fopen(file_name, "r");
    if(!fd_priv_key){
        perror("Error: can't retrieve the private key\n");
        fclose(fd_priv_key);
        return NULL;
    }

    EVP_PKEY* private_key = PEM_read_PrivateKey(fd_priv_key, NULL, NULL, passcode);
    if(!private_key){
        perror("Error: can't retrieve the private key\n");
        fclose(fd_priv_key);
        return NULL;
    }


    fclose(fd_priv_key);

    return private_key;
}

unsigned char* generate_random_bytes(int len){
    // Seed OpenSSL PRNG
    RAND_poll();
    int ret;

    unsigned char* k = NULL;
    k = malloc_and_check(k, len);
    if(!k){
        perror("Error in malloc\n");
        return NULL;
    }

    // Generates len random bytes
    ret = RAND_bytes((unsigned char*)&k[0], len);
    if(ret != 1){
        printf("ERROR: RAND_bytes fails!\n");
        return NULL;
    }
    return k;
}

unsigned char* get_public_key_to_byte(EVP_PKEY *public_key, int* pub_key_len){

    BIO *bio = NULL;
    unsigned char *key = NULL;
    int key_len = 0;

    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, public_key);

    key_len = BIO_pending(bio);
    *pub_key_len = key_len;

    key = (unsigned char *) malloc(sizeof(unsigned char) * key_len);

    BIO_read(bio, key, key_len);
    BIO_free_all(bio);

    return key;

}

char *retrieve_passcode(char *passcode, char *filename){
	FILE* ptr;
		char ch;
		int i = 1;
    
		ptr = fopen(filename, "r");
		if (NULL == ptr) {
			printf("file can't be opened \n");
		}
		do {
			ch = fgetc(ptr);
			i++;
		} while (ch != EOF);
		int j = 0;
		fseek(ptr, 0, SEEK_SET);
		passcode = malloc_and_check_s(passcode, i);
		do {
			ch = fgetc(ptr);
			passcode[j] = ch;
			j++;
		} while (j<i-2);
		fclose(ptr);
		return passcode;
}
unsigned char *malloc_and_check(unsigned char *pointer, int len_pointer) {
    pointer = malloc(len_pointer + 20);
    memset(pointer, 0, len_pointer);
    return pointer;
}
char *malloc_and_check_s(char *pointer, int len_pointer) {
    pointer = malloc(len_pointer + 20);
    memset(pointer, 0, len_pointer);
    return pointer;
}