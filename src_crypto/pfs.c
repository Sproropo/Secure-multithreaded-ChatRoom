#include "pfs.h"

int send_random_nonce(int sock, unsigned char *usr_name){

    int ret = 0;
	RAND_poll();
	int R = rand();

    // int to byte convesion
    unsigned char* r_byte = NULL;
	r_byte = malloc_and_check(r_byte, sizeof(int));
    if(!r_byte){
        perror("Error in malloc\n");
        return 0;
    }
    int_to_byte(R, r_byte);

    int msg_len = HEADER_LEN + sizeof(int) + strlen((const char *)usr_name);
    unsigned char* msg_buff = NULL;
	msg_buff = malloc_and_check(msg_buff, msg_len);
    if(!msg_buff){
        perror("Error in malloc\n");
        free(r_byte);
        return 0;
    }

    int payload_len = sizeof(int) + strlen((const char*)usr_name);
    unsigned char* payload_len_byte = NULL;
    payload_len_byte = malloc_and_check(payload_len_byte, sizeof(int));
    if(!payload_len_byte){
        perror("Error in malloc\n");
        free(r_byte);
        free(msg_buff);
        return 0;
    }
    int_to_byte(payload_len, payload_len_byte);

    memcpy(&msg_buff[0], payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg_buff[HEADER_LEN], r_byte, sizeof(int));
	memcpy(&msg_buff[HEADER_LEN + sizeof(int)], usr_name, strlen((const char*)usr_name));

    ret = sendn(sock, msg_buff, msg_len);
    if(ret == -1){
        perror("Error: Can't send data\n");
        free(r_byte);
	    free(msg_buff);
	    free(payload_len_byte);
        return 0;
    }

	free(r_byte);
	free(msg_buff);
	free(payload_len_byte);
    return R;
}

char *read_nonce(int sock, int* nonce){

    int ret = 0;
    char *error = "e";


    unsigned char* header = NULL;
    header = malloc_and_check(header, HEADER_LEN);
    if(!header){
        perror("Error in malloc\n");
        return error;
    }
    ret = readn(sock, header, HEADER_LEN);
    if(ret == -1) {
        free(header);
        return error;
    }

    int payload_dim=0;
    memcpy(&payload_dim, &header[0], sizeof(int)); // Converto da byte a intero

    unsigned char* rcv_payload_nonce = NULL;
    rcv_payload_nonce = malloc_and_check(rcv_payload_nonce, sizeof(int));
    if(!rcv_payload_nonce){
        perror("Error in malloc\n");
        free(header);
        return error;
    }
	ret = readn(sock, rcv_payload_nonce, sizeof(int));
    if(ret == -1) {
        free(header);
        free(rcv_payload_nonce);
        return error;
    }

    int usrname_len = payload_dim - sizeof(int) + 1;
    unsigned char* rcv_usrname = NULL;
    rcv_usrname = malloc_and_check(rcv_usrname, usrname_len);
    if(!rcv_usrname) {
        perror("Error in malloc\n");
        free(header);
        free(rcv_payload_nonce);
        return error;
    }
    memset(rcv_usrname, '\0', usrname_len);
    ret = readn(sock, rcv_usrname, usrname_len - 1);
    if(ret == -1) {
        free(header);
        free(rcv_payload_nonce);
        free(rcv_usrname);
        return error;
    }
   if(!search_client(rcv_usrname)) {
        free(header);
        free(rcv_payload_nonce);
        free(rcv_usrname);
        return NULL; 
        }

   if(!is_client_online(rcv_usrname)) {
        free(header);
        free(rcv_payload_nonce);
        free(rcv_usrname);
        return error; 
        }
    memcpy(nonce, rcv_payload_nonce, sizeof(int)); //Converting byte to int

    unsigned char *usr_name = NULL;
    usr_name = malloc_and_check(usr_name, strlen((const char*)rcv_usrname));
    if(!usr_name) {
        perror("Error in malloc\n");
        free(header);
        free(rcv_payload_nonce);
        free(rcv_usrname);
        return error;
    }
    memcpy(usr_name, rcv_usrname, usrname_len);

	free(header);
	free(rcv_usrname);
	free(rcv_payload_nonce);
    return (char*)usr_name;

}


void generate_ephemeral_keys(EVP_PKEY** prv, EVP_PKEY** pub) {

    RSA *rsa = NULL;
    BIGNUM* big_num = NULL;
    BIO *bio_prv = NULL;
    BIO *bio_pub = NULL;
    long e = RSA_F4; 


    big_num = BN_new();
    BN_set_word(big_num, e); 
    rsa = RSA_new();
    RSA_generate_key_ex(rsa, 2048, big_num, NULL);
    BN_free(big_num);


    bio_prv = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio_prv, rsa, NULL, NULL, 0, NULL, NULL);
    PEM_read_bio_PrivateKey(bio_prv, &(*prv), NULL, NULL);
    BIO_free_all(bio_prv);


    bio_pub = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio_pub, *prv);
    PEM_read_bio_PUBKEY(bio_pub, &(*pub), NULL, NULL);
    BIO_free_all(bio_pub);

}

int send_ephemeral_public_key(int sock, EVP_PKEY* ephemeral_pub_key, int nonce){
    int ret = 0;

    EVP_PKEY* priv_key = read_private_key("src_server/server_keys/Chat_key.pem", NULL);
    if(priv_key == NULL){
      perror("Error in send_ephemeral_public_key because of read_private_key\n");
      return 0;
    }

    unsigned char* nonce_byte = NULL;
    nonce_byte = malloc_and_check(nonce_byte, sizeof(int));
    if(!nonce_byte){
        perror("Error in malloc\n");
        return 0;
    }
    int_to_byte(nonce, nonce_byte);

    int eph_key_len = 0;
    unsigned char* client_eph_pub_key = get_public_key_to_byte(ephemeral_pub_key, &eph_key_len);
    if(client_eph_pub_key == NULL){
      perror("Error in send_ephemeral_public_key because of get_public_key_to_byte\n");
      return 0;
    }

    unsigned char* eph_key_len_byte = NULL;
    eph_key_len_byte = malloc_and_check(eph_key_len_byte, sizeof(int));
    if(!eph_key_len_byte){
        perror("Error in malloc\n");
        free(nonce_byte);
        return 0;
    }
    int_to_byte(eph_key_len, eph_key_len_byte);

    int msg_to_sign_len = sizeof(int) + eph_key_len;
    unsigned char* msg_to_sign = NULL;
    msg_to_sign = malloc_and_check(msg_to_sign, msg_to_sign_len);
    if(!msg_to_sign){
        perror("Error in malloc\n");
        free(nonce_byte);
        free(eph_key_len_byte);
        return 0;
    }
    memcpy((unsigned char*)msg_to_sign, (unsigned char*) nonce_byte, sizeof(int));
    memcpy((unsigned char*)&msg_to_sign[sizeof(int)], (unsigned char*) client_eph_pub_key, eph_key_len);


    int sign_len = EVP_PKEY_size(priv_key);
    unsigned char* sign = NULL;
    sign = malloc_and_check(sign, sign_len);
    if(!sign){
        perror("Error in malloc\n");
        free(nonce_byte);
        free(eph_key_len_byte);
        free(msg_to_sign);
        return 0;
    }
    sign_len = dig_sign_sgn(DIG_SIGN_CIPHER, priv_key, msg_to_sign, msg_to_sign_len, sign);
    if(sign_len < 0){
      perror("Error: invalid signature generation in send_ephemeral_public_key.");
      return 0;
    }

    unsigned char* sign_len_byte = NULL;
    sign_len_byte = malloc_and_check(sign_len_byte, sizeof(int));
    if(!sign_len_byte){
        perror("Error in malloc\n");
        free(nonce_byte);
        free(eph_key_len_byte);
        free(msg_to_sign);
        free(sign);
        return 0;
    }
    int_to_byte(sign_len, sign_len_byte);

    int cert_len = -1;
    unsigned char* cert = read_certificate("src_server/server_keys/Chat_cert.pem", &cert_len);
    if(cert == NULL){
      perror("Error in send_ephemeral_public_key because of read_certificate\n");
      return 0;
    }

    int payload_len = sizeof(int) + sign_len + sizeof(int) + eph_key_len + cert_len;
    unsigned char* payload_len_byte = NULL;
    payload_len_byte = malloc_and_check(payload_len_byte, sizeof(int));
    if(!payload_len_byte){
        perror("Error in malloc\n");
        free(nonce_byte);
        free(eph_key_len_byte);
        free(msg_to_sign);
        free(sign);
        free(sign_len_byte);
        return 0;
    }
    int_to_byte(payload_len, payload_len_byte);


    int msg_len = HEADER_LEN + payload_len;
    unsigned char* msg = NULL;
    msg = malloc_and_check(msg, msg_len);
    if(!msg){
        perror("Error in malloc\n");
        free(nonce_byte);
        free(eph_key_len_byte);
        free(msg_to_sign);
        free(sign);
        free(sign_len_byte);
        free(payload_len_byte);
        return 0;
    }

    memcpy((unsigned char*) &msg[0], payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN], sign_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN + sizeof(int)], sign, sign_len);
    memcpy((unsigned char*) &msg[HEADER_LEN + sizeof(int) + sign_len], eph_key_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[HEADER_LEN + sizeof(int) + sign_len + sizeof(int)], client_eph_pub_key, eph_key_len);
    memcpy((unsigned char*) &msg[HEADER_LEN + sizeof(int) + sign_len + sizeof(int) + eph_key_len], cert, cert_len);

    ret = sendn(sock, msg, msg_len);
    if(ret == -1) {
        perror("error while sending data\n");
        return 0;
    }
    free(nonce_byte);
    free(client_eph_pub_key);
    free(msg_to_sign);
    free(sign);
    free(sign_len_byte);
    free(payload_len_byte);
    free(msg);
    free(cert);
    free(eph_key_len_byte);
    free(priv_key);
    return 1;
}

EVP_PKEY* read_ephemeral_public_key(int sock, int nonce, unsigned char *header){

    int ret = 0;

    int payload_dim = 0;
    memcpy(&payload_dim, &header[0], sizeof(int)); 

    unsigned char* sign_len_byte = NULL;
    sign_len_byte = malloc_and_check(sign_len_byte, sizeof(int));
    if(!sign_len_byte){
        perror("Error in malloc\n");
        free(header);
        return NULL;
    }
    ret = readn(sock, sign_len_byte, sizeof(int));
    if(ret == -1){
        free(header);
        free(sign_len_byte);
        return NULL;
    }
    int sign_dim = 0;
    memcpy(&sign_dim, sign_len_byte, sizeof(int));

    unsigned char* buff_sign = NULL;
    buff_sign = malloc_and_check(buff_sign, sign_dim);
    if(!buff_sign){
        perror("Error in malloc\n");
        free(header);
        free(sign_len_byte);
        return NULL;
    }
    ret = readn(sock, buff_sign, sign_dim);
        if(ret == -1){
        free(header);
        free(sign_len_byte);
        free(buff_sign);
        return NULL;
    }

    unsigned char* eph_pubkey_byte = NULL;
    eph_pubkey_byte = malloc_and_check(eph_pubkey_byte, sizeof(int));
    if(!eph_pubkey_byte){
        perror("Error in malloc\n");
        free(header);
        free(sign_len_byte);
        free(buff_sign);
        return NULL;
    }
    ret = readn(sock, eph_pubkey_byte, sizeof(int));
    if(ret == -1){
        free(header);
        free(sign_len_byte);
        free(buff_sign);
        free(eph_pubkey_byte);
        return NULL;
    }
    int eph_pubkey_len = -1;
    memcpy(&eph_pubkey_len, eph_pubkey_byte, sizeof(int));

    unsigned char* buff_eph_key = NULL;
    buff_eph_key = malloc_and_check(buff_eph_key, eph_pubkey_len);
    if(!buff_eph_key){
        perror("Error in malloc\n");
        free(header);
        free(sign_len_byte);
        free(buff_sign);
        free(eph_pubkey_byte);
        return NULL;
    }
    ret = readn(sock, buff_eph_key, eph_pubkey_len);
    if(ret == -1){
        free(header);
        free(sign_len_byte);
        free(buff_sign);
        free(eph_pubkey_byte);
        free(buff_eph_key);
        return NULL;
    }

    int cert_len = payload_dim - eph_pubkey_len - sign_dim - sizeof(int)*2;
    unsigned char* buff_cert = NULL;
    buff_cert = malloc_and_check(buff_cert, cert_len);
    if(!buff_cert){
        perror("Error in malloc\n");
        free(header);
        free(sign_len_byte);
        free(buff_sign);
        free(eph_pubkey_byte);
        free(buff_eph_key);
        return NULL;
    }
    ret = readn(sock, buff_cert, cert_len);
    if(ret == -1){
        free(header);
        free(sign_len_byte);
        free(buff_sign);
        free(eph_pubkey_byte);
        free(buff_eph_key);
        free(buff_cert);
        return NULL;
    }

    X509* cert = deserialize_cert(buff_cert, cert_len);
    if(cert == NULL){
      perror("Error in read_ephemeral_public_key because of deserialize_cert\n");
      return NULL;
    }

    int result = cert_verification("src_client/clients_key/FoundationsOfCybersecurity_cert.pem", "src_client/clients_key/FoundationsOfCybersecurity_crl.pem", cert);
    if(result != 1){
        perror("Error: invalid certificate verification in read_ephemeral_public_key\n");
        free(header);
        free(sign_len_byte);
        free(buff_sign);
        free(eph_pubkey_byte);
        free(buff_eph_key);
        free(buff_cert);
        return NULL;
    }

    EVP_PKEY* server_pub_key = X509_get_pubkey(cert);
    if(server_pub_key == NULL){
      perror("Error in read_ephemeral_public_key because of X509_get_pubkey\n");
        free(header);
        free(sign_len_byte);
        free(buff_sign);
        free(eph_pubkey_byte);
        free(buff_eph_key);
        free(buff_cert);
        return NULL;
    }

    int signature_pt_len = sizeof(int) + eph_pubkey_len;
    unsigned char* signature_pt = NULL;
    signature_pt = malloc_and_check(signature_pt, signature_pt_len);
    if(!signature_pt){
        perror("Error in malloc\n");
        return NULL;
    }
    unsigned char* nonce_byte = NULL;
    nonce_byte = malloc_and_check(nonce_byte, sizeof(int));
    if(!nonce_byte){
        perror("Error in malloc\n");
        free(signature_pt);
        return NULL;
    }
    int_to_byte(nonce, nonce_byte);

    memcpy(signature_pt, nonce_byte, sizeof(int));
    memcpy(&signature_pt[sizeof(int)], buff_eph_key, eph_pubkey_len);


    int res = dig_sign_verif(DIG_SIGN_CIPHER, server_pub_key, buff_sign, sign_dim, signature_pt, signature_pt_len);
    EVP_PKEY* p = NULL;
    if(res == 1){
        p = get_public_key_to_PKEY(buff_eph_key, eph_pubkey_len);
        if(p == NULL){
          return NULL;
        }
    } else {
        perror("Error: invalid signature verification in read_ephemeral_public_key, (result error:\n");
        free(header);
        free(sign_len_byte);
        free(buff_sign);
        free(eph_pubkey_byte);
        free(buff_eph_key);
        free(buff_cert);
        return NULL;
    }

    free(header);
    free(sign_len_byte);
    free(buff_sign);
    free(eph_pubkey_byte);
    free(buff_eph_key);
    free(buff_cert);
    free(signature_pt);
    free(nonce_byte);
    EVP_PKEY_free(server_pub_key);
    return p;

}
int send_session_key(int sock, unsigned char* session_key, EVP_PKEY* eph_pubkey, unsigned char *usr_name, char* passcode){

    int ret = 0;
    int encrypted_symkey_len = EVP_PKEY_size(eph_pubkey); 
    unsigned char* encrypted_symkey = NULL;
    encrypted_symkey = malloc_and_check(encrypted_symkey, encrypted_symkey_len);
    if(!encrypted_symkey){
        perror("Error in malloc\n");
        return 0;
    }

    int iv_len = SESS_CIPHER_IV_LEN;
    unsigned char* iv = NULL;
    iv = malloc_and_check(iv, iv_len);
    if(!iv){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        return 0;
    }

    int session_key_len = SESS_CIPHER_KEY_LEN;
    int ct_len = session_key_len + SESS_CIPHER_BLOCK_DIM;
    unsigned char* ct = NULL;
    ct = malloc_and_check(ct, ct_len);
    if(!ct){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        free(iv);
        return 0;
    }

    ct_len = dig_env_encr(EVP_aes_256_cbc(), eph_pubkey, session_key, session_key_len, encrypted_symkey, encrypted_symkey_len, iv, ct);
    if(ct_len == 0){
      perror("Error: invalid encryption in send_session_key\n");
      return 0;
    }

    char *privkey_path = NULL;
    privkey_path = malloc_and_check_s(privkey_path, strlen("src_client/clients_key/") + strlen((const char*)usr_name)+ strlen("_privkey.pem")+1);
    sprintf(privkey_path, "%s%s%s","src_client/clients_key/" , (char*)usr_name, "_privkey.pem");
    EVP_PKEY* client_private_key = read_private_key((char*)privkey_path, passcode);
    free(privkey_path);
    if(!client_private_key){
        fprintf(stderr, "Can't retrieve the client's private key\n");
        return 0;
    }

    int sign_len = EVP_PKEY_size(client_private_key);
    unsigned char* sign = NULL;
    sign = malloc_and_check(sign, sign_len);
    if(!sign){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        free(iv);
        free(ct);
        return 0;
    }

    int eph_pubkey_len = -1;
    unsigned char* eph_pubkey_byte = get_public_key_to_byte(eph_pubkey, &eph_pubkey_len);


    int pt_to_sign_len = eph_pubkey_len + ct_len;
    unsigned char* pt_to_sign = NULL;
    pt_to_sign = malloc_and_check(pt_to_sign, pt_to_sign_len);
    if(!pt_to_sign){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        free(iv);
        free(ct);
        free(sign);
        return 0;
    }

    memcpy(pt_to_sign, ct, ct_len);
    memcpy(&pt_to_sign[ct_len], eph_pubkey_byte, eph_pubkey_len);

    sign_len = dig_sign_sgn(DIG_SIGN_CIPHER, client_private_key, pt_to_sign, pt_to_sign_len, sign);
    if(sign_len == 0){
      perror("Error: invalid signature generation in send_session_key\n");
      return 0;
    }

    int msg_len = HEADER_LEN + sizeof(int) + sign_len + sizeof(int) + ct_len + sizeof(int) + encrypted_symkey_len + iv_len;
    unsigned char* msg_buff = NULL;
    msg_buff = malloc_and_check(msg_buff, msg_len);
    if(!msg_buff){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        free(iv);
        free(ct);
        free(sign);
        free(pt_to_sign);
        return 0;
    }

    int payload_len = msg_len - HEADER_LEN;
    unsigned char* payload_len_byte = NULL;
    payload_len_byte = malloc_and_check(payload_len_byte, sizeof(int));
    if(!payload_len_byte){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        free(iv);
        free(ct);
        free(sign);
        free(pt_to_sign);
        free(msg_buff);
        return 0;
    }
    int_to_byte(payload_len, payload_len_byte);

    unsigned char* sign_len_byte = NULL;
    sign_len_byte = malloc_and_check(sign_len_byte, sizeof(int));
    if(!sign_len_byte){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        free(iv);
        free(ct);
        free(sign);
        free(pt_to_sign);
        free(msg_buff);
        free(payload_len_byte);
        return 0;
    }
    int_to_byte(sign_len, sign_len_byte);

    unsigned char* ct_len_byte = NULL;
    ct_len_byte = malloc_and_check(ct_len_byte, sizeof(int));
    if(!ct_len_byte){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        free(iv);
        free(ct);
        free(sign);
        free(pt_to_sign);
        free(msg_buff);
        free(payload_len_byte);
        free(sign_len_byte);
        return 0;
    }
    int_to_byte(ct_len, ct_len_byte);

    unsigned char* encrypted_symkey_len_byte = NULL;
    encrypted_symkey_len_byte = malloc_and_check(encrypted_symkey_len_byte, sizeof(int));
    if(!encrypted_symkey_len_byte){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        free(iv);
        free(ct);
        free(sign);
        free(pt_to_sign);
        free(msg_buff);
        free(payload_len_byte);
        free(sign_len_byte);
        free(ct_len_byte);
        return 0;
    }
    int_to_byte(encrypted_symkey_len, encrypted_symkey_len_byte);

    memcpy(&msg_buff[0], payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg_buff[HEADER_LEN], sign_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg_buff[HEADER_LEN + sizeof(int)], (unsigned char*) sign, sign_len);
    memcpy((unsigned char*) &msg_buff[HEADER_LEN + sizeof(int) + sign_len], (unsigned char*) ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg_buff[HEADER_LEN + sizeof(int) + sign_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg_buff[HEADER_LEN + sizeof(int) + sign_len + sizeof(int) + ct_len], (unsigned char*) encrypted_symkey_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg_buff[HEADER_LEN + sizeof(int) + sign_len + sizeof(int) + ct_len + sizeof(int)], (unsigned char*) encrypted_symkey, encrypted_symkey_len);
    memcpy((unsigned char*) &msg_buff[HEADER_LEN + sizeof(int) + sign_len + sizeof(int) + ct_len + sizeof(int) + encrypted_symkey_len], (unsigned char*) iv, iv_len);

    ret = sendn(sock, msg_buff, msg_len);
    if(ret == -1) {
        perror("Send failed\n");
        free(sign);
        free(encrypted_symkey);
        free(iv);
        free(ct);
        free(msg_buff);
        free(sign_len_byte);
        free(payload_len_byte);
        free(ct_len_byte);
        EVP_PKEY_free(client_private_key);
        return 0;
    }

    free(sign);
    free(encrypted_symkey);
    free(iv);
    free(ct);
    free(msg_buff);
    free(sign_len_byte);
    free(payload_len_byte);
    free(ct_len_byte);
    EVP_PKEY_free(client_private_key);

    return 1;

}

unsigned char* read_session_key(int sock, EVP_PKEY* eph_priv_key, EVP_PKEY* eph_pubkey, unsigned char *usr_name, int* session_key_len){

    int ret = 0;
    unsigned char* header = NULL;
    header = malloc_and_check(header, HEADER_LEN);
    if(!header){
        perror("Error in malloc\n");
        return NULL;
    }
    ret = readn(sock, header, HEADER_LEN);
    if(ret == -1) {
        perror("read_session_key failed\n");
        free(header);
        return NULL;
    }

    int payload_dim = 0;
    memcpy(&payload_dim, &header[0], sizeof(int)); 

    unsigned char* sign_len_byte = NULL;
    sign_len_byte = malloc_and_check(sign_len_byte, sizeof(int));
    if(!sign_len_byte){
        perror("Error in malloc\n");
        free(header);
        return NULL;
    }
    ret = readn(sock, sign_len_byte, sizeof(int));
    if(ret == -1) {
        perror("Read failed\n");
        free(header);
        free(sign_len_byte);
        return NULL;
    }

    int sign_len = 0;
    memcpy(&sign_len, sign_len_byte, sizeof(int)); 

    unsigned char* sign = NULL;
    sign = malloc_and_check(sign, sign_len);
    if(!sign){
        perror("Error in malloc\n");
        free(header);
        free(sign_len_byte);
        return NULL;
    }
    ret = readn(sock, sign, sign_len);
    if(ret == -1) {
        perror("Read failed\n");
        free(header);
        free(sign_len_byte);
        free(sign);
        return NULL;
    }

    unsigned char* ct_len_byte = NULL;
    ct_len_byte = malloc_and_check(ct_len_byte, sizeof(int));
    if(!ct_len_byte){
        perror("Error in malloc\n");
        free(header);
        free(sign_len_byte);
        free(sign);
        return NULL;
    }
    ret = readn(sock, ct_len_byte, sizeof(int));
    if(ret == -1) {
        perror("Read failed\n");
        free(header);
        free(sign_len_byte);
        free(sign);
        free(ct_len_byte);
        return NULL;
    }

    int ct_len = 0;
    memcpy(&ct_len, ct_len_byte, sizeof(int));

    unsigned char* ct = NULL;
    ct = malloc_and_check(ct, ct_len);
    if(!ct){
        perror("Error in malloc\n");
        free(header);
        free(sign_len_byte);
        free(sign);
        free(ct_len_byte);
        return NULL;
    }
    ret = readn(sock, ct, ct_len);
    if(ret == -1) {
        perror("Read failed\n");
        free(header);
        free(sign_len_byte);
        free(sign);
        free(ct_len_byte);
        free(ct);
        return NULL;
    }

    int eph_pubkey_len = -1;
    unsigned char* eph_pubkey_byte = get_public_key_to_byte(eph_pubkey, &eph_pubkey_len);
    if(eph_pubkey_byte == NULL){
      perror("Error: eph_pubkey_byte is null in read_session_key\n");
      return NULL;
    }
    int pt_to_verify_len = ct_len + eph_pubkey_len;
    unsigned char* pt_to_verify = NULL;
    pt_to_verify = malloc_and_check(pt_to_verify, pt_to_verify_len);
    if(!ct){
        perror("Error in malloc\n");
        free(header);
        free(sign_len_byte);
        free(sign);
        free(ct_len_byte);
        free(ct);
        return NULL;
    }
    memcpy(pt_to_verify, ct, ct_len);
    memcpy(&pt_to_verify[ct_len], eph_pubkey_byte, eph_pubkey_len);


        
    char *client_pubkey_path = NULL;
    client_pubkey_path = malloc_and_check_s(client_pubkey_path, strlen("src_server/server_keys/") + strlen((const char*)usr_name) + strlen("_pubkey.pem")+1); 
    sprintf(client_pubkey_path, "%s%s%s","src_server/server_keys/",(char*)usr_name, "_pubkey.pem");
    EVP_PKEY* client_public_key = read_pub_key(client_pubkey_path);
    if(client_public_key == NULL){
      perror("Error: client_public_key is null in read_session_key\n");
      return NULL;
    }
    free(client_pubkey_path);
    int result = dig_sign_verif(DIG_SIGN_CIPHER, client_public_key, sign, sign_len, pt_to_verify, pt_to_verify_len);
    if(result == 0){
        perror("Error: invalid signature verification in read_session_key\n");
        return NULL;
    }
    else{
        if(result == -1 || result == 0){
            perror("Error: error on signature verification OpenSSL API in read_session_key!\n");
            return NULL;
        }
    }

    unsigned char* encrypted_symkey_len_byte = NULL;
    encrypted_symkey_len_byte = malloc_and_check(encrypted_symkey_len_byte, sizeof(int));
    if(!encrypted_symkey_len_byte){
        perror("Error in malloc\n");
        free(header);
        free(sign_len_byte);
        free(sign);
        free(ct_len_byte);
        free(ct);
        free(pt_to_verify);
        return NULL;
    }
    ret = readn(sock, encrypted_symkey_len_byte, sizeof(int));
    if(ret == -1) {
        perror("Read failed\n");
        free(header);
        free(sign_len_byte);
        free(sign);
        free(ct_len_byte);
        free(ct);
        free(encrypted_symkey_len_byte);
        free(pt_to_verify);
        return NULL;
    }

    int encrypted_symkey_len = -1;
    memcpy(&encrypted_symkey_len, encrypted_symkey_len_byte, sizeof(int));

    unsigned char* encrypted_symkey_byte = NULL;
    encrypted_symkey_byte = malloc_and_check(encrypted_symkey_byte, encrypted_symkey_len);
    if(!encrypted_symkey_byte){
        perror("Error in malloc\n");
        free(header);
        free(sign_len_byte);
        free(sign);
        free(ct_len_byte);
        free(ct);
        free(pt_to_verify);
        free(encrypted_symkey_len_byte);
        return NULL;
    }
    ret =readn(sock, encrypted_symkey_byte, encrypted_symkey_len);
    if(ret == -1) {
        perror("Read failed\n");
        free(header);
        free(sign_len_byte);
        free(sign);
        free(ct_len_byte);
        free(ct);
        free(encrypted_symkey_len_byte);
        free(pt_to_verify);
        free(encrypted_symkey_byte);
        return NULL;
    }

    int iv_len = SESS_CIPHER_IV_LEN;
    unsigned char* iv = NULL;
    iv = malloc_and_check(iv, iv_len);
    if(!iv){
        perror("Error in malloc\n");
        free(header);
        free(sign_len_byte);
        free(sign);
        free(ct_len_byte);
        free(ct);
        free(pt_to_verify);
        free(encrypted_symkey_len_byte);
        free(encrypted_symkey_byte);
        return NULL;
    }
    ret = readn(sock, iv, iv_len);
    if(ret == -1) {
        perror("Read failed\n");
        free(header);
        free(sign_len_byte);
        free(sign);
        free(ct_len_byte);
        free(ct);
        free(encrypted_symkey_len_byte);
        free(pt_to_verify);
        free(encrypted_symkey_byte);
        free(iv);
        return NULL;
    }

    unsigned char* pt = NULL;
    pt = malloc_and_check(pt, ct_len);
    if(!pt){
        perror("Error in malloc\n");
        free(header);
        free(sign_len_byte);
        free(sign);
        free(ct_len_byte);
        free(ct);
        free(pt_to_verify);
        free(encrypted_symkey_len_byte);
        free(encrypted_symkey_byte);
        free(iv);
        return NULL;
    }
    *session_key_len = dig_env_decr(EVP_aes_256_cbc(), eph_priv_key, ct, ct_len, encrypted_symkey_byte, encrypted_symkey_len, iv, pt);
    if(*session_key_len == 0){
      perror("Error: invalid digital envelope decryption in read_session_key\n");
      return NULL;
    }
    free(header);
    free(sign_len_byte);
    free(sign);
    free(ct_len_byte);
    free(ct);
    free(iv);
    free(encrypted_symkey_len_byte);
    free(pt_to_verify);
    free(encrypted_symkey_byte);
    EVP_PKEY_free(client_public_key);
    return pt;
}

int message_exchange_send(unsigned char *message, client_info *user, int sock, unsigned char *session_key, int cont, int len, int control) {
    if(user){
        sock = user->local_sock;
    }
    int ret;
    unsigned char *sess_key = NULL;
    if(!session_key) {
        sess_key = user->session_key;
        } else {
            sess_key = session_key;
        }
    if(sess_key == NULL){
      perror("Error in send_usrs_online because of get_usr_session_key\n");
      return 0;
    }

    int pt_len;
    if(len == -1) {
    pt_len = strlen((const char*)message) + 1;
    } else {
        pt_len = len + 1;
    }
    unsigned char* pt = NULL;
    pt = malloc_and_check(pt, pt_len);
    if(!pt){
        perror("Error in malloc\n");
        return 0;
    }
    if(control == 0){
        pt[0] = MSG;    
    } else if(control == 2){
        pt[0] = EXIT_CHAT;
    } else {
        pt[0] = ALERT_CLIENT_EXITED;
    }
    memcpy(&pt[1], message, pt_len - 1);
    int iv_len = SESS_CIPHER_IV_LEN;
    unsigned char* iv = generate_random_bytes(iv_len);
    if(!iv){
      free(pt);
      return 0;
    }
    int ct_len = pt_len + SESS_CIPHER_BLOCK_DIM;
    unsigned char* ct = NULL;
    ct = malloc_and_check(ct, ct_len);
    if(!ct){
        free(pt);
        perror("Error in malloc\n");
        return 0;
    }
    int tag_len = TAG_LEN;
    unsigned char* tag = NULL;
    tag = malloc_and_check(tag, tag_len);
    if(!tag){
        free(pt);
        free(ct);
        perror("Error in malloc\n");
        return 0;
    }
    // AAD
    int aad_len = sizeof(int);
    unsigned char* aad = NULL;
    aad = malloc_and_check(aad, aad_len);
    if(!aad){
        free(pt);
        free(ct);
        free(tag);
        perror("Error in malloc\n");
        return 0;
    }
    unsigned char* cont_byte = NULL;
    cont_byte = malloc_and_check(cont_byte, sizeof(int));
    if(!cont_byte){
        free(pt);
        free(ct);
        free(tag);
        free(aad);
        perror("Error in malloc\n");
        return 0;
    }
    if(user) {
        cont = user->counter_server_client;
        user->counter_server_client += 1;
    }
    int_to_byte(cont, cont_byte);
    memcpy(&aad[0], cont_byte, sizeof(int));

    ct_len = sym_auth_encr(EVP_aes_256_gcm(), pt, pt_len, sess_key, iv, aad, aad_len, ct, tag_len, tag);
    if(ct_len == 0){
      perror("Error in send_usrs_online because of sym_auth_encr\n");
      return 0;
    }

    int msg_len = sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len + iv_len;
    int payload_len = msg_len;
    unsigned char* payload_len_byte = NULL;
    payload_len_byte = malloc_and_check(payload_len_byte, sizeof(int));
    if(!payload_len_byte){
        free(pt);
        free(ct);
        free(tag);
        free(aad);
        free(cont_byte);
        perror("Error in malloc\n");
        return 0;
    }
    int_to_byte(payload_len, payload_len_byte);
    unsigned char* ct_len_byte = NULL;
    ct_len_byte = malloc_and_check(ct_len_byte, sizeof(int));
    if(!ct_len_byte){
        free(pt);
        free(ct);
        free(tag);
        free(aad);
        free(cont_byte);
        free(payload_len_byte);
        perror("Error in malloc\n");
        return 0;
    }
    int_to_byte(ct_len, ct_len_byte);
    unsigned char* aad_len_byte = NULL;
    aad_len_byte = malloc_and_check(aad_len_byte, sizeof(int));
    if(!aad_len_byte){
        free(pt);
        free(ct);
        free(tag);
        free(aad);
        free(cont_byte);
        free(payload_len_byte);
        free(ct_len_byte);
        perror("Error in malloc\n");
        return 0;
    }
    int_to_byte(aad_len, aad_len_byte);
    unsigned char* msg = NULL;
    msg = malloc_and_check(msg, msg_len);
    if(!msg){
        free(pt);
        free(ct);
        free(tag);
        free(aad);
        free(cont_byte);
        free(payload_len_byte);
        free(ct_len_byte);
        free(aad_len_byte);
        perror("Error in malloc\n");
        return 0;
    }

    memcpy((unsigned char*) &msg[0], aad_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[sizeof(int)], aad, aad_len);
    memcpy((unsigned char*) &msg[sizeof(int) + aad_len], ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
    memcpy((unsigned char*) &msg[sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);

    ret = sendn(sock, payload_len_byte, PAYLOAD_LENGTH);
    if(ret == -1){
        perror("Error in send\n");
        return 0;
    }
    ret = sendn(sock, msg, msg_len);
    if(ret == -1){
        perror("Error in send\n");
        return 0; 
    }
    free(pt);
    free(iv);
    free(ct);
    free(tag);
    free(cont_byte);
    free(payload_len_byte);
    free(ct_len_byte);
    free(msg);
    free(aad_len_byte);
    free(aad);
    return 1;

}
unsigned char *message_exchange_read(unsigned char* payload, client_info *user, unsigned char *session_key, int cont, int control, int *len_msg_rcv){
    char *exit_from_chat = "exit";
    if(payload[0] == EXIT_CHAT){
        return (unsigned char *)exit_from_chat;
    }
    int ret = 0;
    unsigned char *sess_key = NULL;
    if(!session_key) {
        sess_key = user->session_key;
        } else {
            sess_key = session_key;
        }
    if(sess_key == NULL){
      perror("Error in send_usrs_online because of get_usr_session_key\n");
      return NULL;
    }

    int aad_len = 0;
    memcpy(&aad_len, &payload[0], PAYLOAD_LENGTH); 

    unsigned char* aad = NULL;
    aad = malloc_and_check(aad, aad_len);
    if(!aad){
        perror("Error in malloc\n");
        return NULL;
    }
    memcpy(aad, &payload[PAYLOAD_LENGTH], aad_len);
    
    int aad_check = 0;
    memcpy(&aad_check, aad, aad_len);
    if(user) {
        if(aad_check == user->counter_client_server) {
            memcpy(&cont, &aad[0], sizeof(int));
            user->counter_client_server += 1;
        } else {
            perror("message integrity lost because different aad\n");
            return NULL;
        }
    } else {
        if(aad_check != cont) {
            perror("message integrity lost because different aad\n");
            return NULL;
        }
    }

    unsigned int ct_len = 0;
    memcpy(&ct_len, &payload[PAYLOAD_LENGTH + aad_len], sizeof(int)); 
    unsigned char* ct = NULL;
    if(control == 1) {
        *len_msg_rcv = ct_len - 1;
    }
    ct = malloc_and_check(ct, ct_len);
    if(!ct){
        perror("Error in malloc\n");
        free(aad);
        return NULL;
    }
    memcpy(ct, &payload[PAYLOAD_LENGTH + aad_len + sizeof(int)], ct_len); 

    unsigned char* tag = NULL;
    tag = malloc_and_check(tag, TAG_LEN);
    if(!tag){
        perror("Error in malloc\n");
        free(aad);
        free(ct);
        return NULL;
    }
    memcpy(tag, &payload[PAYLOAD_LENGTH + aad_len + sizeof(int) + ct_len], TAG_LEN); 

    int iv_len = SESS_CIPHER_IV_LEN;
    unsigned char* iv = NULL;
    iv = malloc_and_check(iv, iv_len);
    if(!iv){
        perror("Error in malloc\n");
        free(aad);
        free(ct);
        free(tag);
        return NULL;
    }
    memcpy(iv, &payload[PAYLOAD_LENGTH + aad_len + sizeof(int) + ct_len + TAG_LEN], iv_len); 
    
    unsigned char* pt = NULL;
    pt = malloc_and_check(pt, ct_len + 1);
    if(!pt){
        perror("Error in malloc\n");
        free(aad);
        free(ct);
        free(tag);
        free(iv);
        return NULL;
    }
    memset(pt, '\0', ct_len + 1);
    
    ret = sym_auth_decr(EVP_aes_256_gcm(), ct, ct_len, sess_key, iv, aad, aad_len, pt, TAG_LEN, tag);
    if(ret == -1){
        perror("Error in sym_auth_decr");
        free(aad);
        free(ct);
        free(tag);
        free(iv);
        free(pt);
        return NULL;
    }
    if(!control){
        unsigned char *pt_new = NULL;
        pt_new = malloc_and_check(pt_new, ct_len);
        if(!pt_new) {
        perror("Error in malloc\n");
        free(aad);
        free(ct);
        free(tag);
        free(iv);
        free(pt);
        return NULL;
        }
        memcpy(&pt_new[0], pt + 1, ct_len);
        free(pt);
        free(aad);
        free(ct);
        free(tag);
        free(iv);
        return pt_new;
    } else {
        free(aad);
        free(ct);
        free(tag);
        free(iv);
        return pt;
    }

}

unsigned char* send_random_nonce_client(int *nonce, int *len){

	RAND_poll();
	int R = rand();
    *nonce = R;

    unsigned char* r_byte = NULL;
	r_byte = malloc_and_check(r_byte, sizeof(int));
    if(!r_byte){
        perror("Error in malloc\n");
        return NULL;
    }
    int_to_byte(R, r_byte);

    int msg_len = PAYLOAD_LENGTH + sizeof(int);
    *len = msg_len;
    unsigned char* msg_buff = NULL;
	msg_buff = malloc_and_check(msg_buff, msg_len);
    if(!msg_buff){
        perror("Error in malloc\n");
        free(r_byte);
        return NULL;
    }

    int payload_len = msg_len - PAYLOAD_LENGTH;
    unsigned char* payload_len_byte = NULL;
    payload_len_byte = malloc_and_check(payload_len_byte, msg_len);
    if(!payload_len_byte){
        perror("Error in malloc\n");
        free(r_byte);
        free(msg_buff);
        return NULL;
    }
    int_to_byte(payload_len, payload_len_byte);

    memcpy(&msg_buff[0], payload_len_byte, PAYLOAD_LENGTH);
    memcpy((unsigned char*) &msg_buff[PAYLOAD_LENGTH], r_byte, payload_len);

	free(r_byte);
	free(payload_len_byte);
    return msg_buff;
}

int read_nonce_client(int sock, int* nonce){

    int ret = 0;


    unsigned char* header = NULL;
    header = malloc_and_check(header, PAYLOAD_LENGTH);
    if(!header){
        perror("Error in malloc\n");
        return 0;
    }
    ret = readn(sock, header, PAYLOAD_LENGTH);
    if(ret == -1) {
        free(header);
        return 0;
    }

    int payload_dim=0;
    memcpy(&payload_dim, &header[0], PAYLOAD_LENGTH); 

    unsigned char* rcv_payload_nonce = NULL;
    rcv_payload_nonce = malloc_and_check(rcv_payload_nonce, sizeof(int));
    if(!rcv_payload_nonce){
        perror("Error in malloc\n");
        free(header);
        return 0;
    }
	ret = readn(sock, rcv_payload_nonce, sizeof(int));
    if(ret == -1) {
        free(header);
        free(rcv_payload_nonce);
        return 0;
    }

    memcpy(nonce, rcv_payload_nonce, sizeof(int)); 

	free(header);
	free(rcv_payload_nonce);
    return 1;
}


int message_exchange_send_pub_key(char *path_pub_key, client_info *user) {

    int ret;
    EVP_PKEY* client_public_key = read_pub_key(path_pub_key);
    if(client_public_key == NULL){
      perror("Error: client_public_key is null in read_session_key\n");
      return 0;
    }

    int pubkey_len = 0;
    unsigned char* client_public_key_byte = get_public_key_to_byte(client_public_key, &pubkey_len);
    if(client_public_key_byte == NULL){
      perror("Error in send_ephemeral_public_key because of get_public_key_to_byte\n");
      return 0;
    }

    unsigned char* pubkey_len_byte = NULL;
    pubkey_len_byte = malloc_and_check(pubkey_len_byte, sizeof(int));
    if(!pubkey_len_byte){
        perror("Error in malloc\n");
        free(client_public_key_byte);
        return 0;
    }
    int_to_byte(pubkey_len, pubkey_len_byte);

    int iv_len = SESS_CIPHER_IV_LEN;
    unsigned char* iv = generate_random_bytes(iv_len);
    if(!iv){
        perror("Error in malloc\n");
        free(client_public_key_byte);
        free(pubkey_len_byte);
        return 0;
    }
    int ct_len = pubkey_len + SESS_CIPHER_BLOCK_DIM;
    unsigned char* ct = NULL;
    ct = malloc_and_check(ct, ct_len);
    if(!ct){
        perror("Error in malloc\n");
        free(client_public_key_byte);
        free(pubkey_len_byte);
        free(iv);
        return 0;
    }
    int tag_len = TAG_LEN;
    unsigned char* tag = NULL;
    tag = malloc_and_check(tag, tag_len);
    if(!tag){
        free(client_public_key_byte);
        free(pubkey_len_byte);
        free(iv);
        free(ct);
        perror("Error in malloc\n");
        return 0;
    }
    int aad_len = sizeof(int);
    unsigned char* aad = NULL;
    aad = malloc_and_check(aad, aad_len);
    if(!aad){
        free(client_public_key_byte);
        free(pubkey_len_byte);
        free(iv);
        free(ct);
        free(tag);
        perror("Error in malloc\n");
        return 0;
    }
    unsigned char* cont_byte = NULL;
    cont_byte = malloc_and_check(cont_byte, sizeof(int));
    if(!cont_byte){
        free(client_public_key_byte);
        free(pubkey_len_byte);
        free(iv);
        free(ct);
        free(tag);
        free(aad);
        perror("Error in malloc\n");
        return 0;
    }
    int cont = user->counter_server_client;
    user->counter_server_client += 1;
    int_to_byte(cont, cont_byte);
    memcpy(&aad[0], cont_byte, sizeof(int));

    ct_len = sym_auth_encr(EVP_aes_256_gcm(), client_public_key_byte, pubkey_len, user->session_key, iv, aad, aad_len, ct, tag_len, tag);
    if(ct_len == 0){
      perror("Error in send_usrs_online because of sym_auth_encr\n");
      return 0;
    }

    int msg_len = PAYLOAD_LENGTH + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len + iv_len;
    int payload_len = msg_len - PAYLOAD_LENGTH;
    unsigned char* payload_len_byte = NULL;
    payload_len_byte = malloc_and_check(payload_len_byte, sizeof(int));
    if(!payload_len_byte){
        free(client_public_key_byte);
        free(pubkey_len_byte);
        free(ct);
        free(tag);
        free(aad);
        free(cont_byte);
        perror("Error in malloc\n");
        return 0;
    }
    int_to_byte(payload_len, payload_len_byte);
    unsigned char* ct_len_byte = NULL;
    ct_len_byte = malloc_and_check(ct_len_byte, sizeof(int));
    if(!ct_len_byte){
        free(client_public_key_byte);
        free(pubkey_len_byte);
        free(ct);
        free(tag);
        free(aad);
        free(cont_byte);
        free(payload_len_byte);
        perror("Error in malloc\n");
        return 0;
    }
    int_to_byte(ct_len, ct_len_byte);
    unsigned char* aad_len_byte = NULL;
    aad_len_byte = malloc_and_check(aad_len_byte, sizeof(int));
    if(!aad_len_byte){
        free(client_public_key_byte);
        free(pubkey_len_byte);
        free(ct);
        free(tag);
        free(aad);
        free(cont_byte);
        free(payload_len_byte);
        free(ct_len_byte);
        perror("Error in malloc\n");
        return 0;
    }
    int_to_byte(aad_len, aad_len_byte);
    unsigned char* msg = NULL;
    msg = malloc_and_check(msg, msg_len);
    if(!msg){
        free(client_public_key_byte);
        free(pubkey_len_byte);
        free(ct);
        free(tag);
        free(aad);
        free(cont_byte);
        free(payload_len_byte);
        free(ct_len_byte);
        free(aad_len_byte);
        perror("Error in malloc\n");
        return 0;
    }
    memcpy(msg, payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[PAYLOAD_LENGTH], aad_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[PAYLOAD_LENGTH + sizeof(int)], aad, aad_len);
    memcpy((unsigned char*) &msg[PAYLOAD_LENGTH + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[PAYLOAD_LENGTH + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[PAYLOAD_LENGTH + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
    memcpy((unsigned char*) &msg[PAYLOAD_LENGTH + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);
    ret = sendn(user->local_sock, msg, msg_len);
    if(ret == -1){
        perror("Error in send\n");
        return 0;
    }
    free(client_public_key_byte);
    free(pubkey_len_byte);
    free(iv);
    free(ct);
    free(tag);
    free(cont_byte);
    free(payload_len_byte);
    free(ct_len_byte);
    free(msg);
    free(aad_len_byte);
    free(aad);
    return 1;

}

EVP_PKEY *message_exchange_pub_read(int sock, unsigned char *session_key){
    
    int ret = 0;
    // L'header in questo caso e' solo la dimensione del payload
    unsigned char* header = NULL;
    header = malloc_and_check(header, PAYLOAD_LENGTH);
    if(!header){
        perror("Error in malloc\n");
        return NULL;
    }
    ret = readn(sock, header, PAYLOAD_LENGTH);
    if(ret == -1){
        perror("Error in readn\n");
        free(header);
        return NULL;
    }

    int payload_dim = 0;
    memcpy(&payload_dim, &header[0], sizeof(int)); 
    unsigned char* aad_len_byte = NULL;
    aad_len_byte = malloc_and_check(aad_len_byte, sizeof(int));
    if(!aad_len_byte){
        free(header);
        perror("Error in malloc\n");
        return NULL;
    }
    ret = readn(sock, aad_len_byte, sizeof(int));
    if(ret == -1){
        perror("Error in readn\n");
        free(header);
        free(aad_len_byte);
        return NULL;
    }
    int aad_len = 0;
    memcpy(&aad_len, aad_len_byte, sizeof(int)); 
    
    unsigned char* aad = NULL;
    aad = malloc_and_check(aad, aad_len);
    if(!aad){
        perror("Error in malloc\n");
        free(header);
        free(aad_len_byte);
        return NULL;
    }
    ret = readn(sock, aad, aad_len);
    if(ret == -1){
        perror("Error in readn\n");
        free(header);
        free(aad_len_byte);
        free(aad);
        return NULL;
    }

    unsigned char* pubkey_len_byte = NULL;
    pubkey_len_byte = malloc_and_check(pubkey_len_byte, sizeof(int));
    if(!pubkey_len_byte){
        perror("Error in malloc\n");
        free(header);
        free(aad_len_byte);
        free(aad);
        return NULL;
    }
    ret = readn(sock, pubkey_len_byte, sizeof(int));
    if(ret == -1){
        perror("Error in readn\n");
        free(header);
        free(aad_len_byte);
        free(aad);
        free(pubkey_len_byte);
        return NULL;
    }
    int pubkey_len = -1;
    memcpy(&pubkey_len, pubkey_len_byte, sizeof(int));

    // Prelevo la chiave publica del client con cui sto entrando in contatto
    unsigned char* buff_pub_key = NULL;
    buff_pub_key = malloc_and_check(buff_pub_key, pubkey_len);
    if(!buff_pub_key){
        perror("Error in malloc\n");
        free(header);
        free(aad_len_byte);
        free(aad);
        free(pubkey_len_byte);
        return NULL;
    }
    ret = readn(sock, buff_pub_key, pubkey_len);
    if(ret == -1){
        perror("Error in readn\n");
        free(header);
        free(aad_len_byte);
        free(aad);
        free(pubkey_len_byte);
        free(buff_pub_key);
        return NULL;
    }

    unsigned char* tag = NULL;
    tag = malloc_and_check(tag, TAG_LEN);
    if(!tag){
        perror("Error in malloc\n");
        free(header);
        free(aad_len_byte);
        free(aad);
        free(pubkey_len_byte);
        free(buff_pub_key);
        return NULL;
    }
    ret = readn(sock, tag, TAG_LEN);
    if(ret == -1){
        perror("Error in readn\n");
        free(header);
        free(aad_len_byte);
        free(aad);
        free(pubkey_len_byte);
        free(buff_pub_key);
        free(tag);
        return NULL;
    }

    int iv_len = SESS_CIPHER_IV_LEN;
    unsigned char* iv = NULL;
    iv = malloc_and_check(iv, iv_len);
    if(!iv){
        perror("Error in malloc\n");
        free(header);
        free(aad_len_byte);
        free(aad);
        free(pubkey_len_byte);
        free(buff_pub_key);
        free(tag);
        return NULL;
    }
    ret = readn(sock, iv, iv_len);
    if(ret == -1){
        perror("Error in readn\n");
        free(header);
        free(aad_len_byte);
        free(aad);
        free(pubkey_len_byte);
        free(buff_pub_key);
        free(tag);
        free(iv);
        return NULL;
    }
    unsigned char* pt = NULL;
    pt = malloc_and_check(pt, pubkey_len + 1);
    if(!pt){
        perror("Error in malloc\n");
        free(header);
        free(aad_len_byte);
        free(aad);
        free(pubkey_len_byte);
        free(buff_pub_key);
        free(tag);
        free(iv);
        return NULL;
    }
    memset(pt, '\0', pubkey_len + 1);
    ret = sym_auth_decr(EVP_aes_256_gcm(), buff_pub_key, pubkey_len, session_key, iv, aad, aad_len, pt, TAG_LEN, tag);
    if(ret == 0){
        perror("Error in symmetric auth decr\n");
        free(header);
        free(aad_len_byte);
        free(aad);
        free(pubkey_len_byte);
        free(buff_pub_key);
        free(tag);
        free(iv);
        free(pt);
        return NULL;
    }
    EVP_PKEY *p = NULL;
    p = get_public_key_to_PKEY(pt, pubkey_len + 1); 
    if(!p){
        perror("Error in allocation of EVP_PKEY\n");
        free(header);
        free(aad_len_byte);
        free(aad);
        free(pubkey_len_byte);
        free(buff_pub_key);
        free(tag);
        free(iv);
        free(pt);
        return NULL;
    }

        free(header);
        free(aad_len_byte);
        free(aad);
        free(pubkey_len_byte);
        free(buff_pub_key);
        free(tag);
        free(iv);
        free(pt);
        return p;
}


int read_random_nonce_client(unsigned char *msg_rcv, int *nonce) {
    int payload_dim = 0;
    memcpy(&payload_dim, &msg_rcv[0], PAYLOAD_LENGTH); 
    memcpy(nonce, &msg_rcv[PAYLOAD_LENGTH], sizeof(int)); 
    return 1;
}

unsigned char* send_ephemeral_public_key_client(EVP_PKEY* ephemeral_pub_key, int nonce, char* name, char *passcode, int *len){
    char *priv_key_path = NULL;
    priv_key_path = malloc_and_check_s(priv_key_path, strlen("src_client/clients_key/") + strlen(name) + strlen("_privkey.pem") + 1);
    sprintf(priv_key_path, "%s%s%s", "src_client/clients_key/", name, "_privkey.pem");
    EVP_PKEY* priv_key = read_private_key(priv_key_path, passcode);
    free(priv_key_path);
    if(priv_key == NULL){
      perror("Error in send_ephemeral_public_key because of read_private_key\n");
      return NULL;
    }

    unsigned char* nonce_byte = NULL;
    nonce_byte = malloc_and_check(nonce_byte, sizeof(int));
    if(!nonce_byte){
        perror("Error in malloc\n");
        return NULL;
    }
    int_to_byte(nonce, nonce_byte);

    int eph_key_len = -1;
    unsigned char* client_eph_pub_key = get_public_key_to_byte(ephemeral_pub_key, &eph_key_len);
    if(client_eph_pub_key == NULL){
      perror("Error in send_ephemeral_public_key because of get_public_key_to_byte\n");
      return NULL;
    }

    unsigned char* eph_key_len_byte = NULL;
    eph_key_len_byte = malloc_and_check(eph_key_len_byte, sizeof(int));
    if(!eph_key_len_byte){
        perror("Error in malloc\n");
        free(nonce_byte);
        return NULL;
    }
    int_to_byte(eph_key_len, eph_key_len_byte);

    int msg_to_sign_len = sizeof(int) + eph_key_len;
    unsigned char* msg_to_sign = NULL;
    msg_to_sign = malloc_and_check(msg_to_sign, msg_to_sign_len);
    if(!msg_to_sign){
        perror("Error in malloc\n");
        free(nonce_byte);
        free(eph_key_len_byte);
        return NULL;
    }
    memcpy((unsigned char*)msg_to_sign, (unsigned char*) nonce_byte, sizeof(int));
    memcpy((unsigned char*)&msg_to_sign[sizeof(int)], (unsigned char*) client_eph_pub_key, eph_key_len);

    int sign_len = EVP_PKEY_size(priv_key);
    unsigned char* sign = NULL;
    sign = malloc_and_check(sign, sign_len);
    if(!sign){
        perror("Error in malloc\n");
        free(nonce_byte);
        free(eph_key_len_byte);
        free(msg_to_sign);
        return NULL;
    }
    sign_len = dig_sign_sgn(DIG_SIGN_CIPHER, priv_key, msg_to_sign, msg_to_sign_len, sign);
    if(sign_len < 0){
        free(nonce_byte);
        free(eph_key_len_byte);
        free(msg_to_sign);
      perror("Error: invalid signature generation in send_ephemeral_public_key.");
      return NULL;
    }

    unsigned char* sign_len_byte = NULL;
    sign_len_byte = malloc_and_check(sign_len_byte, sizeof(int));
    if(!sign_len_byte){
        perror("Error in malloc\n");
        free(nonce_byte);
        free(eph_key_len_byte);
        free(msg_to_sign);
        free(sign);
        return NULL;
    }
    int_to_byte(sign_len, sign_len_byte);

    int payload_len = sizeof(int) + sign_len + sizeof(int) + eph_key_len;
    unsigned char* payload_len_byte = NULL;
    payload_len_byte = malloc_and_check(payload_len_byte, sizeof(int));
    if(!payload_len_byte){
        perror("Error in malloc\n");
        free(nonce_byte);
        free(eph_key_len_byte);
        free(msg_to_sign);
        free(sign);
        free(sign_len_byte);
        return NULL;
    }
    int_to_byte(payload_len, payload_len_byte);

    int msg_len = PAYLOAD_LENGTH + payload_len;
    *len = msg_len;
    unsigned char* msg = NULL;
    msg = malloc_and_check(msg, msg_len);
    if(!msg){
        perror("Error in malloc\n");
        free(nonce_byte);
        free(eph_key_len_byte);
        free(msg_to_sign);
        free(sign);
        free(sign_len_byte);
        free(payload_len_byte);
        return NULL;
    }
    memcpy((unsigned char*) &msg[0], payload_len_byte, PAYLOAD_LENGTH);
    memcpy((unsigned char*) &msg[PAYLOAD_LENGTH], sign_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[PAYLOAD_LENGTH + sizeof(int)], sign, sign_len);
    memcpy((unsigned char*) &msg[PAYLOAD_LENGTH + sizeof(int) + sign_len], eph_key_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[PAYLOAD_LENGTH + sizeof(int) + sign_len + sizeof(int)], client_eph_pub_key, eph_key_len);
    free(nonce_byte);
    free(client_eph_pub_key);
    free(msg_to_sign);
    free(sign);
    free(sign_len_byte);
    free(payload_len_byte);
    free(eph_key_len_byte);
    free(priv_key);
    return msg;

}

EVP_PKEY* read_ephemeral_public_key_client(unsigned char* msg_rcv, int nonce, EVP_PKEY *client_pub_key){
    int payload_dim = 0;
    memcpy(&payload_dim, &msg_rcv[0], sizeof(int)); 
    int sign_dim = 0;
    memcpy(&sign_dim, &msg_rcv[sizeof(int)], sizeof(int)); 
    unsigned char* buff_sign = NULL;
    buff_sign = malloc_and_check(buff_sign, sign_dim);
    if(!buff_sign){
        perror("Error in malloc\n");
        return NULL;
    }
    memcpy(&buff_sign[0], &msg_rcv[sizeof(int) + sizeof(int)], sign_dim); 
    int eph_pubkey_len = 0;
    memcpy(&eph_pubkey_len, &msg_rcv[sizeof(int) + sizeof(int) + sign_dim], sizeof(int));

    unsigned char* buff_eph_key = NULL;
    buff_eph_key = malloc_and_check(buff_eph_key, eph_pubkey_len);
    if(!buff_eph_key){
        perror("Error in malloc\n");
        free(buff_sign);
        return NULL;
    }
    memcpy(&buff_eph_key[0], &msg_rcv[sizeof(int) + sizeof(int) + sign_dim + sizeof(int)], eph_pubkey_len);
    int signature_pt_len = sizeof(int) + eph_pubkey_len;
    unsigned char* signature_pt = NULL;
    signature_pt = malloc_and_check(signature_pt, signature_pt_len);
    if(!signature_pt){
        perror("Error in malloc\n");
        return NULL;
    }
    unsigned char* nonce_byte = NULL;
    nonce_byte = malloc_and_check(nonce_byte, sizeof(int));
    if(!nonce_byte){
        perror("Error in malloc\n");
        free(signature_pt);
        return NULL;
    }
    int_to_byte(nonce, nonce_byte);

    memcpy(signature_pt, nonce_byte, sizeof(int));
    memcpy(&signature_pt[sizeof(int)], buff_eph_key, eph_pubkey_len);
    int res = dig_sign_verif(DIG_SIGN_CIPHER, client_pub_key, buff_sign, sign_dim, signature_pt, signature_pt_len);
    EVP_PKEY* p = NULL;
    if(res == 1){
        p = get_public_key_to_PKEY(buff_eph_key, eph_pubkey_len);
        if(p == NULL){
            perror("Error in get_public_key_to_PKEY\n");
          return NULL;
        }
    } else {
        perror("Error: invalid signature verification in read_ephemeral_public_key, (result error:\n");
        free(buff_sign);
        free(buff_eph_key);
        return NULL;
    }
    free(buff_sign);
    free(buff_eph_key);
    free(signature_pt);
    free(nonce_byte);
    EVP_PKEY_free(client_pub_key);
    return p;

}

unsigned char* send_session_key_client( unsigned char* session_key, EVP_PKEY* eph_pubkey, unsigned char *usr_name, char *passcode, int *len){

    int encrypted_symkey_len = EVP_PKEY_size(eph_pubkey);
    unsigned char* encrypted_symkey = NULL;
    encrypted_symkey = malloc_and_check(encrypted_symkey, encrypted_symkey_len);
    if(!encrypted_symkey){
        perror("Error in malloc\n");
        return NULL;
    }

    int iv_len = EVP_CIPHER_key_length(EVP_aes_256_cbc()) ;
    unsigned char* iv = NULL;
    iv = malloc_and_check(iv, iv_len);
    if(!iv){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        return NULL;
    }

    int session_key_len = SESS_CIPHER_KEY_LEN;
    int ct_len = session_key_len + EVP_CIPHER_block_size(EVP_aes_256_cbc());
    unsigned char* ct = NULL;
    ct = malloc_and_check(ct, ct_len);
    if(!ct){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        free(iv);
        return NULL;
    }

    ct_len = dig_env_encr(EVP_aes_256_cbc(), eph_pubkey, session_key, session_key_len, encrypted_symkey, encrypted_symkey_len, iv, ct);
    if(ct_len == 0){
      perror("Error: invalid encryption in send_session_key\n");
      return NULL;
    }

    char *privkey_path = NULL;
    privkey_path = malloc_and_check_s(privkey_path, strlen("src_client/clients_key/") + strlen((const char*)usr_name)+ strlen("_privkey.pem")+1);
    sprintf(privkey_path, "%s%s%s","src_client/clients_key/" , (char*)usr_name, "_privkey.pem");
    EVP_PKEY* client_private_key = read_private_key((char*)privkey_path, passcode);
    free(privkey_path);
    if(!client_private_key){
        perror("Can't retrieve the client's private key\n");
        return NULL;
    }

    int sign_len = EVP_PKEY_size(client_private_key);
    unsigned char* sign = NULL;
    sign = malloc_and_check(sign, sign_len);
    if(!sign){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        free(iv);
        free(ct);
        return NULL;
    }

    int eph_pubkey_len = -1;
    unsigned char* eph_pubkey_byte = get_public_key_to_byte(eph_pubkey, &eph_pubkey_len);

    int pt_to_sign_len = eph_pubkey_len + ct_len;
    unsigned char* pt_to_sign = NULL;
    pt_to_sign = malloc_and_check(pt_to_sign, pt_to_sign_len);
    if(!pt_to_sign){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        free(iv);
        free(ct);
        free(sign);
        return NULL;
    }

    memcpy(pt_to_sign, ct, ct_len);
    memcpy(&pt_to_sign[ct_len], eph_pubkey_byte, eph_pubkey_len);

    sign_len = dig_sign_sgn(DIG_SIGN_CIPHER, client_private_key, pt_to_sign, pt_to_sign_len, sign);
    if(sign_len == 0){
      perror("Error: invalid signature generation in send_session_key\n");
      return NULL;
    }

    int msg_len = PAYLOAD_LENGTH + sizeof(int) + sign_len + sizeof(int) + ct_len + sizeof(int) + encrypted_symkey_len + iv_len;
    unsigned char* msg_buff = NULL;
    msg_buff = malloc_and_check(msg_buff, msg_len);
    if(!msg_buff){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        free(iv);
        free(ct);
        free(sign);
        free(pt_to_sign);
        return NULL;
    }

    int payload_len = msg_len - PAYLOAD_LENGTH;
    *len = msg_len;
    unsigned char* payload_len_byte = NULL;
    payload_len_byte = malloc_and_check(payload_len_byte, sizeof(int));
    if(!payload_len_byte){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        free(iv);
        free(ct);
        free(sign);
        free(pt_to_sign);
        free(msg_buff);
        return NULL;
    }
    int_to_byte(payload_len, payload_len_byte);


    unsigned char* sign_len_byte = NULL;
    sign_len_byte = malloc_and_check(sign_len_byte, sizeof(int));
    if(!sign_len_byte){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        free(iv);
        free(ct);
        free(sign);
        free(pt_to_sign);
        free(msg_buff);
        free(payload_len_byte);
        return NULL;
    }
    int_to_byte(sign_len, sign_len_byte);

    unsigned char* ct_len_byte = NULL;
    ct_len_byte = malloc_and_check(ct_len_byte, sizeof(int));
    if(!ct_len_byte){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        free(iv);
        free(ct);
        free(sign);
        free(pt_to_sign);
        free(msg_buff);
        free(payload_len_byte);
        free(sign_len_byte);
        return NULL;
    }
    int_to_byte(ct_len, ct_len_byte);

    unsigned char* encrypted_symkey_len_byte = NULL;
    encrypted_symkey_len_byte = malloc_and_check(encrypted_symkey_len_byte, sizeof(int));
    if(!encrypted_symkey_len_byte){
        perror("Error in malloc\n");
        free(encrypted_symkey);
        free(iv);
        free(ct);
        free(sign);
        free(pt_to_sign);
        free(msg_buff);
        free(payload_len_byte);
        free(sign_len_byte);
        free(ct_len_byte);
        return NULL;
    }
    int_to_byte(encrypted_symkey_len, encrypted_symkey_len_byte);

    memcpy(&msg_buff[0], payload_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg_buff[PAYLOAD_LENGTH], sign_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg_buff[PAYLOAD_LENGTH + sizeof(int)], (unsigned char*) sign, sign_len);
    memcpy((unsigned char*) &msg_buff[PAYLOAD_LENGTH + sizeof(int) + sign_len], (unsigned char*) ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg_buff[PAYLOAD_LENGTH + sizeof(int) + sign_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg_buff[PAYLOAD_LENGTH + sizeof(int) + sign_len + sizeof(int) + ct_len], (unsigned char*) encrypted_symkey_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg_buff[PAYLOAD_LENGTH + sizeof(int) + sign_len + sizeof(int) + ct_len + sizeof(int)], (unsigned char*) encrypted_symkey, encrypted_symkey_len);
    memcpy((unsigned char*) &msg_buff[PAYLOAD_LENGTH + sizeof(int) + sign_len + sizeof(int) + ct_len + sizeof(int) + encrypted_symkey_len], (unsigned char*) iv, iv_len);
    free(sign);
    free(encrypted_symkey);
    free(iv);
    free(ct);
    free(sign_len_byte);
    free(payload_len_byte);
    free(ct_len_byte);
    EVP_PKEY_free(client_private_key);

    return msg_buff;

}

unsigned char* read_session_key_client(unsigned char* msg_rcv, EVP_PKEY* eph_priv_key, EVP_PKEY* eph_pubkey, EVP_PKEY* other_client_pub_key, int* session_key_len){

    int payload_dim = 0;
    memcpy(&payload_dim, &msg_rcv[0], PAYLOAD_LENGTH);

    int sign_len = 0;
    memcpy(&sign_len, &msg_rcv[PAYLOAD_LENGTH], sizeof(int)); 

    unsigned char* sign = NULL;
    sign = malloc_and_check(sign, sign_len);
    if(!sign){
        perror("Error in malloc\n");
        return NULL;
    }
    memcpy(&sign[0], &msg_rcv[PAYLOAD_LENGTH + sizeof(int)], sign_len); 

    int ct_len = 0;
    memcpy(&ct_len, &msg_rcv[PAYLOAD_LENGTH + sizeof(int) + sign_len], sizeof(int)); 

    unsigned char* ct = NULL;
    ct = malloc_and_check(ct, ct_len);
    if(!ct){
        perror("Error in malloc\n");
        free(sign);
        return NULL;
    }
    memcpy(&ct[0], &msg_rcv[PAYLOAD_LENGTH + sizeof(int) + sign_len + sizeof(int)], ct_len); 

    int eph_pubkey_len = -1;
    unsigned char* eph_pubkey_byte = get_public_key_to_byte(eph_pubkey, &eph_pubkey_len);
    if(eph_pubkey_byte == NULL){
      perror("Error: eph_pubkey_byte is null in read_session_key\n");
      return NULL;
    }
    int pt_to_verify_len = ct_len + eph_pubkey_len;
    unsigned char* pt_to_verify = NULL;
    pt_to_verify = malloc_and_check(pt_to_verify, pt_to_verify_len);
    if(!ct){
        perror("Error in malloc\n");
        free(sign);
        free(ct);
        return NULL;
    }
    memcpy(pt_to_verify, ct, ct_len);
    memcpy(&pt_to_verify[ct_len], eph_pubkey_byte, eph_pubkey_len);

    int result = dig_sign_verif(DIG_SIGN_CIPHER, other_client_pub_key, sign, sign_len, pt_to_verify, pt_to_verify_len);
    if(result == 0){
        perror("Error: invalid signature verification in read_session_key\n");
        return NULL;
    }
    else{
        if(result == -1 || result == 0){
            perror("Error: error on signature verification OpenSSL API in read_session_key!\n");
            return NULL;
        }
    }

    int encrypted_symkey_len = -1;
    memcpy(&encrypted_symkey_len, &msg_rcv[PAYLOAD_LENGTH + sizeof(int) + sign_len + sizeof(int) + ct_len], sizeof(int)); 

    unsigned char* encrypted_symkey_byte = NULL;
    encrypted_symkey_byte = malloc_and_check(encrypted_symkey_byte, encrypted_symkey_len);
    if(!encrypted_symkey_byte){
        perror("Error in malloc\n");
        free(sign);
        free(ct);
        free(pt_to_verify);
        return NULL;
    }
    memcpy(&encrypted_symkey_byte[0], &msg_rcv[PAYLOAD_LENGTH + sizeof(int) + sign_len + sizeof(int) + ct_len + sizeof(int)], encrypted_symkey_len); 

    int iv_len = SESS_CIPHER_IV_LEN;
    unsigned char* iv = NULL;
    iv = malloc_and_check(iv, iv_len);
    if(!iv){
        perror("Error in malloc\n");
        free(sign);
        free(ct);
        free(pt_to_verify);
        free(encrypted_symkey_byte);
        return NULL;
    }
    memcpy(&iv[0], &msg_rcv[PAYLOAD_LENGTH + sizeof(int) + sign_len + sizeof(int) + ct_len + sizeof(int) + encrypted_symkey_len], iv_len); 

    unsigned char* pt = NULL;
    pt = malloc_and_check(pt, ct_len);
    if(!pt){
        perror("Error in malloc\n");
        free(sign);
        free(ct);
        free(pt_to_verify);
        free(encrypted_symkey_byte);
        free(iv);
        return NULL;
    }
    *session_key_len = dig_env_decr(EVP_aes_256_cbc(), eph_priv_key, ct, ct_len, encrypted_symkey_byte, encrypted_symkey_len, iv, pt);
    if(*session_key_len == 0){
      perror("Error: invalid digital envelope decryption in read_session_key\n");
      return NULL;
    }
    free(sign);
    free(ct);
    free(iv);
    free(pt_to_verify);
    free(encrypted_symkey_byte);
    return pt;
}


unsigned char *prepare_message(unsigned char *message, unsigned char *session_key, int cont, int *len) {
    unsigned char *header = NULL;
    header = malloc_and_check(header, PAYLOAD_LENGTH);
    if(!header){
        perror("error in malloc\n");
        return NULL;
    }

    int pt_len = strlen((const char*)message);
    unsigned char* pt = NULL;
    pt = malloc_and_check(pt, pt_len);
    if(!pt){
        perror("Error in malloc\n");
        return 0;
    }
    memcpy(pt, message, pt_len);
    int iv_len = SESS_CIPHER_IV_LEN;
    unsigned char* iv = generate_random_bytes(iv_len);
    if(!iv){
      free(pt);
      return 0;
    }
    int ct_len = pt_len + SESS_CIPHER_BLOCK_DIM;
    unsigned char* ct = NULL;
    ct = malloc_and_check(ct, ct_len);
    if(!ct){
        free(pt);
        perror("Error in malloc\n");
        return 0;
    }
    int tag_len = TAG_LEN;
    unsigned char* tag = NULL;
    tag = malloc_and_check(tag, tag_len);
    if(!tag){
        free(pt);
        free(ct);
        perror("Error in malloc\n");
        return 0;
    }
    // AAD
    int aad_len = sizeof(int);
    unsigned char* aad = NULL;
    aad = malloc_and_check(aad, aad_len);
    if(!aad){
        free(pt);
        free(ct);
        free(tag);
        perror("Error in malloc\n");
        return 0;
    }
    unsigned char* cont_byte = NULL;
    cont_byte = malloc_and_check(cont_byte, sizeof(int));
    if(!cont_byte){
        free(pt);
        free(ct);
        free(tag);
        free(aad);
        perror("Error in malloc\n");
        return 0;
    }
    int_to_byte(cont, cont_byte);
    memcpy(&aad[0], cont_byte, sizeof(int));
// Cripto il plaintext (messaggio del client o del server)
    ct_len = sym_auth_encr(EVP_aes_256_gcm(), pt, pt_len, session_key, iv, aad, aad_len, ct, tag_len, tag);
    if(ct_len == 0){
      perror("Error in send_usrs_online because of sym_auth_encr\n");
      return 0;
    }

    int msg_len = PAYLOAD_LENGTH +  sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len + iv_len;
    *len = msg_len;
    int payload_len = msg_len - PAYLOAD_LENGTH;
    int_to_byte(payload_len, header);
    
    unsigned char* ct_len_byte = NULL;
    ct_len_byte = malloc_and_check(ct_len_byte, sizeof(int));
    if(!ct_len_byte){
        free(pt);
        free(ct);
        free(tag);
        free(aad);
        free(cont_byte);
        perror("Error in malloc\n");
        return 0;
    }
    int_to_byte(ct_len, ct_len_byte);
    unsigned char* aad_len_byte = NULL;
    aad_len_byte = malloc_and_check(aad_len_byte, sizeof(int));
    if(!aad_len_byte){
        free(pt);
        free(ct);
        free(tag);
        free(aad);
        free(cont_byte);
        free(ct_len_byte);
        perror("Error in malloc\n");
        return 0;
    }
    int_to_byte(aad_len, aad_len_byte);
    unsigned char* msg = NULL;
    msg = malloc_and_check(msg, msg_len);
    if(!msg){
        free(pt);
        free(ct);
        free(tag);
        free(aad);
        free(cont_byte);
        free(ct_len_byte);
        free(aad_len_byte);
        perror("Error in malloc\n");
        return 0;
    }
    memcpy((unsigned char*) &msg[0], header, PAYLOAD_LENGTH);
    memcpy((unsigned char*) &msg[PAYLOAD_LENGTH], aad_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[PAYLOAD_LENGTH + sizeof(int)], aad, aad_len);
    memcpy((unsigned char*) &msg[PAYLOAD_LENGTH + sizeof(int) + aad_len], ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[PAYLOAD_LENGTH + sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[PAYLOAD_LENGTH + sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
    memcpy((unsigned char*) &msg[PAYLOAD_LENGTH + sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);

    free(pt);
    free(iv);
    free(header);
    free(ct);
    free(tag);
    free(cont_byte);
    free(ct_len_byte);
    free(aad_len_byte);
    free(aad);
    return msg;

}

unsigned char *retrieve_message(unsigned char* msg, unsigned char *session_key, int cont){
    int ret = 0;
    int aad_len = 0;
    int aad_check = 0;
    memcpy(&aad_len, &msg[PAYLOAD_LENGTH], sizeof(int)); 
    unsigned char* aad = NULL;
    aad = malloc_and_check(aad, aad_len);
    if(!aad){
        perror("Error in malloc\n");
        return NULL;
    }
    memcpy(aad, &msg[PAYLOAD_LENGTH + sizeof(int)], aad_len);
    memcpy(&aad_check, &aad[0], sizeof(int));
    if(aad_check != cont) {
        perror("Message integrity lost because of aad in retrieve message\n");
        return NULL;
    }
    int ct_len = 0;
    memcpy(&ct_len, &msg[PAYLOAD_LENGTH + sizeof(int) + aad_len], sizeof(int)); 
    unsigned char* ct = NULL;
    ct = malloc_and_check(ct, ct_len);
    if(!ct){
        perror("Error in malloc\n");
        free(aad);
        return NULL;
    }
    memcpy(ct, &msg[PAYLOAD_LENGTH + sizeof(int) + aad_len + sizeof(int)], ct_len); 

    unsigned char* tag = NULL;
    tag = malloc_and_check(tag, TAG_LEN);
    if(!tag){
        perror("Error in malloc\n");
        free(aad);
        free(ct);
        return NULL;
    }
    memcpy(tag, &msg[PAYLOAD_LENGTH + sizeof(int) + aad_len + sizeof(int) + ct_len], TAG_LEN); 
    int iv_len = SESS_CIPHER_IV_LEN;
    unsigned char* iv = NULL;
    iv = malloc_and_check(iv, iv_len);
    if(!iv){
        perror("Error in malloc\n");
        free(aad);
        free(ct);
        free(tag);
        return NULL;
    }
    memcpy(iv, &msg[PAYLOAD_LENGTH + sizeof(int) + aad_len + sizeof(int) + ct_len + TAG_LEN], iv_len); 
    unsigned char* pt = NULL;
    pt = malloc_and_check(pt, ct_len + 1);
    if(!pt){
        perror("Error in malloc\n");
        free(aad);
        free(ct);
        free(tag);
        free(iv);
        return NULL;
    }
    memset(pt, '\0', ct_len + 1);
    
    ret = sym_auth_decr(EVP_aes_256_gcm(), ct, ct_len, session_key, iv, aad, aad_len, pt, TAG_LEN, tag);
    if(ret == -1){
        perror("Error in sym_auth_decr");
        free(aad);
        free(ct);
        free(tag);
        free(iv);
        free(pt);
        return NULL;
    }
        free(aad);
        free(ct);
        free(tag);
        free(iv);
        return pt;

}

int message_exchange_send_exit(unsigned char *message, client_info *user) {
    int ret;

    int pt_len;
    pt_len = strlen((const char*)message) + 1;
        
    unsigned char* pt = NULL;
    pt = malloc_and_check(pt, pt_len);
    if(!pt){
        perror("Error in malloc\n");
        return 0;
    }
    pt[0] = ALERT_CLIENT_EXITED;
    memcpy(&pt[1], message, pt_len - 1);
    int iv_len = SESS_CIPHER_IV_LEN;
    unsigned char* iv = generate_random_bytes(iv_len);
    if(!iv){
      free(pt);
      return 0;
    }
    int ct_len = pt_len + SESS_CIPHER_BLOCK_DIM;
    unsigned char* ct = NULL;
    ct = malloc_and_check(ct, ct_len);
    if(!ct){
        free(pt);
        perror("Error in malloc\n");
        return 0;
    }
    int tag_len = TAG_LEN;
    unsigned char* tag = NULL;
    tag = malloc_and_check(tag, tag_len);
    if(!tag){
        free(pt);
        free(ct);
        perror("Error in malloc\n");
        return 0;
    }
    int aad_len = sizeof(int);
    unsigned char* aad = NULL;
    aad = malloc_and_check(aad, aad_len);
    if(!aad){
        free(pt);
        free(ct);
        free(tag);
        perror("Error in malloc\n");
        return 0;
    }
    unsigned char* cont_byte = NULL;
    cont_byte = malloc_and_check(cont_byte, sizeof(int));
    if(!cont_byte){
        free(pt);
        free(ct);
        free(tag);
        free(aad);
        perror("Error in malloc\n");
        return 0;
    }

    int_to_byte(user->counter_server_client, cont_byte);
    user->counter_server_client += 1;
    memcpy(&aad[0], cont_byte, sizeof(int));

    ct_len = sym_auth_encr(EVP_aes_256_gcm(), pt, pt_len, user->session_key, iv, aad, aad_len, ct, tag_len, tag);
    if(ct_len == 0){
      perror("Error in send_usrs_online because of sym_auth_encr\n");
      return 0;
    }

    int msg_len = sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len + iv_len;
    int payload_len = msg_len;
    unsigned char* payload_len_byte = NULL;
    payload_len_byte = malloc_and_check(payload_len_byte, sizeof(int));
    if(!payload_len_byte){
        free(pt);
        free(ct);
        free(tag);
        free(aad);
        free(cont_byte);
        perror("Error in malloc\n");
        return 0;
    }
    int_to_byte(payload_len, payload_len_byte);
    unsigned char* ct_len_byte = NULL;
    ct_len_byte = malloc_and_check(ct_len_byte, sizeof(int));
    if(!ct_len_byte){
        free(pt);
        free(ct);
        free(tag);
        free(aad);
        free(cont_byte);
        free(payload_len_byte);
        perror("Error in malloc\n");
        return 0;
    }
    int_to_byte(ct_len, ct_len_byte);
    unsigned char* aad_len_byte = NULL;
    aad_len_byte = malloc_and_check(aad_len_byte, sizeof(int));
    if(!aad_len_byte){
        free(pt);
        free(ct);
        free(tag);
        free(aad);
        free(cont_byte);
        free(payload_len_byte);
        free(ct_len_byte);
        perror("Error in malloc\n");
        return 0;
    }
    int_to_byte(aad_len, aad_len_byte);
    unsigned char* msg = NULL;
    msg = malloc_and_check(msg, msg_len);
    if(!msg){
        free(pt);
        free(ct);
        free(tag);
        free(aad);
        free(cont_byte);
        free(payload_len_byte);
        free(ct_len_byte);
        free(aad_len_byte);
        perror("Error in malloc\n");
        return 0;
    }

    memcpy((unsigned char*) &msg[0], aad_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[sizeof(int)], aad, aad_len);
    memcpy((unsigned char*) &msg[sizeof(int) + aad_len], ct_len_byte, sizeof(int));
    memcpy((unsigned char*) &msg[sizeof(int) + aad_len + sizeof(int)], (unsigned char*) ct, ct_len);
    memcpy((unsigned char*) &msg[sizeof(int) + aad_len + sizeof(int) + ct_len], (unsigned char*) tag, tag_len);
    memcpy((unsigned char*) &msg[sizeof(int) + aad_len + sizeof(int) + ct_len + tag_len], (unsigned char*) iv, iv_len);

    ret = sendn(user->local_sock, payload_len_byte, PAYLOAD_LENGTH);
    if(ret == -1){
        perror("Error in send\n");
        return 0;
    }
    ret = sendn(user->local_sock, msg, msg_len);
    if(ret == -1){
        perror("Error in send\n");
        return 0; 
    }
    free(pt);
    free(iv);
    free(ct);
    free(tag);
    free(cont_byte);
    free(payload_len_byte);
    free(ct_len_byte);
    free(msg);
    free(aad_len_byte);
    free(aad);
    return 1;

}