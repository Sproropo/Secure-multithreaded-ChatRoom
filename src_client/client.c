#include "../utility_fun.h"
#include "../src_server/server_client_lists.c"
#include "../src_crypto/pfs.c"
// Global variables
volatile unsigned short int flag_exit = 0; 
volatile unsigned short int state_chat_is_active = 0;
int connect_socket = 0;
unsigned char name[14];
int ret = 0;
unsigned char* session_key_server = NULL;
unsigned char* session_key = NULL;

char server_reply[2];
unsigned char payload[SET_BUFFER+32];
unsigned char *message_recv;
unsigned char *temp;
unsigned char *payload_dim;
int p_dim = 0;
char *passcode;

int cont_client_server = 0;
int cont_server_client = 0;
int cont_client_to_client = 0;
int cont_client_from_client = 0;

void send_msg_handler(); 
void recv_msg_handler(); 
void catch_signal(); 
int main(int argc, char **argv){
	if(argc != 4){
		fprintf(stderr, "Usage: %s <ip address> <username> <port>\n", argv[0]);
		return EXIT_FAILURE;
	}
	char *ip = argv[1]; 
	size_t len = strlen((const char*)argv[2]);
	memcpy(name, argv[2], len);
	int port = atoi(argv[3]);
	
	signal(SIGINT, catch_signal);
	signal(SIGQUIT, catch_signal);

	if (strlen((const char*)name) > 14 || strlen((const char*)name) < 2){ 
		printf("Name must be less than 14 and more than 2 characters.\n");
		return EXIT_FAILURE; 
	}

	struct sockaddr_in server_addr;
	connect_socket = socket(AF_INET, SOCK_STREAM, 0);
	memset(&server_addr, 0, sizeof(server_addr)); 
	server_addr.sin_family = AF_INET; 
	server_addr.sin_addr.s_addr = inet_addr(ip);
	server_addr.sin_port = htons(port); 

    if(connect(connect_socket, (struct sockaddr *)&server_addr, sizeof(server_addr))){ 
        perror("ERROR: connect\n");
		exit(1); 
		} 
	int nonce = send_random_nonce(connect_socket, name);
    if (nonce == 0) {
		perror("Error in send_random_nonce\n");
		close(connect_socket);
		exit(1);
	}
	unsigned char *header = NULL;
	header = malloc_and_check(header, HEADER_LEN);
	if(!header){
		perror("Error in malloc\n");
		close(connect_socket);
		exit(1);
	}
    ret = readn(connect_socket, header, HEADER_LEN);
    if(ret <= 0){
		printf("You're not registered or you're already online\n");
		exit(1);
    }
    // Read ephemeral public key from server (perfect forward secrecy)
    EVP_PKEY* eph_pubkey = read_ephemeral_public_key(connect_socket, nonce, header);
    if(eph_pubkey == NULL){
      perror("Error in read_ephemeral_public_key\n");
      close(connect_socket);
      exit(1);
    }
        // Generate a random session key and send it to server
    int key_len = SESS_CIPHER_KEY_LEN;
    session_key_server = generate_random_bytes(key_len);
    if(session_key_server == NULL){
      perror("Error in generate_random_bytes");
      close(connect_socket);
      exit(1);
    }
	char *path_passcode = NULL;
	path_passcode = malloc_and_check_s(path_passcode, strlen("src_client/clients_key/") + strlen((char*)name) + strlen("_passcode.txt"));
	sprintf(path_passcode, "%s%s%s", "src_client/clients_key/", (char*)name, "_passcode.txt");
	passcode = retrieve_passcode(passcode, path_passcode);
    ret = send_session_key(connect_socket, session_key_server, eph_pubkey, name, passcode);
    EVP_PKEY_free(eph_pubkey);
    if(!ret){
      perror("Error in send_session_key\n");
      close(connect_socket);
      exit(1);
    }
	printf("Connected\n");

	pthread_t send_msg_thread; 
  	if(pthread_create(&send_msg_thread, NULL, (void *) send_msg_handler, NULL) != 0){
		perror("ERROR: pthread\n");
		close(connect_socket);
    	return EXIT_FAILURE;
	} 

	pthread_t recv_msg_thread; 
  	if(pthread_create(&recv_msg_thread, NULL, (void *) recv_msg_handler, NULL) != 0){
		perror("ERROR: pthread\n");
		close(connect_socket);
		return EXIT_FAILURE;
	} 

	while (1){ 
		if(flag_exit){ 
			printf("Thanks for using this ChatRoom\n"); 
			#pragma optimize("", off)
				memset(session_key_server, 0, SESS_CIPHER_KEY_LEN);
			#pragma optimize("", off)
			free(session_key_server);
			break; 
    } }
	close(connect_socket); 

	return EXIT_SUCCESS; 
	}

void send_msg_handler() {
    unsigned char message[SET_BUFFER];
    unsigned char buff_send[SET_BUFFER + 32];
    unsigned int count = 0;

  while(1) {
    fgets((char*)message, SET_BUFFER, stdin); 
	if(state_chat_is_active == 0) { 
		while(count < strlen((const char*)message) && message[count] != ':') count++; 
		if('\n' == message[strlen((const char*)message) - 1]) message[strlen((const char*)message) - 1] = '\0'; 
    	if (strcmp((const char*)message, "exit") == 0) { 
				flag_exit = 1;
    }	else if (strcmp((const char*)message, "a") == 0) {
					ret = message_exchange_send(message, NULL, connect_socket, session_key_server, cont_client_server, -1, 0);
					if(!ret){
						flag_exit = 1;
						break;
					}
					cont_client_server++;
					count = 0;
						}
			else if(message[0] != '@') {
						memset(message, 0, sizeof(message)); 
						count = 0;
						continue; 
			}   else if(!strchr((const char*)message, ':' )){ 
						memset(message, 0, sizeof(message)); 
						printf("Maybe you forgot ':'\n");  
						count = 0; 
						continue;              
				}   else if(count > 14){ 
							memset(message, 0, sizeof(message)); 
							printf("The name of the client receiver exceeds the maximum number of characters the names can have \n");  
							count = 0; 
							continue;              
					}    else { 
									memcpy(buff_send, message, strlen((const char*)message));
									ret = message_exchange_send(buff_send, NULL, connect_socket, session_key_server, cont_client_server, -1, 0);
									cont_client_server++;
									state_chat_is_active = 4;
									memset(message, 0, sizeof(message)); // Azzero il messaggio
									count = 0;
								}
        memset(message, 0, sizeof(message));
    	memset(buff_send, 0, sizeof(buff_send));
			} else if(state_chat_is_active == 2) {
				if('\n' == message[strlen((const char *)message) - 1]) message[strlen((const char*)message) - 1] = '\0';
					if (strcmp((const char*)message, "exit") == 0) { 
						memset(message, 0, sizeof(message));
						memcpy(message, "no", strlen("no"));
						ret = message_exchange_send(message, NULL, connect_socket, session_key_server, cont_client_server, -1, 0);
						flag_exit = 1; 
					}	else if(!strcmp((const char*)message,"yes")) { 
							memcpy(buff_send, message, strlen((const char*)message));
							ret = message_exchange_send(buff_send, NULL, connect_socket, session_key_server, cont_client_server, -1, 0);
							cont_client_server++;
							} else if(!strcmp((const char*)message, "no") ) { 
								state_chat_is_active = 0;
								memcpy(buff_send, message, strlen((const char*)message)); 
								ret = message_exchange_send(buff_send, NULL, connect_socket, session_key_server, cont_client_server, -1, 0);
								cont_client_server++;
								}
								else { 
									fprintf(stdout,"You can reply only yes or no to the request\n");
											}
				memset(message, 0, sizeof(message));
				memset(buff_send, 0, sizeof(buff_send));

			} else if(state_chat_is_active == 3) { 
					if (strcmp((const char*)message, "exit\n") == 0) { 
						memcpy(buff_send, message, strlen((const char*)message));
						if('\n' == buff_send[strlen((const char *)buff_send) - 1]) {
							buff_send[strlen((const char*)buff_send) - 1] = '\0'; 
						}
							ret = message_exchange_send(buff_send, NULL, connect_socket, session_key_server, cont_client_server, -1, 2);
							cont_client_server++;
							cont_client_from_client = 0;
							cont_client_to_client = 0;
							state_chat_is_active = 0;
					}   else {  
							memcpy(buff_send, "> ", strlen("> "));
							memcpy(&buff_send[strlen("> ")], name, strlen((const char*)name));
							memcpy(&buff_send[strlen("> ") + strlen((const char*)name)], ":", strlen(":"));
							memcpy(&buff_send[strlen("> ") + strlen((const char*)name) + strlen(":")], message, strlen((const char*)message));

							if('\n' == buff_send[strlen((const char *)buff_send) - 1]) {
								buff_send[strlen((const char*)buff_send) - 1] = '\0'; 
							}
							int len = 0;
							temp = prepare_message(buff_send, session_key, cont_client_to_client, &len); 
							ret = message_exchange_send(temp, NULL, connect_socket, session_key_server, cont_client_server, len, 0);
							if(!temp) free(temp);
							cont_client_server++;
							cont_client_to_client++;
											}

				memset(message, 0, sizeof(message));
				memset(buff_send, 0, sizeof(buff_send));
				} else {
					if(!strcmp((const char*)message,"resume\n")) { 
							memcpy(buff_send, message, strlen((const char*)message));
							if('\n' == buff_send[strlen((const char *)buff_send) - 1]) buff_send[strlen((const char*)buff_send) - 1] = '\0'; 
							ret = message_exchange_send(buff_send, NULL, connect_socket, session_key_server, cont_client_server, -1, 0);
							cont_client_server++;
							state_chat_is_active = 0;
							memset(buff_send, 0, sizeof(buff_send));
							memset(message, 0, sizeof(message));
							fprintf(stdout, "The request is resumed\n");
				} 
					if(!strcmp((const char*)message,"exit\n")) { 
						flag_exit = 1;
						break;
				} 
					memset(buff_send, 0, sizeof(buff_send));
					memset(message, 0, sizeof(message));
			}

	}
	}

void recv_msg_handler() {
	
  while (1) {
		payload_dim = malloc_and_check(payload_dim, sizeof(int));
        ret = recv(connect_socket, payload_dim, sizeof(int), 0);
		if(ret <= 0) {
			flag_exit = 1;
			break;
		}
        memcpy(&p_dim, payload_dim ,sizeof(int));
		free(payload_dim);
        ret = recv(connect_socket, payload, p_dim, 0);
		if(ret <= 0) {
			perror("Error in recv\n");
			flag_exit = 1;
			break;
		}
			
		int len_msg_rcv = 0;
		if(state_chat_is_active == 3){
			temp = (unsigned char*)message_exchange_read(payload, NULL, session_key_server, cont_server_client, 1, &len_msg_rcv);
			cont_server_client++;
			if(!temp) {
				flag_exit = 1;
				break;
			}
			if(temp[0] == MSG){
				message_recv = retrieve_message(temp + 1, session_key, cont_client_from_client);
				if(!message_recv) {
					flag_exit = 1;
				    break;
			    }
				cont_client_from_client = cont_client_from_client + 1;	
				if(!temp) free(temp);
			} else {
					message_recv = malloc_and_check(message_recv, len_msg_rcv + 10);
					memcpy(&message_recv[0], temp + 1, len_msg_rcv);
					if(!temp) free(temp);
					cont_client_from_client = 0;
					cont_client_to_client = 0;
			}
		} else {
				message_recv = (unsigned char*)message_exchange_read(payload, NULL, session_key_server, cont_server_client, 0, NULL);
				cont_server_client++;
		}
    if (message_recv) { 
		fprintf(stdout, "%s\n",message_recv);
		if(!strncmp((const char*)message_recv,"Do you want to accept the request of: ",36)) { 
			state_chat_is_active = 2; }
			else if(!strcmp((const char*)message_recv,"The client has accepted the request") || !strcmp((const char*)message_recv,"You are now chatting with the client")) { 
				EVP_PKEY *peer_pub_key = message_exchange_pub_read(connect_socket, session_key_server);
				cont_server_client++;
				if(!strcmp((const char*)message_recv,"You are now chatting with the client")) {
					int nonce = 0;
					int len = 0;

					temp = send_random_nonce_client(&nonce, &len);
					ret = message_exchange_send(temp, NULL, connect_socket, session_key_server, cont_client_server, len, 0);
					if(!temp) free(temp);
					cont_client_server++;
					if (!nonce) {
						perror("Error in send_random_nonce\n");
						flag_exit = 1;
						break;
					}
					payload_dim = malloc_and_check(payload_dim, sizeof(int));
					ret = recv(connect_socket, payload_dim, sizeof(int), 0);
					if(ret <= 0) {
						flag_exit = 1;
						break;
					}
					memcpy(&p_dim, payload_dim ,sizeof(int));
					free(payload_dim);
					memset(&payload, 0, sizeof(payload));
					ret = recv(connect_socket, payload, p_dim, 0);
					if(ret <= 0) {
						perror("Error in recv\n");
						flag_exit = 1;
						break;
					}
					message_recv = (unsigned char*)message_exchange_read(payload, NULL, session_key_server, cont_server_client, 0, NULL);
					cont_server_client++;
					EVP_PKEY* eph_pubkey = read_ephemeral_public_key_client(message_recv, nonce, peer_pub_key);
					if(eph_pubkey == NULL){
					perror("Error in read_ephemeral_public_key_client\n");
					flag_exit = 1;
					break;
					}
						// Generate a random session key and send it to server
					int key_len = EVP_CIPHER_key_length(SESS_CIPHER);
					session_key = generate_random_bytes(key_len);
					if(session_key == NULL){
					perror("Error in generate_random_bytes");
					flag_exit = 1;
					break;
					}
					temp = send_session_key_client(session_key, eph_pubkey, name, passcode, &len);
					// ret = send_auth_routing(temp, len, connect_socket, session_key_server, cont_client_server);
					ret = message_exchange_send(temp, NULL, connect_socket, session_key_server, cont_client_server, len, 0);
					if(!temp) free(temp);
					cont_client_server++;
					EVP_PKEY_free(eph_pubkey);
					if(!ret){
					perror("Error in send_session_key\n");
					flag_exit = 1;
					break;
					}
				} else {
					int nonce = 0;
					payload_dim = malloc_and_check(payload_dim, sizeof(int));
					ret = recv(connect_socket, payload_dim, sizeof(int), 0);
					if(ret <= 0) {
						flag_exit = 1;
						break;
					}
					memcpy(&p_dim, payload_dim ,sizeof(int));
					free(payload_dim);
					memset(&payload, 0, sizeof(payload));
					ret = recv(connect_socket, payload, p_dim, 0);
					if(ret <= 0) {
						perror("Error in recv\n");
						flag_exit = 1;
						break;
					}
					message_recv = (unsigned char*)message_exchange_read(payload, NULL, session_key_server, cont_server_client, 0, NULL);
					cont_server_client++;
					ret = read_random_nonce_client(message_recv, &nonce);
					if(!ret){
						perror("Error in send_session_key\n");
						flag_exit = 1;
						break;
					}
					EVP_PKEY* ephemeral_public_key = NULL;
					EVP_PKEY* ephemeral_private_key = NULL;
					generate_ephemeral_keys(&ephemeral_private_key, &ephemeral_public_key);
					if(ephemeral_private_key == NULL || ephemeral_public_key == NULL){
						perror("Error while reading generate_ephemeral_keys\n");
						flag_exit = 1;
						break;
					}
					int len = 0;
					temp = send_ephemeral_public_key_client(ephemeral_public_key, nonce,(char*)name, passcode, &len);
					// ret = send_auth_routing(temp, len, connect_socket, session_key_server, cont_client_server);
					ret = message_exchange_send(temp, NULL, connect_socket, session_key_server, cont_client_server, len, 0);
					cont_client_server++;
					if(!ret){
						perror("Error while reading send_ephemeral_public_key.\n");
						flag_exit = 1;
						break;
					}
					if(!temp) free(temp);
					int session_key_len = -1;
					payload_dim = malloc_and_check(payload_dim, sizeof(int));
					ret = recv(connect_socket, payload_dim, sizeof(int), 0);
					if(ret <= 0) {
						flag_exit = 1;
						break;
					}
					memcpy(&p_dim, payload_dim ,sizeof(int));
					free(payload_dim);
					memset(&payload, 0, sizeof(payload));
					ret = recv(connect_socket, payload, p_dim, 0);
					if(ret <= 0) {
						perror("Error in recv\n");
						flag_exit = 1;
						break;
					}
					message_recv = (unsigned char*)message_exchange_read(payload, NULL, session_key_server, cont_server_client, 0, NULL);
					cont_server_client++;
					session_key = read_session_key_client(message_recv, ephemeral_private_key, ephemeral_public_key, peer_pub_key, &session_key_len);
					EVP_PKEY_free(ephemeral_private_key);
					EVP_PKEY_free(ephemeral_public_key);
					if(!session_key){
						perror("Error because of read_session_key.\n");
						flag_exit = 1;
						break;
					}
				}
				state_chat_is_active = 3; }  
				else if(!strcmp((const char*)message_recv,"Sorry, the client didn't accept your request") || !strcmp((const char*)message_recv,"The request has timed out") || !strcmp((const char*)message_recv,"You can't text yourself") || !strcmp((const char*)message_recv,"The client doesn't exists") || !strcmp((const char*)message_recv,"The client is busy or offline") || !strcmp((const char*)message_recv,"The client has left") || !strcmp((const char*)message_recv, "The client don't want to talk to you anymore") || !strcmp((const char*)message_recv, "Sorry, the client wait too much and got bored")) {
						//printf("sess %s<\n",session_key);
					cont_client_from_client = 0;
					cont_client_to_client = 0;
					state_chat_is_active = 0;}
					else if(!strncmp((const char*)message_recv,"Sorry, the client exit the chat",strlen("Sorry, the client exit the chat")) || !strcmp((const char*)message_recv,"You exit the chat") ){
						if(session_key != NULL) {
							#pragma optimize("", off)
								memset(session_key, 0, SESS_CIPHER_KEY_LEN);
							#pragma optimize("", off)
							free(session_key); }
						cont_client_from_client = 0;
						cont_client_to_client = 0;
						state_chat_is_active = 0;
					} else {
						
					}
					memset(payload, 0, p_dim);
					if(!message_recv) free(message_recv);
    } else  { 
			flag_exit = 1;
			//memset(payload, 0, p_dim);
			break;
    } 

  } }

void catch_signal() {
    flag_exit = 1;
}
