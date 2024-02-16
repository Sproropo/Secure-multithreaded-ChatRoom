#include "server_handle_client.h"

extern client_info *first_client; 
extern long int how_many_user_av; 
short volatile int flag = 1;

//unsigned char *key = (unsigned char *)"0123456789012345";
client_info *user; 
unsigned char message_to_send[SET_BUFFER];
unsigned char buff_handle[SET_BUFFER];
unsigned char *plaintext;
unsigned char *temp;
unsigned char payload_dim[sizeof(int)];
char other_message[40] = "Do you want to accept the request of: ";
unsigned char *token_name;

pthread_mutex_t mut_ip_name_recv = PTHREAD_MUTEX_INITIALIZER; 

pthread_mutex_t mut_msg_recv = PTHREAD_MUTEX_INITIALIZER; 

void exit_procedure(client_info *client_recvr);

void *handle_client(void *arg){
    pthread_mutex_lock(&mut_ip_name_recv); 
    client_info *local_user; 
    client_info *is_there_a_client_receiver;
    local_user = (client_info *) arg; 
    size_t leng;
    int ret;
    int nonce = 0;
    int error_val = 0;
    char *name = read_nonce(local_user->local_sock, &nonce);
    if(!name){
	    close(local_user->local_sock); 
        free(local_user); 
        pthread_mutex_unlock(&mut_ip_name_recv);
        return NULL;
    }
    if(strcmp((const char*)name, "e") == 0){
        memset(&name, 0, sizeof(name)); 
	    close(local_user->local_sock); 
        free(local_user); 
        pthread_mutex_unlock(&mut_ip_name_recv);
        return NULL; 
    }
    EVP_PKEY* ephemeral_public_key = NULL;
    EVP_PKEY* ephemeral_private_key = NULL;
    generate_ephemeral_keys(&ephemeral_private_key, &ephemeral_public_key);
    if(ephemeral_private_key == NULL || ephemeral_public_key == NULL){
        perror("Error while reading generate_ephemeral_keys\n");
        set_online_flag((unsigned char*)name); 
	    close(local_user->local_sock); // chiudo la socket
        free(local_user); // libero lo heap
        memset(&name, 0, sizeof(name)); 
        pthread_mutex_unlock(&mut_ip_name_recv);
        return NULL; 
    }
    error_val = send_ephemeral_public_key(local_user->local_sock, ephemeral_public_key, nonce);
    if(error_val == 0){
        perror("Error while reading send_ephemeral_public_key.\n");
        set_online_flag((unsigned char*)name); 
	    close(local_user->local_sock); // chiudo la socket
        free(local_user); // libero lo heap
        memset(&name, 0, sizeof(name)); 
        pthread_mutex_unlock(&mut_ip_name_recv);
        return NULL; 
    }
    int session_key_len = -1;
    unsigned char* session_key = read_session_key(local_user->local_sock, ephemeral_private_key, ephemeral_public_key, (unsigned char*)name, &session_key_len);
    EVP_PKEY_free(ephemeral_private_key);
    EVP_PKEY_free(ephemeral_public_key);
    if(session_key == NULL){
        perror("Error in read_session_key.\n");
        set_online_flag((unsigned char*)name); 
	    close(local_user->local_sock); // chiudo la socket
        free(local_user); // libero lo heap
        memset(&name, 0, sizeof(name)); 
        pthread_mutex_unlock(&mut_ip_name_recv);
        return NULL;
    }
    leng = strlen((const char*)name);
    memcpy(&(local_user->name), name, leng);

    local_user->session_key = malloc(EVP_CIPHER_key_length(SESS_CIPHER));
    memcpy((local_user->session_key), session_key, EVP_CIPHER_key_length(SESS_CIPHER));
    update_client(*local_user);
    how_many_user_av++; 
    free(session_key);
    memset(&name, 0, sizeof(name)); 
    memset(&buff_handle, 0, sizeof(buff_handle)); 
    fprintf(stdout,"%s:%s connected\n",inet_ntoa(local_user->address.sin_addr), local_user->name); // Stampo nel terminale del server che la connessione e' avvenuta
    flag = 1;
    unsigned char *available_users = print_clients(local_user->name);
    ret = message_exchange_send(available_users, local_user, 0, NULL, 0, -1, 0);
    return_client(local_user->name)->counter_server_client++;
    free(available_users); 
    pthread_mutex_unlock(&mut_ip_name_recv); // Sblocco 
	while(flag){
        ret = recv(local_user->local_sock, payload_dim, sizeof(int), 0);
        pthread_mutex_lock(&mut_msg_recv);
        if(ret <= 0){
            user = return_client(local_user->name);
            exit_procedure(user->client_rcvr);
            break;
        }
        memcpy(&(return_client(local_user->name))->p_dim, payload_dim, sizeof(int));
        memcpy(&local_user->p_dim, payload_dim, sizeof(int));
        memset(&payload_dim, 0, sizeof(int));
        pthread_mutex_unlock(&mut_msg_recv);
        ret = recv(local_user->local_sock, buff_handle, local_user->p_dim, 0);
        pthread_mutex_lock(&mut_msg_recv);
        if(ret <= 0){
            user = return_client(local_user->name);
            exit_procedure(user->client_rcvr);
            break;
        }
        user = return_client(local_user->name);
		plaintext = (unsigned char*)message_exchange_read(buff_handle, user, NULL, 0, 0, NULL);
        flag = 1;
        is_there_a_client_receiver = search_rcvr(user->name);
        switch (user->user_state)
        {
            case 0:
                if (plaintext[0] == '@') { 
                    token_name = (unsigned char*)strtok((char*)plaintext + 1, ":"); 
                    
                    if(!strcmp((char *)user->name, (char *)token_name)) { 
                        memcpy(message_to_send,"You can't text yourself", strlen("You can't text yourself"));
                        ret = message_exchange_send(&message_to_send[0], user, 0, NULL, 0, -1, 0);
                        free(plaintext);
                        } else if(!search_client(token_name)) {
                            memcpy(&message_to_send[0],"The client doesn't exists", strlen("The client doesn't exists"));
                            ret = message_exchange_send(message_to_send, user, 0, NULL, 0, -1, 0);
                            free(plaintext);
                            } else if(client_is_busy_or_offline(token_name)) {
                                    memcpy(message_to_send, "The client is busy or offline", strlen("The client is busy or offline"));
                                    ret = message_exchange_send(&message_to_send[0], user, 0, NULL, 0, -1, 0);
                                    free(plaintext);
                                } 
                                else { 
                                    add_client_rcvr(*user, token_name);
                                    change_state_user(user->name, 4);
                                    change_state_user(token_name, 1);
                                    memcpy(&message_to_send[0], other_message, strlen(other_message));
                                    memcpy(&message_to_send[strlen(other_message)], user->name,strlen((const char*)user->name));
                                    ret = message_exchange_send(&message_to_send[0], user->client_rcvr, 0, NULL, 0, -1, 0);
                                    memset(&message_to_send, 0, sizeof(message_to_send));
                                    memcpy(&message_to_send[0],"you can resume the request by typing 'resume'...", strlen("you can resume the request by typing 'resume'..."));
                                    ret = message_exchange_send(&message_to_send[0], user, 0, NULL, 0, -1, 0);
                                    free(plaintext);
                            }
                    } else if (plaintext[0] == 'a') {
                            unsigned char *available_users = print_clients(user->name);
                            ret = message_exchange_send(available_users, user, 0, NULL, 0, -1, 0);
                            
                            free(available_users); 
                            free(plaintext);
                        } else {
                            free(plaintext);
                            exit_procedure(is_there_a_client_receiver);
                            } 
            break;

            case 1:
                if(!(strcmp((char *)plaintext,"exit"))) {
                    free(plaintext);
                    exit_procedure(is_there_a_client_receiver);
                } else if(!(strcmp((char *)plaintext,"no"))) {
                    if(is_there_a_client_receiver){
                    memcpy(&message_to_send[0], "Sorry, the client didn't accept your request", strlen("Sorry, the client didn't accept your request"));
                    ret = message_exchange_send(&message_to_send[0], is_there_a_client_receiver, 0, NULL, 0, -1, 0);
                    
                    change_state_user(is_there_a_client_receiver->name, 0);
                    change_state_user(user->name, 0);
                    rmv_clients_rcvr(*is_there_a_client_receiver);
                    free(plaintext);
                    } else {
                    memcpy(&message_to_send[0], "Sorry, the client wait too much and got bored", strlen("Sorry, the client wait too much and got bored"));
                    ret = message_exchange_send(&message_to_send[0], user, 0, NULL, 0, -1, 0);
                    free(plaintext);

                    }
                        
                    } else if(!(strcmp((char *)plaintext,"yes"))){
                        memcpy(&message_to_send,"The client has accepted the request", strlen("The client has accepted the request"));
                        add_client_rcvr(*user, is_there_a_client_receiver->name);
                        change_state_user(user->client_rcvr->name, 2);
                        change_state_user(user->name, 2);
                        ret = message_exchange_send(&message_to_send[0], user->client_rcvr, 0, NULL, 0, -1, 0);
                        if(!ret){
                            perror("Error in message_exchange_send\n");
                            exit_procedure(is_there_a_client_receiver);
                        }
                        
                        char *client_pubkey_path_1 = malloc(strlen("src_server/server_keys/") + strlen((const char*)user->name) + strlen("_pubkey.pem")+1); 
                        sprintf(client_pubkey_path_1,"%s%s%s","src_server/server_keys/",(char*)user->name,"_pubkey.pem");
                        message_exchange_send_pub_key(client_pubkey_path_1, user->client_rcvr);
                        if(!ret){
                            perror("Error in exchange_send_pub_key\n");
                            exit_procedure(is_there_a_client_receiver);
                        }
                        free(client_pubkey_path_1);
                        
                        memset(&message_to_send, 0, sizeof(message_to_send));
                        memcpy(message_to_send,"You are now chatting with the client", strlen("You are now chatting with the client"));
                        ret = message_exchange_send(&message_to_send[0], user, 0, NULL, 0, -1, 0);
                        if(!ret){
                            perror("Error in exchange_send\n");
                            exit_procedure(is_there_a_client_receiver);
                        }
                        char *client_pubkey_path_2 = malloc(strlen("src_server/server_keys/") + strlen((const char*)user->client_rcvr->name) + strlen("_pubkey.pem")+1); 
                        sprintf(client_pubkey_path_2, "%s%s%s","src_server/server_keys/", (char*)user->client_rcvr->name,"_pubkey.pem");
                        message_exchange_send_pub_key(client_pubkey_path_2, user);
                        free(client_pubkey_path_2);
                        if(!ret){
                            perror("Error in exchange_send_pub_key\n");
                            exit_procedure(is_there_a_client_receiver);
                        }
                        free(plaintext);
                    }   else {
                        free(plaintext);
                        exit_procedure(user->client_rcvr);
                }

            break;

            case 2:
                if(!(strncmp((char *)plaintext,"exit", 4))) {
                    memcpy(&message_to_send[0], "Sorry, the client exit the chat", strlen("Sorry, the client exit the chat"));
                    ret = message_exchange_send(&message_to_send[0], is_there_a_client_receiver, 0, NULL, 0, -1, 1);
                    memset(&message_to_send, 0 , sizeof(message_to_send));
                    memcpy(&message_to_send[0], "You exit the chat", strlen("You exit the chat"));
                    ret = message_exchange_send(&message_to_send[0], user, 0, NULL, 0, -1, 1);
                    change_state_user(is_there_a_client_receiver->name, 0);
                    change_state_user(user->name, 0);
                    rmv_clients_rcvr(*is_there_a_client_receiver);
                    rmv_clients_rcvr(*user);
                    free(plaintext);
                    } else {
                        int dim = 0;
                        memcpy(&dim, &plaintext[0],sizeof(int));
                        dim+=sizeof(int);
                        ret = message_exchange_send(plaintext, user->client_rcvr, 0, NULL, 0, dim, 0);
                        if(!ret) {
                            perror("Error in redirect_message\n");
                            exit_procedure(user->client_rcvr);
                            break;
                        }
                        free(temp);
                        free(plaintext); 
                    }
            break;

            default:
                    if(user->client_rcvr) {
                        if(!(strcmp((char *)plaintext,"resume"))) {
                        memcpy(&message_to_send[0], "The client don't want to talk to you anymore", strlen("The client don't want to talk to you anymore"));
                        ret = message_exchange_send(&message_to_send[0], user->client_rcvr, 0, NULL, 0, -1, 0);
                        change_state_user(user->client_rcvr->name, 0);
                        change_state_user(user->name, 0);
                        rmv_clients_rcvr(*user->client_rcvr);
                        free(plaintext);
                    } else {
                        memcpy(&message_to_send[0], "The client reject you already. Know you place", strlen("The client reject you already. Know you place"));
                        ret = message_exchange_send(&message_to_send[0], user, 0, NULL, 0, -1, 0);
                        free(plaintext);
                    }
                }
            memset(&buff_handle, 0, sizeof(buff_handle));
            memset(&message_to_send, 0, sizeof(message_to_send));
            break;
        }
    memset(&buff_handle, 0, sizeof(buff_handle));
    memset(&message_to_send, 0, sizeof(message_to_send));
    pthread_mutex_unlock(&mut_msg_recv); // Sblocco
} 
	close(user->local_sock); // chiudo la socket
    free(local_user);
    return NULL; 
}

void exit_procedure(client_info *client_recvr){
    memcpy(&buff_handle,user->name, strlen((const char*)user->name));
    memcpy(&buff_handle[strlen((const char*)user->name)], " has left\n", strlen(" has left\n"));
    set_online_flag(user->name);
    change_state_user(user->name, 0);
    user->counter_client_server = 0;
    user->counter_server_client = 0;
    user->p_dim = 0;

    #pragma optimize("", off)
        memset(user->session_key, 0, EVP_CIPHER_key_length(SESS_CIPHER));
    #pragma optimize("", on)
    fprintf(stdout, "%s", buff_handle);
    if(client_recvr) {
        memset(&message_to_send, 0, sizeof(message_to_send));
        memcpy(&message_to_send, "The client has left", strlen("The client has left"));
        flag = message_exchange_send(&message_to_send[0], client_recvr, 0, NULL, 0, -1, 1);
        change_state_user(client_recvr->name,0);
        rmv_clients_rcvr(*client_recvr);
        rmv_clients_rcvr(*user);
    }
    memset(&buff_handle, 0, sizeof(buff_handle));
    memset(&message_to_send, 0, sizeof(message_to_send));
    pthread_mutex_unlock(&mut_msg_recv);
}