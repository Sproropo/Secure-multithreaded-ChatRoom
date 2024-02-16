#include "server_client_lists.h"

client_info *first_client = NULL; 
long int how_many_user_av = 0; 

void create_clients(unsigned char *name_user){
    client_info *temp, *last_client;
    temp = calloc(1, sizeof(client_info)); 
    size_t leng = strlen((const char*)name_user);
    memcpy(temp->name, name_user,leng);
    temp->online_flag = 0;
    temp->user_state = 0;
    temp->next = NULL;
    temp->client_rcvr = NULL;
    temp->counter_server_client = 0;
    temp->counter_client_server = 0;
    temp->p_dim = 0;
    last_client = first_client;
    if (!last_client) { 
        first_client = temp; 
        }
    else { while(last_client->next) { 
        last_client = last_client->next; 
        }
        last_client->next = temp; 
    }
}

int update_client(client_info user){
    client_info *tmp;
    tmp = first_client;
    while (strcmp((char *)tmp->name,(char *)user.name)) { 
        tmp = tmp->next;
        }  
    if(tmp->online_flag == 1){ 
        return 0;
    } else { 
        memset(&tmp->address, 0, sizeof(tmp->address));
        tmp->address = user.address; 
        tmp->local_sock = user.local_sock; 
        tmp->online_flag = 1;
        tmp->session_key = user.session_key;
        return 1;
    }
}
int is_client_online(unsigned char *namae) {
    client_info *tmp;
    tmp = first_client;
    while (tmp != NULL && strcmp((char *)tmp->name, (char *)namae)) {tmp = tmp->next;}
    if(tmp->online_flag == 1) {
        return 0;
        } else
            {return 1;
            }
}
int search_client(unsigned char *namae) { 
    client_info *tmp;
    tmp = first_client;
    while (tmp != NULL) {
        if(!strcmp((char *)tmp->name,(char *)namae)){
            return 1;
        }
        tmp = tmp->next;
    }
    return 0;
}

client_info *return_client(unsigned char *namae) {
    client_info *tmp;
    tmp = first_client;
    while (tmp != NULL && strcmp((char *)tmp->name, (char *)namae)) {tmp = tmp->next;}
    return tmp;
}

client_info *search_rcvr(unsigned char *namae) { 
    client_info *tmp;
    tmp = first_client;
    while (tmp != NULL) {
        if(!tmp->client_rcvr){
            tmp = tmp->next;
        } else {
            if(!strcmp((char *)tmp->client_rcvr->name,(char *)namae)){
                return tmp;
            }
            tmp = tmp->next;
        }
    }
    return tmp;
}

void add_client_rcvr(client_info user, unsigned char *name_client_receiver){ 
    client_info *tmp_local_user, *tmp_client_receiver;
    tmp_local_user = first_client;
    tmp_client_receiver = first_client;
    while(strcmp((char *)tmp_local_user->name,(char *)user.name)){
        tmp_local_user = tmp_local_user->next;
    }
    while(strcmp((char *)tmp_client_receiver->name,(char *)name_client_receiver)){
        tmp_client_receiver = tmp_client_receiver->next;
    }
    tmp_local_user->client_rcvr = tmp_client_receiver;

    }

void change_state_user(unsigned char *namae, int state) {
    client_info *tmp;
    tmp = first_client;
    while (strcmp((char *)tmp->name,(char *)namae)) {tmp = tmp->next;}
    tmp->user_state = state;
}

void rmv_clients_rcvr(client_info user){ 
    client_info *tmp;
    tmp = first_client;
    while(tmp != NULL && strcmp((char *)tmp->name,(char *)user.name)){
        tmp = tmp->next;
    }
    if(tmp != NULL) tmp->client_rcvr = NULL;
}

int client_is_busy_or_offline(unsigned char *namae){
    client_info *tmp;
    tmp = first_client;
    while (tmp != NULL && strcmp((char *)tmp->name,(char *)namae)) tmp = tmp->next;
    if(tmp->user_state || !(tmp->online_flag)) {return 1;} else { return 0;}
}

unsigned char *print_clients(unsigned char *namae) { 
    client_info *tmp;
    tmp = first_client;
    char *users_available;
    int n = 0;
    int n_space_needed;
    while(tmp != NULL) {
        if(strcmp((const char*)tmp->name, (const char*)namae) && (tmp->user_state == 0) && (tmp->online_flag == 1)) {
            n++;
        }
        tmp = tmp->next;
    }
    if(!n){
        users_available = malloc(strlen("Only you are available :(") + 1);
        sprintf(users_available,"Only you are available :(");
        return (unsigned char*)users_available;
    } else {
        n_space_needed = n*14;
        users_available = malloc(strlen("Only you are connected :(") + 1 + n_space_needed);
        sprintf(users_available, "These are the available users: ");
        tmp = first_client;
        while (tmp != NULL) {
            //check set_online_flag
            if(strcmp((const char*)tmp->name, (const char*)namae) && (tmp->user_state == 0) && (tmp->online_flag == 1)) 
            {
                if(n == 1) { 
                sprintf(users_available, "%s %s", users_available, (char*)tmp->name);
                tmp = tmp->next;
                } else {
                    n--; // 
                    sprintf(users_available, "%s %s, ", users_available, (char*)tmp->name);
                    tmp = tmp->next;
                }
            } else {
                tmp = tmp->next;
            }
        }
        return (unsigned char*)users_available; 
    }
}

void set_online_flag(unsigned char *namae) { 
    client_info *tmp;
    tmp = first_client;
    while (strcmp((char *)tmp->name,(char *)namae)) {tmp = tmp->next;}
    tmp->online_flag = 0;
    how_many_user_av--;
}

void free_clients(){
    client_info *tmp;
    tmp = first_client;
    while (tmp != NULL) {
        tmp = tmp->next;
        free(tmp);
        }
    if(first_client != NULL) free(first_client);
}

unsigned char *get_usr_session_key(unsigned char *namae) {
    client_info *tmp;
    tmp = first_client;
    while (tmp != NULL && strcmp((char *)tmp->name,(char *)namae)) tmp = tmp->next;
    if(!tmp || !tmp->session_key) return NULL;
    return tmp->session_key;
}

int get_usr_cont_sc(unsigned char *namae){
    client_info *tmp;
    tmp = first_client;
    while (tmp != NULL && strcmp((char *)tmp->name,(char *)namae)) tmp = tmp->next;
    if(!tmp || !tmp->session_key) return -11;
    return tmp->counter_server_client;
}
int get_usr_cont_cs(unsigned char *namae){
    client_info *tmp;
    tmp = first_client;
    while (tmp != NULL && strcmp((char *)tmp->name,(char *)namae)) tmp = tmp->next;
    if(!tmp || !tmp->session_key) return -11;
    return tmp->counter_client_server;
}
void increase_usr_cont_sc(unsigned char *namae, int cont){
    client_info *tmp;
    tmp = first_client;
    while (tmp != NULL && strcmp((char *)tmp->name,(char *)namae)) tmp = tmp->next;
    tmp->counter_server_client = cont + 1;
}
void increase_usr_cont_cs(unsigned char *namae, int cont){
    client_info *tmp;
    tmp = first_client;
    while (tmp != NULL && strcmp((char *)tmp->name,(char *)namae)) tmp = tmp->next;
    tmp->counter_client_server = cont + 1;
}