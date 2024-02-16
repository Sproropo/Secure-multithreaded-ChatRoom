#ifndef SERVER_CLIENT_LISTS_H 
#define SERVER_CLIENT_LISTS_H

typedef struct client_struct{ 
    int local_sock; 
    short volatile int online_flag;
    short volatile int user_state;
    unsigned char name[14]; 
	struct sockaddr_in address; 
    struct client_struct *next; 
    struct client_struct *client_rcvr;
    unsigned char* session_key;
    int counter_client_server;
    int counter_server_client;
    int p_dim;
}client_info; 

void create_clients(unsigned char *name_user);
int update_client(client_info user);
client_info *return_client(unsigned char *namae);

int search_client(unsigned char *namae); 
client_info *search_rcvr(unsigned char *namae);
unsigned char *print_clients(unsigned char *namae);

void change_state_user(unsigned char *namae, int state);
void set_online_flag(unsigned char *namae); 
int client_is_busy_or_offline(unsigned char *namae); 

void add_client_rcvr(client_info user, unsigned char *name_client_receiver); 
void rmv_clients_rcvr(client_info user); 

void free_clients();
int is_client_online(unsigned char *namae);
unsigned char *get_usr_session_key(unsigned char *namae);
int get_usr_cont_sc(unsigned char *namae);
int get_usr_cont_cs(unsigned char *namae);
void increase_usr_cont_sc(unsigned char *namae, int cont);
void increase_usr_cont_cs(unsigned char *namae, int cont);
#endif