#include "../utility_fun.h"
#include "server_client_lists.h"
#include "server_handle_client.c"

extern client_info *first_client; 
extern long int how_many_user_av; 
int listening_socket = 0, conn_socket = 0;


pthread_mutex_t mut_client_sock= PTHREAD_MUTEX_INITIALIZER; 

int main(int argc, char **argv){ 
    unsigned char alice[] = "alice";
    unsigned char bob[] = "bob";
    unsigned char chloe[] = "chloe";
    unsigned char dave[] = "dave";
    create_clients(alice);
    create_clients(bob);
    create_clients(chloe);
    create_clients(dave);
    puts("Welcome. To exit press ctrl+c or ctrl+\\");
	if(argc != 2){ 
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
		return EXIT_FAILURE; 
	}

	int port = atoi(argv[1]); 
    struct sockaddr_in server;
    struct sockaddr_in client;
    pthread_t tid;

    signal(SIGPIPE, SIG_IGN); 
   
    listening_socket = socket(AF_INET, SOCK_STREAM, 0); 
    memset(&server, 0, sizeof(server)); 
    server.sin_family = AF_INET; 
    server.sin_addr.s_addr = htonl(INADDR_ANY); 
    server.sin_port = htons(port); 
	int option = 0;
	if(setsockopt(listening_socket, SOL_SOCKET, SO_REUSEADDR,(char*)&option,sizeof(option)) < 0){ 
		perror("ERROR: setsockopt failed"); 
    return EXIT_FAILURE;
	}

    if(bind(listening_socket, (struct sockaddr*)&server, sizeof(server)) < 0) { 
       perror("ERROR: Socket binding failed");
        return EXIT_FAILURE; 
    }
    
    if (listen(listening_socket, 10) < 0) { 
        perror("ERROR: Socket listening failed");
        return EXIT_FAILURE; 
        }

    puts("Waiting for incoming connections...");
    while(1) {
        socklen_t client_struct_dim = sizeof(struct sockaddr_in); 
        if ((conn_socket = accept(listening_socket, (struct sockaddr *)&client, &client_struct_dim)) < 0) 
                perror("ERROR: accept failed");
            return EXIT_FAILURE; 
            }
        client_info *user = calloc(1, sizeof(client_info));
        pthread_mutex_lock(&mut_client_sock);
            user->address = client; 
            user->local_sock = conn_socket; 
        pthread_mutex_unlock(&mut_client_sock); 
        pthread_create(&tid, NULL, &handle_client, (void*)user); 
     }
     free_clients(); 
 	return EXIT_SUCCESS;
 }