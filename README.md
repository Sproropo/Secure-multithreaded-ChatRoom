# Secure multithreaded ChatRoom
- This project is a client-server multi-threaded application that allows clients to communicate through an authenticated channel. Users interact with the application entirely through the command line.
- Clients rely on the server to identify available users; their communication with the server is encrypted. However, once connected, messages between clients are secured by end-to-end encryption, meaning the server cannot read their contents. 
- The communication is protected by an authentication mechanism, providing security against MITM and REPLAY attacks. 
- The communication features the use of ephemeral public keys.
- (Note: This is an older project originally created and distributed by me in 2022 before being uploaded in 2024 to GitHub.)

## Compilation
- Server: gcc -lcrypto -lpthread src_server/server.c -o server
- Client: gcc -lcrypto -lpthread src_client/client.c -o client
 Execution:

## Usage
- Server: `./server <port_number>`
- Client: `./client <server_ip_address> <username> <server_port>`
- type `a`: Request a list of available clients.
- start with `@username:` to send a chat request to another client.
- type `resume`: Withdraw a chat request sent.
- Incoming requests
	- type `yes`: Accept an incoming chat request.
	- type `no`: Decline an incoming chat request.


 
