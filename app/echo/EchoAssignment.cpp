#include "EchoAssignment.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>

// !IMPORTANT: allowed system calls.
// !DO NOT USE OTHER NETWORK SYSCALLS (send, recv, select, poll, epoll, fork
// etc.)
//  * socket
//  * bind
//  * listen
//  * accept
//  * read
//  * write
//  * close
//  * getsockname
//  * getpeername
// See below for their usage.
// https://github.com/ANLAB-KAIST/KENSv3/wiki/Misc:-External-Resources#linux-manuals

int EchoAssignment::serverMain(const char *bind_ip, int port,
                               const char *server_hello) {

  int socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket_fd == -1)
    return -1;

  struct sockaddr_in socket_addr;
  memset(&socket_addr, 0, sizeof(struct sockaddr_in));
  socket_addr.sin_family = AF_INET;
  socket_addr.sin_port = port;
  inet_aton(bind_ip, &socket_addr.sin_addr);
  
  if (bind(socket_fd, (const sockaddr *)&socket_addr, 
      sizeof(struct sockaddr_in)) == -1)
    return -1;

  if (listen(socket_fd, 5) == -1)
    return -1;
  
  int client_fd;
  socklen_t socket_len = sizeof(sockaddr_in);

  while (1) {
    socket_len = sizeof(sockaddr_in);
    client_fd = accept(socket_fd, (sockaddr *)&socket_addr, &socket_len);
    if (client_fd == -1) {
      return -1;
    }

    struct sockaddr_in client_addr;
    socklen_t c_sock_len = sizeof(sockaddr_in);
    if (getpeername(client_fd, (sockaddr *)&client_addr, &c_sock_len) == -1)
      return -1;
    char c_address[16];
    memset(c_address, 0, 16);
    if (inet_ntop(AF_INET, &client_addr.sin_addr, c_address, c_sock_len) == NULL)
      return -1;

    struct sockaddr_in server_addr;
    socklen_t s_sock_len = sizeof(sockaddr_in);
    if (getsockname(client_fd, (sockaddr *)&server_addr, &s_sock_len) == -1)
      return -1;
    char s_address[16];
    memset(s_address, 0, 16);
    if (inet_ntop(AF_INET, &server_addr.sin_addr, s_address, s_sock_len) == NULL)
      return -1;

    char size[11];
    memset(size, 0, 11);
    if (read(client_fd, size, 11) == -1)
      return -1;
    int remaining_n = atoi(size);
    
    char *request = (char *)calloc(1, remaining_n + 1);
    if (read(client_fd, request, remaining_n) == -1)
      return -1;

    memset(size, 0, 11);
    if (!strcmp("hello", request)){
      sprintf(size, "%d", (int)strlen(server_hello));
      if (write(client_fd, size, 11) == -1)
        return -1;
      if (write(client_fd, server_hello, strlen(server_hello)) == -1)
        return -1;
    }else if (!strcmp("whoami", request)){
      sprintf(size, "%d", (int)strlen(c_address));
      if (write(client_fd, size, 11) == -1)
        return -1;
      if (write(client_fd, c_address, strlen(c_address)) == -1)
        return -1;
    }else if (!strcmp("whoru", request)){
      sprintf(size, "%d", (int)strlen(s_address));
      if (write(client_fd, size, 11) == -1)
        return -1;
      if (write(client_fd, s_address, strlen(s_address)) == -1)
        return -1;
    }else{
      sprintf(size, "%d", (int)strlen(request));
      if (write(client_fd, size, 11) == -1)
        return -1;
      if (write(client_fd, request, strlen(request)) == -1)
        return -1;
    }
    
    submitAnswer(c_address, request);
    free(request);
    close(client_fd);
  }

  return 0;
}

int EchoAssignment::clientMain(const char *server_ip, int port,
                               const char *command) {
  // Your client code
  // !IMPORTANT: do not use global variables and do not define/use functions
  // !IMPORTANT: for all system calls, when an error happens, your program must
  // return. e.g., if an read() call return -1, return -1 for clientMain.
  int socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (socket_fd == -1)
    return -1;

  struct sockaddr_in socket_addr;
  memset(&socket_addr, 0, sizeof(struct sockaddr_in));
  socket_addr.sin_family = AF_INET;
  socket_addr.sin_port = port;
  inet_aton(server_ip, &socket_addr.sin_addr);
  socklen_t socket_len = sizeof(sockaddr);

  if (connect(socket_fd, (const sockaddr *)&socket_addr, socket_len) == -1)
    return -1;
  
  struct sockaddr_in server_addr;
  socklen_t s_socklen = sizeof(sockaddr);
  if (getpeername(socket_fd, (sockaddr *)&server_addr, &s_socklen) == -1)
    return -1;
  char s_address[16];
  memset(s_address, 0, 16);
  inet_ntop(AF_INET, &server_addr.sin_addr, s_address, s_socklen);

  char req_size[11];
  memset(req_size, 0, 11);
  sprintf(req_size, "%d", (int)strlen(command));
  if (write(socket_fd, req_size, 11) == -1)
    return -1;
  if (write(socket_fd, command, strlen(command)) == -1)
    return -1;

  char res_size[11];
  memset(res_size, 0, 11);
  if (read(socket_fd, res_size, 11) == -1)
    return -1;
  int remaining_n = atoi(res_size);
  char *response = (char *)calloc(1, remaining_n + 1);
  if (read(socket_fd, response, remaining_n) == -1)
    return -1;

  submitAnswer(s_address, response);

  close(socket_fd);
  free(response);

  return 0;
}

static void print_usage(const char *program) {
  printf("Usage: %s <mode> <ip-address> <port-number> <command/server-hello>\n"
         "Modes:\n  c: client\n  s: server\n"
         "Client commands:\n"
         "  hello : server returns <server-hello>\n"
         "  whoami: server returns <client-ip>\n"
         "  whoru : server returns <server-ip>\n"
         "  others: server echos\n"
         "Note: each command is terminated by newline character (\\n)\n"
         "Examples:\n"
         "  server: %s s 0.0.0.0 9000 hello-client\n"
         "  client: %s c 127.0.0.1 9000 whoami\n",
         program, program, program);
}

int EchoAssignment::Main(int argc, char *argv[]) {

  if (argc == 0)
    return 1;

  if (argc != 5) {
    print_usage(argv[0]);
    return 1;
  }

  int port = atoi(argv[3]);
  if (port == 0) {
    printf("Wrong port number\n");
    print_usage(argv[0]);
  }

  switch (*argv[1]) {
  case 'c':
    return clientMain(argv[2], port, argv[4]);
  case 's':
    return serverMain(argv[2], port, argv[4]);
  default:
    print_usage(argv[0]);
    return 1;
  }
}
