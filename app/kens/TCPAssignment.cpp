/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

namespace E {

#define min(a, b) (a > b ? b : a)

  struct socket_info* all_sockets;
  struct addr_entry* bound_addrs;

bool is_addr_used(sockaddr* addr) {
  sockaddr_in* addr_in = (sockaddr_in*)addr;
  bool result = false;
  for(addr_entry* cur = bound_addrs->next; cur != bound_addrs; cur = cur->next) {

    // same addr and port
    if(!memcmp(&cur->addr, addr, sizeof(cur->addr))) {
      result = true;
      break;
    }

    // INADDR_ANY && same port
    if((cur->addr.sin_addr.s_addr == INADDR_ANY || addr_in->sin_addr.s_addr == INADDR_ANY) &&
      cur->addr.sin_port == addr_in->sin_port) {
      result = true;
      break;
    }
  }
  return result;
} 

// get socket_info by HOST_NAME and FD from HEAD list
socket_info* get_socket_info_by_fd(socket_info* head, std::string host_name, int fd) {
  for (socket_info* cur = head->next; cur != head; cur = cur->next) 
  {
    if (!cur->host_name.compare(host_name) && cur->fd == fd)
    {
      return cur;
    }
  } 
  return NULL;
}

// get socket_info by HOST_ADDR from HEAD list
socket_info* get_socket_info_by_addr(socket_info* head, sockaddr_in* addr) {
  for (socket_info* cur = head->next; cur != head; cur = cur->next) 
  {
    if (!memcmp(&cur->host_addr, addr, sizeof(sockaddr_in)) ||
      ((cur->host_addr.sin_addr.s_addr == INADDR_ANY || 
        addr->sin_addr.s_addr == INADDR_ANY) &&
        cur->host_addr.sin_port == addr->sin_port))
    {
      return cur;
    }
  } 
  return NULL;
}

// get addr_entry by HOST_ADDR from HEAD list
addr_entry* get_addr_entry_by_addr(addr_entry* head, sockaddr_in* addr) {
  for (addr_entry* cur = head->next; cur != head; cur = cur->next) 
  {
    if (!memcmp(&cur->addr, addr, sizeof(sockaddr_in)) ||
      ((cur->addr.sin_addr.s_addr == INADDR_ANY || 
        addr->sin_addr.s_addr == INADDR_ANY) &&
        cur->addr.sin_port == addr->sin_port))
    {
      return cur;
    }
  } 
  return NULL;
}


// print linked list strating from HEAD
void socket_info_list_iterate(socket_info* head) {
  printf("iterating...\n");
  for (socket_info* cur = head->next; cur != head; cur = cur->next) 
  {
    printf("hostname is %s, ", (cur->host_name).c_str());
  }
  printf("list ended...\n");
}

// append ADDR to the linked list starting with HEAD
void append_addr_entry(addr_entry* head, addr_entry* addr) {
  head->prev->next = addr;
  addr->prev = head->prev;
  addr->next = head;
  head->prev = addr;
}

// remove ADDR from the linked list
void remove_addr_entry(addr_entry* addr) {
  addr->prev->next = addr->next;
  addr->next->prev = addr->prev;
}

// append SOCK_INFO to the linked list starting with HEAD
void append_socket_info(socket_info* head, socket_info* sock_info) {
  head->prev->next = sock_info;
  sock_info->prev = head->prev;
  sock_info->next = head;
  head->prev = sock_info;
}

// remove SOCK_INFO from the linked list
void remove_socket_info(socket_info* sock_info) {
  sock_info->prev->next = sock_info->next;
  sock_info->next->prev = sock_info->prev;
}

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {
  all_sockets = (socket_info*)malloc(sizeof(socket_info));
  all_sockets->next = all_sockets;
  all_sockets->prev = all_sockets;

  bound_addrs = (addr_entry*)malloc(sizeof(addr_entry));
  bound_addrs->next = bound_addrs;
  bound_addrs->prev = bound_addrs;
}

void TCPAssignment::finalize() {}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  // Remove below
  // (void)syscallUUID;
  // (void)pid;

  socket_info* self_sock_info;
  socket_info* peer_sock_info;

  int fd;
  sockaddr* temp_sockaddr = NULL;
  sockaddr_in* new_sockaddr = (sockaddr_in *)malloc(sizeof(sockaddr_in));

  socklen_t sock_len;
  socklen_t* sock_len_p;

  addr_entry* temp_addr_entry;
  addr_entry* new_addr_entry = (addr_entry *)malloc(sizeof(addr_entry));

  bool success = true;

  std::string host_name = getHostModuleName();

  switch (param.syscallNumber) {
  case SOCKET:
    // this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    // int socket(int domain, int type__unused, int protocol)
    self_sock_info = (socket_info*)malloc(sizeof(socket_info));
    memset(self_sock_info, 0, sizeof(socket_info));
    self_sock_info->host_name.assign(host_name);
    self_sock_info->fd = this->createFileDescriptor(pid);
    self_sock_info->tcp_status = TCP_CLOSE;
    self_sock_info->sock_status = OPENED;

    append_socket_info(all_sockets, self_sock_info);

    this->returnSystemCall(syscallUUID, self_sock_info->fd);
    break;
  case CLOSE:
    // this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    // int close(int fd)
    
    fd = std::get<int>(param.params[0]);
    self_sock_info = get_socket_info_by_fd(all_sockets, host_name, fd);    
    temp_addr_entry = get_addr_entry_by_addr(bound_addrs, &self_sock_info->host_addr);
    this->removeFileDescriptor(pid, fd);

    // handle sock_info
    // if sock_info is null
    if (self_sock_info == NULL){
      success = false;
      this->returnSystemCall(syscallUUID, -1);
    } else {
      remove_socket_info(self_sock_info);
      free(self_sock_info);
    }

    // handle addr_entry
    if (temp_addr_entry != NULL){
      remove_addr_entry(temp_addr_entry);
      free(temp_addr_entry);
    }
    this->returnSystemCall(syscallUUID, 0);
    break;
  case READ:
    // this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
    //                    std::get<void *>(param.params[1]),
    //                    std::get<int>(param.params[2]));
    // int read(int fd, void *buf, size_t count)
    break;
  case WRITE:
    // this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
    //                     std::get<void *>(param.params[1]),
    //                     std::get<int>(param.params[2]));
    // int write(int fd, const void *buf, size_t cound
    break;
  case CONNECT:
    // this->syscall_connect(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
    // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
    break;
  case LISTEN:
    // this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    // int listen(int sockfd, int backlog)
    break;
  case ACCEPT:
    // this->syscall_accept(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case BIND:
    // this->syscall_bind(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
    // int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
    fd = std::get<int>(param.params[0]);
    self_sock_info = get_socket_info_by_fd(all_sockets, getHostModuleName(), fd);
    
    // if self_sock_info pointer is null 
    if (self_sock_info == NULL) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    } else if (self_sock_info->sock_status != OPENED) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    }
    
    sock_len = (socklen_t)std::get<int>(param.params[2]);

    // host_addr bind
    memcpy(&self_sock_info->host_addr, (sockaddr_in*)std::get<void *>(param.params[1]), (size_t)min(sock_len, (socklen_t)sizeof(sockaddr_in)));
    // if is already bound 
    if (is_addr_used((sockaddr *)&self_sock_info->host_addr)) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    } else {
      // append bound addrs list
      memcpy(&new_addr_entry->addr, &self_sock_info->host_addr, sizeof(sockaddr_in));
      append_addr_entry(bound_addrs, new_addr_entry);
    }

    self_sock_info->sock_status = BOUND;
    // is always true in the end, breaks before end if fail
    this->returnSystemCall(syscallUUID, 0);
    // printf("bind() ended\n");
    break;
  case GETSOCKNAME:
    // this->syscall_getsockname(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    // int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
    fd = std::get<int>(param.params[0]);
    self_sock_info = get_socket_info_by_fd(all_sockets, host_name, fd);
    temp_sockaddr = static_cast<struct sockaddr *>(std::get<void *>(param.params[1]));
    sock_len_p = static_cast<socklen_t *>(std::get<void *>(param.params[2]));
    
    memcpy(temp_sockaddr, &self_sock_info->host_addr, min(*sock_len_p, sizeof(sockaddr_in)));
    *sock_len_p = sizeof(sockaddr_in);
    
    this->returnSystemCall(syscallUUID, 0);
    printf("getsockname() ended\n");
    break;
  case GETPEERNAME:
    // this->syscall_getpeername(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    // int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
