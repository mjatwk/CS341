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

addr_entry* bound_addrs;

addr_entry* get_addr_entry_by_fd(int fd) {
  for (addr_entry* cur = bound_addrs->next; cur != bound_addrs; cur = cur->next) 
  {
    if (cur->fd == fd)
    {
      return cur;
    }
  } 
  return NULL;
}

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {
  bound_addrs = (addr_entry *)malloc(sizeof(struct addr_entry));
  bound_addrs->addr = NULL;
  bound_addrs->prev = bound_addrs;
  bound_addrs->next = bound_addrs;
}

void TCPAssignment::finalize() {

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  // Remove below
  // (void)syscallUUID;
  // (void)pid;
  sockaddr_in* sock = (sockaddr_in*)malloc(sizeof(sockaddr_in));
  addr_entry* cur;
  addr_entry* new_addr;
  addr_entry* addr;
  int fd;
  bool success;

  switch (param.syscallNumber) {
  case SOCKET:
    // this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    this->returnSystemCall(syscallUUID, this->createFileDescriptor(pid)); 
    break;

  case CLOSE:
    // this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    fd = std::get<int>(param.params[0]);
    this->removeFileDescriptor(pid, fd);

    addr = get_addr_entry_by_fd(fd);
    if (addr == NULL) {
      success = false;
      this->returnSystemCall(syscallUUID, -1); 
    } else {
      addr->prev->next = addr->next;
      addr->next->prev = addr->prev;
      free(addr);
      this->returnSystemCall(syscallUUID, 0);
    }
    break;
  
  case READ:
    // this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
    //                    std::get<void *>(param.params[1]),
    //                    std::get<int>(param.params[2]));
    break;
  
  case WRITE:
    // this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
    //                     std::get<void *>(param.params[1]),
    //                     std::get<int>(param.params[2]));
    break;
  
  case CONNECT:
    // this->syscall_connect(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
    break;
  
  case LISTEN:
    // this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
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
    // int bind(int socket, const struct sockaddr *address, socklen_t address_len);
    
    success = true;
    memcpy(sock, static_cast<struct sockaddr_in *>(std::get<void *> (param.params[1])), sizeof(struct sockaddr_in));
    
    // check if the address is not bound
    for (cur = bound_addrs->next; cur != bound_addrs; cur = cur->next) {
      if (!memcmp(cur->addr, sock, sizeof(addr_entry)))
      {
        // the address is already bound
        success = false;
        break;
      }
    } 

    if (success) {
      new_addr = (addr_entry *)malloc(sizeof(addr_entry));
      new_addr->fd = std::get<int>(param.params[0]);
      new_addr->addr = sock;
      
      // insert addrs list
      bound_addrs->prev->next = new_addr;
      new_addr->prev = bound_addrs->prev;
      new_addr->next = bound_addrs;
      bound_addrs->prev = new_addr;
      
      this->returnSystemCall(syscallUUID, 0);
    } else {
      this->returnSystemCall(syscallUUID, -1);
    }

    break;
  
  case GETSOCKNAME:
    // this->syscall_getsockname(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    // int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
    fd = std::get<int>(param.params[0]);

    addr = get_addr_entry_by_fd(fd);
    if (addr == NULL) {
      this->returnSystemCall(syscallUUID, -1);
    } else {
      memcpy(sock, static_cast<struct sockaddr_in *>(std::get<void *> (param.params[1])), sizeof(struct sockaddr_in));
      this->returnSystemCall(syscallUUID, 0);
    }

    break;
  
  case GETPEERNAME:
    // this->syscall_getpeername(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    
    break;
  
  default:
    assert(0);
  }
  
  free(sock);
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
