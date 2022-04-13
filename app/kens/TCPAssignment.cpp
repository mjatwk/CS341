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
#define MIN_BACKLOG 1
#define START_PORT 0

struct socket_info* all_sockets;
struct addr_entry* bound_addrs;
struct syscall_entry* blocked_syscalls;


uint16_t convert_2byte(uint16_t ori) {
  return (ori << 8) | (ori >> 8);
}

uint32_t convert_4byte(uint32_t ori) {
  return ((ori << 24)&0xFF000000) | ((ori << 8)&0x00FF0000) | ((ori >> 8)&0x0000FF00) | ((ori >> 24)&0x000000FF);
}

bool is_bound(int pid, int fd, sockaddr* addr) {
  sockaddr_in* addr_in = (sockaddr_in*)addr;
  bool bound = false;
  for(addr_entry* cur = bound_addrs->next; cur != bound_addrs; cur = cur->next) {
    // same fd
    if(cur->fd == fd && cur->pid == pid) {
      bound = true;
      break;
    }
    // same addr and port
    if(!memcmp(&cur->addr, addr, sizeof(cur->addr))) {
      bound = true;
      break;
    }
    // INADDR_ANY && same port
    if((cur->addr.sin_addr.s_addr == INADDR_ANY || addr_in->sin_addr.s_addr == INADDR_ANY) &&
      cur->addr.sin_port == addr_in->sin_port) {
      bound = true;
      break;
    }
  }
  return bound;
} 

// get socket_info by FD from HEAD list
socket_info* get_socket_info_by_fd(socket_info* head, int pid, int fd) {
  for (socket_info* cur = head->next; cur != head; cur = cur->next) 
  {
    if (cur->fd == fd && cur->pid == pid)
    {
      return cur;
    }
  } 
  return NULL;
}

// get socket_info by ADDR from HEAD list
socket_info* get_socket_info_by_addr(socket_info* head, sockaddr_in* addr) {
  for (socket_info* cur = head->next; cur != head; cur = cur->next) 
  {
    // printf("getsockaddr: %x:%d\n", cur->host_addr.sin_addr.s_addr, cur->host_addr.sin_port);
    if ((cur->host_addr.sin_addr.s_addr == (addr->sin_addr.s_addr) && cur->host_addr.sin_port == (addr->sin_port)) ||
      (cur->host_addr.sin_addr.s_addr == INADDR_ANY || 
        addr->sin_addr.s_addr == INADDR_ANY))
    {
      return cur;
    }
  } 
  return NULL;
}

// get socket_info by HOST_ADDR from HEAD list
packet_info* pop_packet_info_by_addr(packet_info* head, sockaddr_in* addr) {
  for (packet_info* cur = head->next; cur != head; cur = cur->next) 
  {
    if (cur->src_addr.sin_addr.s_addr == addr->sin_addr.s_addr ||
      (cur->src_addr.sin_addr.s_addr == INADDR_ANY || 
        addr->sin_addr.s_addr == INADDR_ANY))
    {
      cur->prev->next = cur->next;
      cur->next->prev = cur->prev;
      cur->next = NULL;
      cur->prev = NULL;
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
    ;
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

// append WAITER to the LISTENER's pending list
void append_packet_info(packet_info* head, packet_info* waiter) {
  head->prev->next = waiter;
  waiter->prev = head->prev;
  waiter->next = head;
  head->prev = waiter;
}

// remove SOCK_INFO from pending_list or established_list 
void remove_packet_info(packet_info* pack_info) {
  pack_info->prev->next = pack_info->next;
  pack_info->next->prev = pack_info->prev;
  pack_info->prev = NULL;
  pack_info->next = NULL;
}

// 
void free_packet_list(packet_info* head) {
  packet_info* temp;
  for (packet_info* cur = head->next; cur != head; ) {
    temp = cur->next;
    free(cur);
    cur = temp;
  }
  free(head);
}

// append SOCK_INFO to the linked list starting with HEAD
void append_syscall_entry(syscall_entry* head, syscall_entry* syscall) {
  head->prev->next = syscall;
  syscall->prev = head->prev;
  syscall->next = head;
  head->prev = syscall;
}

// remove SOCK_INFO from the linked list
void remove_syscall_entry(syscall_entry* syscall) {
  syscall->prev->next = syscall->next;
  syscall->next->prev = syscall->prev;
}

void free_blocked_list(syscall_entry* head) {
  syscall_entry* temp;
  for (syscall_entry* cur = head->next; cur != head; ) {
    temp = cur->next;
    free(cur);
    cur = temp;
  }
  free(head);
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

  blocked_syscalls = (syscall_entry*)malloc(sizeof(syscall_entry));
  blocked_syscalls->next = blocked_syscalls;
  blocked_syscalls->prev = blocked_syscalls;
}

void TCPAssignment::finalize() {
  printf("finalize() started\n");
  for (syscall_entry *cur_syscall = blocked_syscalls->next; cur_syscall != blocked_syscalls; cur_syscall = cur_syscall->next) {
    printf("finalize: return -1: %d\n", cur_syscall->uuid);
    this->returnSystemCall(cur_syscall->uuid, -1);
  }
  free(blocked_syscalls);
  // TODO: free
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  // Remove below
  // (void)syscallUUID;
  // (void)pid;

  socket_info* sock_info;
  socket_info* new_sock_info;
  tcp_segment* new_tcp_seg;

  packet_info* established_pack_info;
  packet_info* new_pack_info;

  int fd;
  int backlog;
  sockaddr* temp_sockaddr;
  in_addr_t host_ip;
  in_addr_t peer_ip;
  sockaddr_in* new_sockaddr;

  sockaddr_in vacant_sockaddr;
  memset(&vacant_sockaddr, 0, sizeof(vacant_sockaddr));
  sockaddr_in* search_sockaddr;
  in_port_t port;
  std::optional<E::ipv4_t> possible_ipv4_op;
  ipv4_t possible_ipv4;
  uint32_t possible_address;

  socklen_t sock_len;
  socklen_t* sock_len_p;

  addr_entry* temp_addr_entry;
  addr_entry* new_addr_entry;

  syscall_entry* temp_syscall;

  bool success = true;

  ipv4_t binding_ip;
  ipv4_t src_ip;
  ipv4_t dst_ip;

  Packet pkt (54);

  packet_info* sent_packet_info;

  switch (param.syscallNumber) {
  case SOCKET:
    // this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    // int socket(int domain, int type__unused, int protocol)
    printf("socket() started\n");
    sock_info = (socket_info*)malloc(sizeof(socket_info));
    memset(sock_info, 0, sizeof(socket_info));
    sock_info->fd = this->createFileDescriptor(pid);
    sock_info->pid = pid;
    sock_info->tcp_status = TCP_CLOSE;

    append_socket_info(all_sockets, sock_info);
   
    sock_info->pending_list = (packet_info *)malloc(sizeof(packet_info));
    memset(sock_info->pending_list, 0, sizeof(packet_info));
    sock_info->pending_list->prev = sock_info->pending_list;
    sock_info->pending_list->next = sock_info->pending_list;

    sock_info->established_list = (packet_info *)malloc(sizeof(packet_info));
    memset(sock_info->established_list, 0, sizeof(packet_info));
    sock_info->established_list->prev = sock_info->established_list;
    sock_info->established_list->next = sock_info->established_list;

    sock_info->self_syscall = (syscall_entry *)malloc(sizeof(syscall_entry));
    memset(sock_info->self_syscall, 0, sizeof(syscall_entry));
    sock_info->self_syscall->prev = NULL;
    sock_info->self_syscall->next = NULL;
    printf("socket() finishing\n");
    this->returnSystemCall(syscallUUID, sock_info->fd);
    break;

  case CLOSE:
    // this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    // int close(int fd)
    fd = std::get<int>(param.params[0]);
    sock_info = get_socket_info_by_fd(all_sockets, pid, fd);
    temp_addr_entry = get_addr_entry_by_addr(bound_addrs, &sock_info->host_addr);
    this->removeFileDescriptor(pid, fd);
    // handle sock_info
    // if sock_info is null
    if (sock_info == NULL){
      success = false;
      this->returnSystemCall(syscallUUID, -1);
    } else {
      // free_packet_list(sock_info->pending_list);
      // free_packet_list(sock_info->established_list);
      // if(sock_info->self_syscall->next != NULL) {
      //   remove_syscall_entry(sock_info->self_syscall);
      // }
      // free(sock_info->self_syscall);
      
      // remove_socket_info(sock_info);
      // free(sock_info);
  

      // TODO: free
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
    
    // should convert ip of server addr
    fd = std::get<int>(param.params[0]);
    temp_sockaddr = static_cast<struct sockaddr *>(std::get<void *>(param.params[1]));
    sock_len = (socklen_t)std::get<int>(param.params[2]);

    printf("connect() started uuid:%d\n", syscallUUID);
    // ERROR: not an existing fd
    sock_info = get_socket_info_by_fd(all_sockets, pid, fd);
    if (sock_info == NULL) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    }
    // if client addr is vacant should bind 
    if (!memcmp(&sock_info->host_addr, &vacant_sockaddr, sizeof(sock_info->host_addr))) {
      search_sockaddr = (sockaddr_in *)malloc(sizeof(sockaddr_in));
      search_sockaddr->sin_family = AF_INET;
      
      // find available address and port
      port = 0;
      do {
        possible_ipv4_op = getIPAddr(port++);
        possible_ipv4 = possible_ipv4_op.value();
          possible_address = (uint32_t)NetworkUtil::arrayToUINT64<4>(possible_ipv4);        
          // printf("possible ipv4 is 0x%x:%d\n", convert_4byte(possible_address), (port-1));
          search_sockaddr->sin_addr.s_addr = (possible_address);
          // ALERT: this port is not the port used here 
          search_sockaddr->sin_port = (port-1);
        
      } while (is_bound(pid, fd, (sockaddr*) search_sockaddr));
      
      memcpy(&sock_info->host_addr, search_sockaddr, sizeof(sockaddr_in));
      free(search_sockaddr);

      // printf("possible ipv4 is 0x%x:%d\n", (sock_info->host_addr.sin_addr.s_addr), (sock_info->host_addr.sin_port));
    }


    // peer address copy
    memcpy(&sock_info->peer_addr, temp_sockaddr, min(sock_len, (socklen_t)sizeof(sockaddr_in)));
    new_tcp_seg = (tcp_segment*)malloc(sizeof(tcp_segment));
    memset(new_tcp_seg, 0, sizeof(tcp_segment));
    // sent_packet_info = (packet_info *)malloc(sizeof(packet_info));

    new_tcp_seg->src_port = (sock_info->host_addr.sin_port);
    new_tcp_seg->dst_port = (sock_info->peer_addr.sin_port);
    new_tcp_seg->seq = convert_4byte(rand());
    new_tcp_seg->flags = (5 << 11); // Header length is 5 words
    new_tcp_seg->flags = (new_tcp_seg->flags + 1) << 1; // SYN is set
    new_tcp_seg->flags = convert_2byte(new_tcp_seg->flags);
    new_tcp_seg->rec_win = 200;
    new_tcp_seg->urg_pts = 0;
    
    host_ip = (sock_info->host_addr.sin_addr.s_addr);
    peer_ip = (sock_info->peer_addr.sin_addr.s_addr);

    new_tcp_seg->checksum = htons(~NetworkUtil::tcp_sum(host_ip, peer_ip, (uint8_t*)new_tcp_seg, 20));

    pkt.writeData(26, &host_ip, 4);
    pkt.writeData(30, &peer_ip, 4);
    pkt.writeData(34, new_tcp_seg, 20);
    
    sock_info->tcp_status = TCP_SYN_SENT;
    sock_info->self_syscall->seq = convert_4byte(new_tcp_seg->seq);
    
    sendPacket("IPv4", pkt);

    sock_info->self_syscall->uuid = syscallUUID;
    sock_info->self_syscall->self_socket = sock_info;
    sock_info->self_syscall->temp_sockaddr = temp_sockaddr;
    sock_info->self_syscall->sock_len_p = &sock_len;
    append_syscall_entry(blocked_syscalls, sock_info->self_syscall);

    printf("connect() ended\n");
    break;


  case LISTEN:
    // this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    // int listen(int sockfd, int backlog)

    fd = std::get<int>(param.params[0]);
    backlog = std::get<int>(param.params[1]);
    sock_info = get_socket_info_by_fd(all_sockets, pid, fd);
    // if fd is invalid 
    if (sock_info == NULL) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    }
    // sock_info init
    if (backlog <= 0){ 
      backlog = MIN_BACKLOG;
    }

    sock_info->backlog = backlog;
    sock_info->tcp_status = TCP_LISTEN;

    this->returnSystemCall(syscallUUID, 0);
    break;
    
  case ACCEPT:
    // this->syscall_accept(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    // int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)

    fd = std::get<int>(param.params[0]);
    temp_sockaddr = static_cast<struct sockaddr *>(std::get<void *>(param.params[1]));
    sock_len_p = static_cast<socklen_t *>(std::get<void *>(param.params[2]));

    printf("accept() started\n");
    // ERROR: not an existing fd
    sock_info = get_socket_info_by_fd(all_sockets, pid, fd);
    if (sock_info == NULL) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      printf("accept01\n");
      break;
    }
    // ERROR: listen() never called before
    // if (sock_info->tcp_status != TCP_LISTEN) {
    //   success = false;
    //   this->returnSystemCall(syscallUUID, -1);
    //   break;
    // }

    // There exists etablished connections
    if (sock_info->established_num != 0) {

      printf("accept01\n");
      // pop from established list
      established_pack_info = sock_info->established_list->next;
      remove_packet_info(established_pack_info);
      sock_info->established_num--;

      // create a new fd
      new_sock_info = (socket_info*)malloc(sizeof(socket_info));
      memset(new_sock_info, 0, sizeof(socket_info));
      append_socket_info(all_sockets, new_sock_info);
      printf("accept02\n");
      
      // initialize
      new_sock_info->fd = this->createFileDescriptor(pid);
      new_sock_info->pid = pid;
      new_sock_info->tcp_status = TCP_ESTABLISHED;
      new_sock_info->self_syscall = (syscall_entry *)malloc(sizeof(syscall_entry));
      memset(sock_info->self_syscall, 0, sizeof(syscall_entry));
      printf("accept03\n");

      memcpy(&new_sock_info->host_addr, &sock_info->host_addr, sizeof(sockaddr_in));
      memcpy(&new_sock_info->peer_addr, &established_pack_info->src_addr, sizeof(sockaddr_in));

      // return
      *sock_len_p = sizeof(sockaddr_in);
      memcpy(temp_sockaddr, &new_sock_info->peer_addr, sizeof(sockaddr_in));
      printf("fd is %d\n", new_sock_info->fd);
      this->returnSystemCall(syscallUUID, new_sock_info->fd);

    // There are no established connection, blocked.
    } else {
      // init self_syscall
      sock_info->self_syscall->uuid = syscallUUID;
      sock_info->self_syscall->self_socket = sock_info;
      sock_info->self_syscall->temp_sockaddr = temp_sockaddr;
      sock_info->self_syscall->sock_len_p = sock_len_p;
      // append to blocked_syscalls
      append_syscall_entry(blocked_syscalls, sock_info->self_syscall);
    }

    break;

  case BIND:
    // this->syscall_bind(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
    // int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
    fd = std::get<int>(param.params[0]);
    sock_info = get_socket_info_by_fd(all_sockets, pid, fd);
    
    // if sock_info pointer is null 
    if (sock_info == NULL) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    } else if (sock_info->tcp_status != TCP_CLOSE) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    }
    
    sock_len = (socklen_t)std::get<int>(param.params[2]);
    new_addr_entry = (addr_entry *)malloc(sizeof(addr_entry));

    // host_addr bind
    memcpy(&sock_info->host_addr, (sockaddr_in*)std::get<void *>(param.params[1]), (size_t)min(sock_len, (socklen_t)sizeof(sockaddr_in)));
    // if fd is already bound 
    if (is_bound(pid, fd, (sockaddr *)&sock_info->host_addr)) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    }
    // if addr is already bound
    if (is_bound(pid, fd, (sockaddr *)&sock_info->host_addr)) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    }
    // append bound addrs list
    memcpy(&new_addr_entry->addr, &sock_info->host_addr, sizeof(sockaddr_in));
    new_addr_entry->fd = fd;
    new_addr_entry->pid = pid;
    append_addr_entry(bound_addrs, new_addr_entry);
    // is always true in the end, breaks before end if fail
    this->returnSystemCall(syscallUUID, 0);

    printf("fd: %d, pid: %d h_addr: 0x%x:%d\n", fd, pid, sock_info->host_addr.sin_addr.s_addr, sock_info->host_addr.sin_port);
    break;
    
  case GETSOCKNAME:
    // this->syscall_getsockname(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    // int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
    fd = std::get<int>(param.params[0]);
    sock_info = get_socket_info_by_fd(all_sockets, pid, fd);
    temp_sockaddr = static_cast<struct sockaddr *>(std::get<void *>(param.params[1]));
    sock_len_p = static_cast<socklen_t *>(std::get<void *>(param.params[2]));
    
    // handle null pointer error
    if (sock_info == NULL) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    } 
    memcpy(temp_sockaddr, &sock_info->host_addr, min(*sock_len_p, sizeof(sockaddr_in)));
    *sock_len_p = sizeof(sockaddr_in);
    
    this->returnSystemCall(syscallUUID, 0);
    break;

  case GETPEERNAME:
    // this->syscall_getpeername(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    // int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
    
    printf("getpeername() started\n");
    
    fd = std::get<int>(param.params[0]);
    sock_info = get_socket_info_by_fd(all_sockets, pid, fd);
    temp_sockaddr = static_cast<struct sockaddr *>(std::get<void *>(param.params[1]));
    sock_len_p = static_cast<socklen_t *>(std::get<void *>(param.params[2]));
    
    // handle null pointer error
    if (sock_info == NULL) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    } 
    memcpy(temp_sockaddr, &sock_info->peer_addr, min(*sock_len_p, sizeof(sockaddr_in)));
    *sock_len_p = sizeof(sockaddr_in);
    
    this->returnSystemCall(syscallUUID, 0);
    printf("getpeername() ended\n");
    
    break;

  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // // Remove below
  // (void)fromModule;
  // (void)packet;

  tcp_segment arrived_tcp_seg;
  ipv4_t src_ip;
  ipv4_t dst_ip;

  // read as arrived_tcp_seg and store in arrived_packet
  packet.readData(34, &arrived_tcp_seg, sizeof(tcp_segment));
  packet_info* arrived_packet = (packet_info*)malloc(sizeof(packet_info));
  memset(arrived_packet, 0, sizeof(arrived_packet));

  // arrived_tcp_seg.src_port = convert_2byte(arrived_tcp_seg.src_port);
  // arrived_tcp_seg.dst_port = convert_2byte(arrived_tcp_seg.dst_port);
  arrived_tcp_seg.seq = convert_4byte(arrived_tcp_seg.seq);
  arrived_tcp_seg.ack = convert_4byte(arrived_tcp_seg.ack);
  arrived_tcp_seg.flags = convert_2byte(arrived_tcp_seg.flags);
  arrived_tcp_seg.rec_win = convert_2byte(arrived_tcp_seg.rec_win);
  arrived_tcp_seg.checksum = convert_2byte(arrived_tcp_seg.checksum);
  arrived_tcp_seg.urg_pts = convert_2byte(arrived_tcp_seg.urg_pts);
  
  // printf("src_port: %d [%d]\n", arrived_tcp_seg.src_port, sizeof(arrived_tcp_seg.src_port));
  // printf("dst_port: %d [%d]\n", arrived_tcp_seg.dst_port, sizeof(arrived_tcp_seg.dst_port));
  // printf("seq: %d [%d]\n", arrived_tcp_seg.seq, sizeof(arrived_tcp_seg.seq));
  // printf("ack: %d [%d]\n", arrived_tcp_seg.ack, sizeof(arrived_tcp_seg.ack));
  // printf("flags: %d [%d]\n", arrived_tcp_seg.flags, sizeof(arrived_tcp_seg.flags));
  // printf("rec_win: %d [%d]\n", arrived_tcp_seg.rec_win, sizeof(arrived_tcp_seg.rec_win));
  // printf("checksum: %d [%d]\n", arrived_tcp_seg.checksum, sizeof(arrived_tcp_seg.checksum));

  int32_t addr;
  // src_addr
  arrived_packet->src_addr.sin_family=AF_INET;
  arrived_packet->src_addr.sin_port=(arrived_tcp_seg.src_port);
  packet.readData(26, &addr, 4);
  arrived_packet->src_addr.sin_addr.s_addr = (addr);

  // dst_addr
  arrived_packet->dst_addr.sin_family=AF_INET;
  arrived_packet->dst_addr.sin_port=(arrived_tcp_seg.dst_port);
  packet.readData(30, &addr, 4);
  arrived_packet->dst_addr.sin_addr.s_addr = (addr);
  // printf("addr is 0x%x:%d\n", arrived_packet->dst_addr.sin_addr.s_addr, arrived_packet->dst_addr.sin_port);

  socket_info* self_sock_info = get_socket_info_by_addr(all_sockets, &arrived_packet->dst_addr);
  
  arrived_packet->seq = arrived_tcp_seg.seq;
  arrived_packet->ack = arrived_tcp_seg.ack;
  arrived_packet->SYN = !!(arrived_tcp_seg.flags & 0x0002);
  arrived_packet->ACK = !!(arrived_tcp_seg.flags & 0x0010);
  arrived_packet->FIN = !!(arrived_tcp_seg.flags & 0x0001);
  arrived_packet->checksum = arrived_tcp_seg.checksum;
  arrived_packet->prev = NULL;
  arrived_packet->next = NULL;   
  // now, packet info is written in arrived packet 
  
  // construct a new packet to send
  struct tcp_segment* new_tcp_seg = (tcp_segment*)malloc(sizeof(tcp_segment));
  memset(new_tcp_seg, 0, sizeof(tcp_segment));
  Packet pkt (54);
  struct packet_info* sent_packet_info = (packet_info *)malloc(sizeof(packet_info));
  
  if (self_sock_info == NULL) {

  }
  if (self_sock_info->tcp_status == TCP_CLOSE) {
    // TCP_CLOSE
    ;
  } else if (self_sock_info->tcp_status == TCP_LISTEN || self_sock_info->tcp_status == TCP_SYN_RECV) {
    
    if (arrived_packet->SYN == 1 && arrived_packet->ACK != 1) {
      // TWH1_SYN
      if (self_sock_info->backlog <= self_sock_info->pending_num) {
        return;
      }
      new_tcp_seg->src_port = (arrived_packet->dst_addr.sin_port);
      new_tcp_seg->dst_port = (arrived_packet->src_addr.sin_port);
      new_tcp_seg->seq = convert_4byte(rand());
      new_tcp_seg->ack = convert_4byte(arrived_packet->seq + 1);
      new_tcp_seg->flags = (5 << 8); // Header length is 5 words
      new_tcp_seg->flags = (new_tcp_seg->flags + 1) << 3; // ACK is set
      new_tcp_seg->flags = (new_tcp_seg->flags + 1) << 1; // SYN is set
      new_tcp_seg->flags = convert_2byte(new_tcp_seg->flags);
      new_tcp_seg->rec_win = 200;
      new_tcp_seg->urg_pts = 0;
      arrived_packet->dst_addr.sin_addr.s_addr = (arrived_packet->dst_addr.sin_addr.s_addr);
      arrived_packet->src_addr.sin_addr.s_addr = (arrived_packet->src_addr.sin_addr.s_addr);
      new_tcp_seg->checksum = htons(~NetworkUtil::tcp_sum(arrived_packet->src_addr.sin_addr.s_addr, arrived_packet->dst_addr.sin_addr.s_addr, (uint8_t*)new_tcp_seg, 20));
      
      pkt.writeData(26, &arrived_packet->dst_addr.sin_addr.s_addr, 4);
      pkt.writeData(30, &arrived_packet->src_addr.sin_addr.s_addr, 4);
      pkt.writeData(34, new_tcp_seg, 20);

      self_sock_info->tcp_status = TCP_SYN_RECV;
      arrived_packet->seq_sent = convert_4byte(new_tcp_seg->seq);
      


      append_packet_info(self_sock_info->pending_list, arrived_packet);
      self_sock_info->pending_num++;
      printf("appending pending list... \tpending num: %d\n", self_sock_info->pending_num);

      free(new_tcp_seg);
      sendPacket("IPv4", pkt);

    } else if (arrived_packet->SYN != 1 && arrived_packet->ACK == 1) {
      // TWH3_ACK


      if (self_sock_info->pending_num == 0) {
        return;
      }
      self_sock_info->tcp_status = TCP_LISTEN;
      packet_info* sender_packet = pop_packet_info_by_addr(self_sock_info->pending_list, &arrived_packet->src_addr);
      if (sender_packet != NULL && sender_packet->seq_sent+1 != arrived_packet->ack) {
        return;
      }
      self_sock_info->pending_num--;
      append_packet_info(self_sock_info->established_list, arrived_packet);
      self_sock_info->established_num++;
      
      printf("appending establish list... \tpending_num: %d\testablished_num: %d\n", self_sock_info->pending_num, self_sock_info->established_num);
      
      // if blocked call exists
      if (self_sock_info->self_syscall->next != NULL) { 
        // unblock accept()
        if (self_sock_info->established_num != 0) {
          // pop from established list
          packet_info* sender_packet = self_sock_info->established_list->next;
          remove_packet_info(sender_packet);
          self_sock_info->established_num--;

          // create a new fd
          socket_info* new_sock_info = (socket_info*)malloc(sizeof(socket_info));
          memset(new_sock_info, 0, sizeof(socket_info));
          append_socket_info(all_sockets, new_sock_info);

          // initialize
          new_sock_info->fd = this->createFileDescriptor(self_sock_info->pid);
          new_sock_info->pid = self_sock_info->pid;
          new_sock_info->tcp_status = TCP_ESTABLISHED;
          new_sock_info->self_syscall = (syscall_entry *)malloc(sizeof(syscall_entry));
          memset(new_sock_info->self_syscall, 0, sizeof(syscall_entry));

          memcpy(&new_sock_info->host_addr, &self_sock_info->host_addr, sizeof(sockaddr_in));
          memcpy(&new_sock_info->peer_addr, &sender_packet->src_addr, sizeof(sockaddr_in));


          // return
          *(self_sock_info->self_syscall->sock_len_p) = sizeof(sockaddr_in);
          memcpy(self_sock_info->self_syscall->temp_sockaddr, &new_sock_info->peer_addr, sizeof(sockaddr_in));
          printf("return value fd: %d\n", new_sock_info->fd);
          this->returnSystemCall(self_sock_info->self_syscall->uuid, new_sock_info->fd);
          remove_syscall_entry(self_sock_info->self_syscall);
        }
      } else {
        // no blocked calls 
        ;
      }
    } else {
      // error
      return;
    }
  } else if (self_sock_info->tcp_status == TCP_SYN_SENT) {
    if (arrived_packet->SYN == 1 && arrived_packet->ACK == 1 ) {
      // TWH2_ACKSYN

      if (self_sock_info->self_syscall->next != NULL) {
        // unblock connect()

      // if (arrived_packet->ack != self_sock_info->self_syscall->seq+1) {
      //   returnSystemCall(self_sock_info->self_syscall->uuid, -1);
      // }

      // set tcp status
      self_sock_info->tcp_status = TCP_ESTABLISHED;

      // set new packet data
      new_tcp_seg->src_port = (arrived_packet->dst_addr.sin_port);
      new_tcp_seg->dst_port = (arrived_packet->src_addr.sin_port);
      new_tcp_seg->seq = convert_4byte(arrived_packet->ack);
      new_tcp_seg->ack = convert_4byte(arrived_packet->seq + 1);
      new_tcp_seg->flags = (5 << 8); // Header length is 5 words
      new_tcp_seg->flags = (new_tcp_seg->flags + 1) << 4; // ACK is set
      new_tcp_seg->flags = convert_2byte(new_tcp_seg->flags);
      new_tcp_seg->rec_win = 200;
      new_tcp_seg->urg_pts = 0;
      new_tcp_seg->checksum = htons(~NetworkUtil::tcp_sum(arrived_packet->src_addr.sin_addr.s_addr, arrived_packet->dst_addr.sin_addr.s_addr, (uint8_t*)new_tcp_seg, 20));
      
      pkt.writeData(26, &arrived_packet->dst_addr.sin_addr.s_addr, 4);
      pkt.writeData(30, &arrived_packet->src_addr.sin_addr.s_addr, 4);
      pkt.writeData(34, new_tcp_seg, 20);

      arrived_packet->seq_sent = convert_4byte(new_tcp_seg->seq);
      
      free(new_tcp_seg);
      sendPacket("IPv4", pkt);

      returnSystemCall(self_sock_info->self_syscall->uuid, 0);
      }
    } else {
     // error 
     ;
    }
  } else {
    // error
    ;
  }

}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
