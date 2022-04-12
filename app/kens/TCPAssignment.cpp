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

  struct socket_info* all_sockets;
  struct addr_entry* bound_addrs;
  struct syscall_entry* blocked_syscalls;

bool is_addr_used(sockaddr* addr) {
  sockaddr_in* addr_in = (sockaddr_in*)addr;
  bool arrived_packet = false;
  for(addr_entry* cur = bound_addrs->next; cur != bound_addrs; cur = cur->next) {

    // same addr and port
    if(!memcmp(&cur->addr, addr, sizeof(cur->addr))) {
      arrived_packet = true;
      break;
    }

    // INADDR_ANY && same port
    if((cur->addr.sin_addr.s_addr == INADDR_ANY || addr_in->sin_addr.s_addr == INADDR_ANY) &&
      cur->addr.sin_port == addr_in->sin_port) {
      arrived_packet = true;
      break;
    }
  }
  return arrived_packet;
} 

// get socket_info by HOST_NAME and FD from HEAD list
socket_info* get_socket_info_by_fd(socket_info* head, int fd) {
  for (socket_info* cur = head->next; cur != head; cur = cur->next) 
  {
    if (cur->fd == fd)
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
void append_pending_list(socket_info* listener, packet_info* waiter) {
  listener->pending_list->prev->next = waiter;
  waiter->prev = listener->pending_list->prev;
  waiter->next = listener->pending_list;
  listener->pending_list->prev = waiter;
}

// remove SOCK_INFO from the pending_list
void remove_pending_list(packet_info* pack_info) {
  pack_info->prev->next = pack_info->next;
  pack_info->next->prev = pack_info->prev;
}

void free_pending_list(packet_info* head) {
  packet_info* temp;
  for (packet_info* cur = head->next; cur != head; ) {
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
}

void TCPAssignment::finalize() {
  for (syscall_entry *cur_syscall = blocked_syscalls->next; cur_syscall != blocked_syscalls; cur_syscall = cur_syscall->next) {
    cur_syscall->prev->next = cur_syscall->next;
    cur_syscall->next->prev = cur_syscall->prev;
    cur_syscall->prev = NULL;
    cur_syscall->next = NULL;
    this->returnSystemCall(cur_syscall->uuid, -1);
  }
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  // Remove below
  // (void)syscallUUID;
  // (void)pid;

  socket_info* sock_info;
  tcp_segment* new_tcp_seg;

  packet_info* pending_pack_info;
  packet_info* new_pack_info;

  int fd;
  int backlog;
  sockaddr* temp_sockaddr;
  sockaddr_in* new_sockaddr;

  socklen_t sock_len;
  socklen_t* sock_len_p;

  addr_entry* temp_addr_entry;
  addr_entry* new_addr_entry;

  bool success = true;

  ipv4_t binding_ip;
  ipv4_t src_ip;
  ipv4_t dst_ip;

  Packet pkt (100);

  switch (param.syscallNumber) {
  case SOCKET:
    // this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    // int socket(int domain, int type__unused, int protocol)
    sock_info = (socket_info*)malloc(sizeof(socket_info));
    memset(sock_info, 0, sizeof(socket_info));
    sock_info->fd = this->createFileDescriptor(pid);
    sock_info->tcp_status = TCP_CLOSE;
    sock_info->sock_status = OPENED;

    append_socket_info(all_sockets, sock_info);

    sock_info->pending_list = (packet_info *)malloc(sizeof(packet_info));
    memset(sock_info->pending_list, 0, sizeof(packet_info));
    sock_info->pending_list->prev = sock_info->pending_list;
    sock_info->pending_list->next = sock_info->pending_list;


    this->returnSystemCall(syscallUUID, sock_info->fd);
    break;

  case CLOSE:
    // this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    // int close(int fd)
    
    fd = std::get<int>(param.params[0]);
    sock_info = get_socket_info_by_fd(all_sockets, fd);    
    temp_addr_entry = get_addr_entry_by_addr(bound_addrs, &sock_info->host_addr);
    this->removeFileDescriptor(pid, fd);

    // handle sock_info
    // if sock_info is null
    if (sock_info == NULL){
      success = false;
      this->returnSystemCall(syscallUUID, -1);
    } else {
      remove_socket_info(sock_info);
      free_pending_list(sock_info->pending_list);
      free(sock_info);
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

    // if client addr is vacant should bind 

    break;


  case LISTEN:
    // this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    // int listen(int sockfd, int backlog)

    fd = std::get<int>(param.params[0]);
    backlog = std::get<int>(param.params[1]);
    sock_info = get_socket_info_by_fd(all_sockets, fd);

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
    sock_info->sock_status = LISTENING;
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
    printf("accept 01\n");
    // not an existing fd
    sock_info = get_socket_info_by_fd(all_sockets, fd);
    if (sock_info == NULL) {
      printf("accept 02\n");
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    }
    
    // socket is not listening
    if (sock_info->sock_status != LISTENING) {
      printf("accept 03\n");
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    }

    *sock_len_p = sizeof(sockaddr_in);
    sock_info->sock_status = ACCEPTING;
    printf("accept 04\n");

    if (sock_info->pending_num == 0) {
      // if pending list is empty
      printf("accept 05\n");
      ;
    } else {
      // if pending list not empty
      pending_pack_info = sock_info->pending_list->next;
      memcpy(temp_sockaddr, &pending_pack_info->src_addr, sizeof(temp_sockaddr));
      printf("accept 06\n");
      // prepare tcp_segment
      new_tcp_seg = (tcp_segment*)malloc(sizeof(tcp_segment));
      memset(new_tcp_seg, 0, sizeof(tcp_segment));
      printf("accept 07\n");
      new_tcp_seg->src_port = pending_pack_info->dst_addr.sin_port;
      new_tcp_seg->dst_port = pending_pack_info->src_addr.sin_port;
      new_tcp_seg->seq = rand();
      new_tcp_seg->ack = pending_pack_info->seq + 1;
      new_tcp_seg->flags = (5 << 7); // Header length is 5 words
      new_tcp_seg->flags = (new_tcp_seg->flags + 1) << 2; // URG is set
      new_tcp_seg->flags = (new_tcp_seg->flags + 1) << 2; // PSH is set
      new_tcp_seg->flags = (new_tcp_seg->flags + 1) << 1; // SYN is set
      printf("accept 08\n");
      // POSSIBLE ERROR: rec_win not handled
      new_tcp_seg->rec_win = 0;
      new_tcp_seg->checksum = NetworkUtil::tcp_sum(
        pending_pack_info->dst_addr.sin_addr.s_addr, 
        pending_pack_info->src_addr.sin_addr.s_addr, (uint8_t *)new_tcp_seg, sizeof(new_tcp_seg));
      new_tcp_seg->urg_pts = 0;
      printf("accept 09\n");
      // write and send packet 
      Packet pkt (100);
      pkt.writeData(34, new_tcp_seg, 20);
      sendPacket("IPv4", pkt);

      sock_info->tcp_status = TCP_SYN_RECV;
      printf("accept 10\n");
    }
    
    printf("accept() ended\n");

    break;

  case BIND:
    // this->syscall_bind(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
    // int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
    fd = std::get<int>(param.params[0]);
    sock_info = get_socket_info_by_fd(all_sockets, fd);
    
    // if sock_info pointer is null 
    if (sock_info == NULL) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    } else if (sock_info->sock_status != OPENED) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    }
    
    sock_len = (socklen_t)std::get<int>(param.params[2]);
    new_addr_entry = (addr_entry *)malloc(sizeof(addr_entry));

    // host_addr bind
    memcpy(&sock_info->host_addr, (sockaddr_in*)std::get<void *>(param.params[1]), (size_t)min(sock_len, (socklen_t)sizeof(sockaddr_in)));
    // if is already bound 
    if (is_addr_used((sockaddr *)&sock_info->host_addr)) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    } else {
      // append bound addrs list
      memcpy(&new_addr_entry->addr, &sock_info->host_addr, sizeof(sockaddr_in));
      // binding_ip = NetworkUtil::UINT64ToArray<4>(sock_info->host_addr.sin_addr.s_addr);
      // setIPAddr(binding_ip, sock_info->host_addr.sin_port);
      append_addr_entry(bound_addrs, new_addr_entry);
    }

    sock_info->sock_status = BOUND;
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
    printf("getsockname() started\n");
    fd = std::get<int>(param.params[0]);
    sock_info = get_socket_info_by_fd(all_sockets, fd);
    temp_sockaddr = static_cast<struct sockaddr *>(std::get<void *>(param.params[1]));
    sock_len_p = static_cast<socklen_t *>(std::get<void *>(param.params[2]));
    
    memcpy(temp_sockaddr, &sock_info->host_addr, min(*sock_len_p, sizeof(sockaddr_in)));
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

  tcp_segment arrived_tcp_seg;
  ipv4_t src_ip;
  ipv4_t dst_ip;

  // read as arrived_tcp_seg and store in arrived_packet
  packet.readData(34, &arrived_tcp_seg, sizeof(tcp_segment));
  packet_info* arrived_packet = (packet_info*)malloc(sizeof(packet_info));
  memset(arrived_packet, 0, sizeof(arrived_packet));

  // src_addr
  arrived_packet->src_addr.sin_family=AF_INET;
  arrived_packet->src_addr.sin_port=arrived_tcp_seg.src_port;
  
  if (getIPAddr(arrived_tcp_seg.src_port).has_value()) {
    src_ip = getIPAddr(arrived_tcp_seg.src_port).value();
  }
  
  arrived_packet->src_addr.sin_addr.s_addr = NetworkUtil::arrayToUINT64<4>(src_ip);
 
  // dst_addr
  arrived_packet->dst_addr.sin_family=AF_INET;
  arrived_packet->dst_addr.sin_port=arrived_tcp_seg.dst_port;
  
  if (getIPAddr(arrived_tcp_seg.dst_port).has_value()) {
    dst_ip = getIPAddr(arrived_tcp_seg.dst_port).value();
  }
  
  arrived_packet->dst_addr.sin_addr.s_addr = NetworkUtil::arrayToUINT64<4>(dst_ip);

  arrived_packet->seq = arrived_tcp_seg.seq;
  arrived_packet->ack = arrived_tcp_seg.ack;
  arrived_packet->SYN = arrived_tcp_seg.flags << 14 >> 15;
  arrived_packet->FIN = arrived_tcp_seg.flags << 15 >> 15;
  arrived_packet->checksum = arrived_tcp_seg.checksum;
  arrived_packet->prev = NULL;
  arrived_packet->next = NULL;    

  printf("packet arrived\n");

  socket_info* self_sock_info = get_socket_info_by_addr(all_sockets, &arrived_packet->dst_addr);
  printf("%d\n", self_sock_info->fd);
  
  // handle cases
  if (arrived_packet->SYN == 1) {
    if (arrived_packet->ack != 0) {
      // pac1_syn
    } else {
      // pac2_syn+ack
    }
  } else if (arrived_packet->SYN == 0) {
    // pac3_ack
  } else {
    // error 
    
  }

// should free arrived_packet

}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
