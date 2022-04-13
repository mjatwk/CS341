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

// get socket_info by FD from HEAD list
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
      (cur->host_addr.sin_addr.s_addr == INADDR_ANY || 
        addr->sin_addr.s_addr == INADDR_ANY))
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


uint16_t convert_2byte(uint16_t ori) {
  return (ori << 8) | (ori >> 8);
}

uint32_t convert_4byte(uint32_t ori) {
  return ((ori << 24)&0xFF000000) | ((ori << 8)&0x00FF0000) | ((ori >> 8)&0x0000FF00) | ((ori >> 24)&0x000000FF);
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
    this->returnSystemCall(cur_syscall->uuid, -1);
  }
  free(blocked_syscalls);
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

  syscall_entry* temp_syscall;

  bool success = true;

  ipv4_t binding_ip;
  ipv4_t src_ip;
  ipv4_t dst_ip;

  Packet pkt (54);

  switch (param.syscallNumber) {
  case SOCKET:
    // this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    // int socket(int domain, int type__unused, int protocol)
    sock_info = (socket_info*)malloc(sizeof(socket_info));
    memset(sock_info, 0, sizeof(socket_info));
    sock_info->fd = this->createFileDescriptor(pid);
    sock_info->pid = pid;
    sock_info->tcp_status = TCP_CLOSE;
    sock_info->sock_status = OPENED;

    append_socket_info(all_sockets, sock_info);

    sock_info->pending_list = (packet_info *)malloc(sizeof(packet_info));
    memset(sock_info->pending_list, 0, sizeof(packet_info));
    sock_info->pending_list->prev = sock_info->pending_list;
    sock_info->pending_list->next = sock_info->pending_list;

    sock_info->self_syscall = (syscall_entry *)malloc(sizeof(syscall_entry));
    memset(sock_info->self_syscall, 0, sizeof(syscall_entry));

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
      remove_syscall_entry(sock_info->self_syscall);
      free(sock_info->self_syscall);
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


    // ERROR: not an existing fd
    sock_info = get_socket_info_by_fd(all_sockets, fd);
    if (sock_info == NULL) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    }
    
    // ERROR: listen() not called before
    if (sock_info->tcp_status != TCP_LISTEN) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    }

    *sock_len_p = sizeof(sockaddr_in);

    // init self_syscall
    sock_info->self_syscall->uuid = syscallUUID;
    sock_info->self_syscall->self_socket = sock_info;
    sock_info->self_syscall->temp_sockaddr = temp_sockaddr;

    // append to blocked_syscalls
    append_syscall_entry(blocked_syscalls, sock_info->self_syscall);
    printf("%d\n", sock_info->pending_num);
    if (sock_info->pending_num == 0) {
      // if pending list is empty
      sock_info->self_syscall->new_fd = -1;
      sock_info->sock_status = ACCEPTING;
    } else {
      // if pending list not empty

      sock_info->self_syscall->new_fd = this->createFileDescriptor(pid);

      pending_pack_info = sock_info->pending_list->next;
      remove_pending_list(pending_pack_info);
      sock_info->pending_num--;

      // printf("accept 06-1: %d\n", ((sockaddr_in*)temp_sockaddr)->sin_port);
      // prepare tcp_segment
      new_tcp_seg = (tcp_segment*)malloc(sizeof(tcp_segment));
      memset(new_tcp_seg, 0, sizeof(tcp_segment));
      new_tcp_seg->src_port = convert_2byte(pending_pack_info->dst_addr.sin_port);
      new_tcp_seg->dst_port = convert_2byte(pending_pack_info->src_addr.sin_port);
      new_tcp_seg->seq = rand();
      new_tcp_seg->seq = convert_4byte(new_tcp_seg->seq);
      // new_tcp_seg->seq = rand();
      new_tcp_seg->ack = convert_4byte(pending_pack_info->seq + 1);
      new_tcp_seg->flags = (5 << 8); // Header length is 5 words
      new_tcp_seg->flags = (new_tcp_seg->flags + 1) << 3; // ACK is set
      new_tcp_seg->flags = (new_tcp_seg->flags + 1) << 1; // SYN is set
      new_tcp_seg->flags = convert_2byte(new_tcp_seg->flags);
      new_tcp_seg->rec_win = 200;
      // new_tcp_seg->rec_win = convert_2byte(new_tcp_seg->rec_win);
      new_tcp_seg->urg_pts = 0;
      pending_pack_info->dst_addr.sin_addr.s_addr = convert_4byte(pending_pack_info->dst_addr.sin_addr.s_addr);
      pending_pack_info->src_addr.sin_addr.s_addr = convert_4byte(pending_pack_info->src_addr.sin_addr.s_addr);
      new_tcp_seg->checksum = htons(~NetworkUtil::tcp_sum(pending_pack_info->src_addr.sin_addr.s_addr, pending_pack_info->dst_addr.sin_addr.s_addr, (uint8_t*)new_tcp_seg, 20));

      pkt.writeData(26, &pending_pack_info->dst_addr.sin_addr.s_addr, 4);
      pkt.writeData(30, &pending_pack_info->src_addr.sin_addr.s_addr, 4);
      pkt.writeData(34, new_tcp_seg, 20);

      sock_info->tcp_status = TCP_SYN_RECV;
      sock_info->self_syscall->sent_packet = pending_pack_info;


      // // make new socket
      // temp_syscall->new_fd = this->createFileDescriptor(pid);
      // sock_info = (socket_info*)malloc(sizeof(socket_info));
      // memset(sock_info, 0, sizeof(socket_info));
      // sock_info->fd = temp_syscall->new_fd;
      // sock_info->tcp_status = TCP_CLOSE;
      // sock_info->sock_status = OPENED;

      // append_socket_info(all_sockets, sock_info);

      // sock_info->pending_list = (packet_info *)malloc(sizeof(packet_info));
      // memset(sock_info->pending_list, 0, sizeof(packet_info));
      // sock_info->pending_list->prev = sock_info->pending_list;
      // sock_info->pending_list->next = sock_info->pending_list;

      free(new_tcp_seg);
      sendPacket("IPv4", pkt);
    }

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
    break;
  case GETSOCKNAME:
    // this->syscall_getsockname(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    // int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
    fd = std::get<int>(param.params[0]);
    sock_info = get_socket_info_by_fd(all_sockets, fd);
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

  arrived_tcp_seg.src_port = convert_2byte(arrived_tcp_seg.src_port);
  arrived_tcp_seg.dst_port = convert_2byte(arrived_tcp_seg.dst_port);
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
  arrived_packet->src_addr.sin_port=arrived_tcp_seg.src_port;
  packet.readData(26, &addr, 4);
  arrived_packet->src_addr.sin_addr.s_addr = convert_4byte(addr);

  // dst_addr
  arrived_packet->dst_addr.sin_family=AF_INET;
  arrived_packet->dst_addr.sin_port=arrived_tcp_seg.dst_port;
  packet.readData(30, &addr, 4);
  arrived_packet->dst_addr.sin_addr.s_addr = convert_4byte(addr);

  socket_info* self_sock_info = get_socket_info_by_addr(all_sockets, &arrived_packet->dst_addr);
  
  arrived_packet->seq = arrived_tcp_seg.seq;
  arrived_packet->ack = arrived_tcp_seg.ack;
  arrived_packet->SYN = !!(arrived_tcp_seg.flags & 0x0002);
  arrived_packet->FIN = !!(arrived_tcp_seg.flags & 0x0001);
  arrived_packet->checksum = arrived_tcp_seg.checksum;
  arrived_packet->prev = NULL;
  arrived_packet->next = NULL;    

  Packet pack = packet;
  if (self_sock_info == NULL) {
    return;
  }
  
  // handle cases
  if (arrived_packet->SYN == 1) {
    if (arrived_packet->ack == 0) {
      if (self_sock_info->sock_status == LISTENING || self_sock_info->sock_status == ACCEPTING) {
        // connect() after listen()
        if (self_sock_info->pending_num >= self_sock_info->backlog) {
          // over backlog, cancel automatically
          return;
        } else {
          // pend properly
          append_pending_list(self_sock_info, arrived_packet);
          self_sock_info->pending_num++;
        }
      } else if (self_sock_info->sock_status == ACCEPTING) {
        // accept with vacant pending list

        self_sock_info->self_syscall->new_fd = this->createFileDescriptor(self_sock_info->pid);

        // printf("accept 06-1: %d\n", ((sockaddr_in*)temp_sockaddr)->sin_port);
        // prepare tcp_segment
        struct tcp_segment* new_tcp_seg = (tcp_segment*)malloc(sizeof(tcp_segment));
        memset(new_tcp_seg, 0, sizeof(tcp_segment));
        new_tcp_seg->src_port = convert_2byte(arrived_packet->dst_addr.sin_port);
        new_tcp_seg->dst_port = convert_2byte(arrived_packet->src_addr.sin_port);
        new_tcp_seg->seq = rand();
        new_tcp_seg->seq = convert_4byte(new_tcp_seg->seq);
        // new_tcp_seg->seq = rand();
        new_tcp_seg->ack = convert_4byte(arrived_packet->seq + 1);
        new_tcp_seg->flags = (5 << 8); // Header length is 5 words
        new_tcp_seg->flags = (new_tcp_seg->flags + 1) << 3; // ACK is set
        new_tcp_seg->flags = (new_tcp_seg->flags + 1) << 1; // SYN is set
        new_tcp_seg->flags = convert_2byte(new_tcp_seg->flags);
        new_tcp_seg->rec_win = 200;
        // new_tcp_seg->rec_win = convert_2byte(new_tcp_seg->rec_win);
        new_tcp_seg->urg_pts = 0;
        arrived_packet->dst_addr.sin_addr.s_addr = convert_4byte(arrived_packet->dst_addr.sin_addr.s_addr);
        arrived_packet->src_addr.sin_addr.s_addr = convert_4byte(arrived_packet->src_addr.sin_addr.s_addr);
        new_tcp_seg->checksum = htons(~NetworkUtil::tcp_sum(arrived_packet->src_addr.sin_addr.s_addr, arrived_packet->dst_addr.sin_addr.s_addr, (uint8_t*)new_tcp_seg, 20));

        Packet pkt (54);
        pkt.writeData(26, &arrived_packet->dst_addr.sin_addr.s_addr, 4);
        pkt.writeData(30, &arrived_packet->src_addr.sin_addr.s_addr, 4);
        pkt.writeData(34, new_tcp_seg, 20);

        self_sock_info->tcp_status = TCP_SYN_RECV;
        self_sock_info->self_syscall->sent_packet = arrived_packet;
        free(new_tcp_seg);
        
        sendPacket("IPv4", pkt);
        
      } else {
        // error
        return;
      }
    } else {
      // pac2_syn+ack
    }
  } else if(arrived_packet->SYN == 0) {
    // pac3_ack
    int new_fd = self_sock_info->self_syscall->new_fd;
    // if (arrived_packet->ack != self_sock_info->self_syscall->sent_packet->seq + 1) {
    //   returnSystemCall(self_sock_info->self_syscall->uuid, -1);
    //   return;
    // } else if (arrived_packet->seq != self_sock_info->self_syscall->sent_packet->ack) {
    //   returnSystemCall(self_sock_info->self_syscall->uuid, -1);
    //   return;
    // }

    if (new_fd > 0) {
      socket_info *new_sock_info = (socket_info*)malloc(sizeof(socket_info));
    memset(new_sock_info, 0, sizeof(socket_info));

    new_sock_info->fd = new_fd;
    new_sock_info->pid = self_sock_info->pid;
    new_sock_info->host_addr = self_sock_info->host_addr;
    new_sock_info->peer_addr = arrived_packet->src_addr;
    new_sock_info->tcp_status = TCP_ESTABLISHED;
    new_sock_info->sock_status = CONNECTED;
    append_socket_info(all_sockets, new_sock_info);
    new_sock_info->pending_list = (packet_info *)malloc(sizeof(packet_info));
    memset(new_sock_info->pending_list, 0, sizeof(packet_info));

    new_sock_info->pending_list->prev = new_sock_info->pending_list;
    new_sock_info->pending_list->next = new_sock_info->pending_list;

    memcpy(self_sock_info->self_syscall->temp_sockaddr, &arrived_packet->src_addr, sizeof(sockaddr_in));

    // remove from blocked_syscalls
    remove_syscall_entry(self_sock_info->self_syscall);
    self_sock_info->sock_status = LISTENING;
    self_sock_info->tcp_status = TCP_LISTEN;
    
    printf("return down here: %d\n", new_fd);
    this->returnSystemCall(self_sock_info->self_syscall->uuid, new_fd); 
    }   
    
  }

// should free arrived_packet

}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

} // namespace E
