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

struct socket_info *all_sockets;
struct addr_entry *bound_addrs;
struct syscall_entry *blocked_syscalls;

uint16_t convert_2byte(uint16_t ori) { return (ori << 8) | (ori >> 8); }

uint32_t convert_4byte(uint32_t ori) {
  return ((ori << 24) & 0xFF000000) | ((ori << 8) & 0x00FF0000) |
         ((ori >> 8) & 0x0000FF00) | ((ori >> 24) & 0x000000FF);
}

bool is_bound(int pid, int fd, sockaddr *addr) {
  sockaddr_in *addr_in = (sockaddr_in *)addr;
  bool bound = false;
  for (addr_entry *cur = bound_addrs->next; cur != bound_addrs;
       cur = cur->next) {
    // same fd
    if (cur->fd == fd && cur->pid == pid) {
      bound = true;
      break;
    }
    // same addr and port
    if (!memcmp(&cur->addr, addr, sizeof(cur->addr))) {
      bound = true;
      break;
    }
    // INADDR_ANY && same port
    if ((cur->addr.sin_addr.s_addr == INADDR_ANY ||
         addr_in->sin_addr.s_addr == INADDR_ANY) &&
        cur->addr.sin_port == addr_in->sin_port) {
      bound = true;
      break;
    }
  }
  return bound;
}

// get socket_info by FD from HEAD list
socket_info *get_socket_info_by_fd(socket_info *head, int pid, int fd) {
  for (socket_info *cur = head->next; cur != head; cur = cur->next) {
    if (cur->fd == fd && cur->pid == pid) {
      return cur;
    }
  }
  return NULL;
}

// get socket_info by ADDR from HEAD list
socket_info *get_socket_info_by_addr(socket_info *head, sockaddr_in *addr) {
  for (socket_info *cur = head->next; cur != head; cur = cur->next) {
    if ((cur->host_addr.sin_addr.s_addr == (addr->sin_addr.s_addr) &&
         cur->host_addr.sin_port == (addr->sin_port)) ||
        (cur->host_addr.sin_addr.s_addr == INADDR_ANY ||
         addr->sin_addr.s_addr == INADDR_ANY)) {
      return cur;
    }
  }
  return NULL;
}

// get socket_info by HOST, PEER from HEAD list
socket_info *get_socket_info_by_host_and_peer(socket_info *head, sockaddr_in *host, sockaddr_in *peer) {
  
  for (socket_info *cur = head->next; cur != head; cur = cur->next) {
    if ((cur->host_addr.sin_addr.s_addr == (host->sin_addr.s_addr) &&
         cur->host_addr.sin_port == (host->sin_port)) ||
        (cur->host_addr.sin_addr.s_addr == INADDR_ANY ||
         host->sin_addr.s_addr == INADDR_ANY)) {
      if (peer == NULL) {
        if (cur->tcp_status == TCP_LISTEN || cur->tcp_status == TCP_SYN_RECV)
          return cur;
      }
      if ((cur->peer_addr.sin_addr.s_addr == (peer->sin_addr.s_addr) &&
         cur->peer_addr.sin_port == (peer->sin_port)) ||
        (cur->peer_addr.sin_addr.s_addr == INADDR_ANY ||
         peer->sin_addr.s_addr == INADDR_ANY)) {
        if (peer != NULL) {
          if (cur->tcp_status == TCP_LISTEN || cur->tcp_status == TCP_SYN_RECV)
            continue;
        }
        return cur;
      }
    }
  }
  return NULL;
}

// get socket_info by HOST_ADDR from HEAD list
packet_info *pop_packet_info_by_addr(packet_info *head, sockaddr_in *addr) {
  for (packet_info *cur = head->next; cur != head; cur = cur->next) {
    if (cur->src_addr.sin_addr.s_addr == addr->sin_addr.s_addr ||
        (cur->src_addr.sin_addr.s_addr == INADDR_ANY ||
         addr->sin_addr.s_addr == INADDR_ANY)) {
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
addr_entry *get_addr_entry_by_addr(addr_entry *head, sockaddr_in *addr) {
  for (addr_entry *cur = head->next; cur != head; cur = cur->next) {
    if (!memcmp(&cur->addr, addr, sizeof(sockaddr_in)) ||
        ((cur->addr.sin_addr.s_addr == INADDR_ANY ||
          addr->sin_addr.s_addr == INADDR_ANY) &&
         cur->addr.sin_port == addr->sin_port)) {
      return cur;
    }
  }
  return NULL;
}

// append ADDR to the linked list starting with HEAD
void append_addr_entry(addr_entry *head, addr_entry *addr) {
  head->prev->next = addr;
  addr->prev = head->prev;
  addr->next = head;
  head->prev = addr;
}

// remove ADDR from the linked list
void remove_addr_entry(addr_entry *addr) {
  addr->prev->next = addr->next;
  addr->next->prev = addr->prev;
}

// append SOCK_INFO to the linked list starting with HEAD
void append_socket_info(socket_info *head, socket_info *sock_info) {
  head->prev->next = sock_info;
  sock_info->prev = head->prev;
  sock_info->next = head;
  head->prev = sock_info;
}

// remove SOCK_INFO from the linked list
void remove_socket_info(socket_info *sock_info) {
  sock_info->prev->next = sock_info->next;
  sock_info->next->prev = sock_info->prev;
}

// append WAITER to the LISTENER's pending list
void append_packet_info(packet_info *head, packet_info *waiter) {
  head->prev->next = waiter;
  waiter->prev = head->prev;
  waiter->next = head;
  head->prev = waiter;
}

// remove SOCK_INFO from pending_list or established_list
void remove_packet_info(packet_info *pack_info) {
  pack_info->prev->next = pack_info->next;
  pack_info->next->prev = pack_info->prev;
  pack_info->prev = NULL;
  pack_info->next = NULL;
}

// free all packet_info in packet_list HEAD
void free_packet_list(packet_info *head) {
  packet_info *temp;
  for (packet_info *cur = head->next; cur != head;) {
    temp = cur->next;

    free(cur);
    cur = temp;
  }

  free(head);
}

// append SOCK_INFO to the linked list starting with HEAD
void append_syscall_entry(syscall_entry *head, syscall_entry *syscall) {
  head->prev->next = syscall;
  syscall->prev = head->prev;
  syscall->next = head;
  head->prev = syscall;
}

// remove SOCK_INFO from the linked list
void remove_syscall_entry(syscall_entry *syscall) {
  syscall->prev->next = syscall->next;
  syscall->next->prev = syscall->prev;
}

void free_blocked_list(syscall_entry *head) {
  syscall_entry *temp;
  for (syscall_entry *cur = head->next; cur != head;) {
    temp = cur->next;

    free(cur);
    cur = temp;
  }

  free(head);
}

// return new tcp_segment with SRC_ADDR, DST_ADDR, 'SYN', 'ACK', SEQ, ACK
struct tcp_segment *get_new_tcp_seg(sockaddr_in src_addr, sockaddr_in dst_addr,
                                    bool SYN, bool ACK, int seq, int ack) {
  struct tcp_segment *new_tcp_seg = (tcp_segment *)malloc(sizeof(tcp_segment));
  memset(new_tcp_seg, 0, sizeof(tcp_segment));

  new_tcp_seg->src_port = (src_addr.sin_port);
  new_tcp_seg->dst_port = (dst_addr.sin_port);
  new_tcp_seg->seq = convert_4byte(seq);
  new_tcp_seg->ack = convert_4byte(ack);

  if (ACK) {
    new_tcp_seg->flags = (5 << 8); // Header length is 5 words
    new_tcp_seg->flags = (new_tcp_seg->flags + 1) << 3; // ACK is set
  } else {
    new_tcp_seg->flags = (5 << 11); // Header length is 5 words
  }

  if (SYN) {
    new_tcp_seg->flags = (new_tcp_seg->flags + 1) << 1; // SYN is set
  } else {
    new_tcp_seg->flags = (new_tcp_seg->flags) << 1;
  }

  new_tcp_seg->flags = convert_2byte(new_tcp_seg->flags);
  new_tcp_seg->rec_win = 200;
  new_tcp_seg->urg_pts = 0;
  new_tcp_seg->checksum = htons(
      ~NetworkUtil::tcp_sum(src_addr.sin_addr.s_addr, dst_addr.sin_addr.s_addr,
                            (uint8_t *)new_tcp_seg, 20));

  return new_tcp_seg;
}

struct packet_info *tcp_seg_to_pkt_info(struct tcp_segment arrived_tcp_seg,
                                        int32_t src_addr, int32_t dst_addr) {
  packet_info *arrived_packet = (packet_info *)malloc(sizeof(packet_info));
  memset(arrived_packet, 0, sizeof(arrived_packet));

  // arrived_tcp_seg.src_port = convert_2byte(arrived_tcp_seg.src_port);
  // arrived_tcp_seg.dst_port = convert_2byte(arrived_tcp_seg.dst_port);
  arrived_tcp_seg.seq = convert_4byte(arrived_tcp_seg.seq);
  arrived_tcp_seg.ack = convert_4byte(arrived_tcp_seg.ack);
  arrived_tcp_seg.flags = convert_2byte(arrived_tcp_seg.flags);
  arrived_tcp_seg.rec_win = convert_2byte(arrived_tcp_seg.rec_win);
  arrived_tcp_seg.checksum = convert_2byte(arrived_tcp_seg.checksum);
  arrived_tcp_seg.urg_pts = convert_2byte(arrived_tcp_seg.urg_pts);

  // src_addr
  arrived_packet->src_addr.sin_family = AF_INET;
  arrived_packet->src_addr.sin_port = (arrived_tcp_seg.src_port);
  arrived_packet->src_addr.sin_addr.s_addr = (src_addr);

  // dst_addr
  arrived_packet->dst_addr.sin_family = AF_INET;
  arrived_packet->dst_addr.sin_port = (arrived_tcp_seg.dst_port);
  arrived_packet->dst_addr.sin_addr.s_addr = (dst_addr);

  arrived_packet->SYN = !!(arrived_tcp_seg.flags & 0x0002);
  arrived_packet->ACK = !!(arrived_tcp_seg.flags & 0x0010);
  arrived_packet->FIN = !!(arrived_tcp_seg.flags & 0x0001);

  arrived_packet->seq = arrived_tcp_seg.seq;
  arrived_packet->ack = arrived_tcp_seg.ack;
  arrived_packet->rec_win = arrived_tcp_seg.rec_win;

  arrived_packet->checksum = arrived_tcp_seg.checksum;
  arrived_packet->prev = NULL;
  arrived_packet->next = NULL;

  return arrived_packet;
}

// update snd_window_remaining and snd_count_remaining in SOCK_INFO
void update_remaining(struct socket_info *sock_info) {

  int window_consumed = sock_info->snd_packet - sock_info->snd_base;
  if (window_consumed < 0)
    window_consumed = window_consumed + BUF_SIZE;

  // sock_info->snd_window_remaining =
  //     sock_info->snd_base + sock_info->snd_window - sock_info->snd_packet;
  // sock_info->snd_window_remaining =
  //     sock_info->snd_window_remaining >= BUF_SIZE
  //         ? sock_info->snd_window_remaining - BUF_SIZE
  //         : sock_info->snd_window_remaining;

  sock_info->snd_window_remaining = sock_info->snd_window - window_consumed;
  sock_info->snd_count_remaining =
      sock_info->snd_next - sock_info->snd_packet < 0
          ? sock_info->snd_next - sock_info->snd_packet + BUF_SIZE
          : sock_info->snd_next - sock_info->snd_packet;
}

// update snd_empty_size in SOCK_INFO
void update_empty_size(struct socket_info *sock_info) {
  sock_info->snd_empty_size = (sock_info->snd_next - sock_info->snd_base) > 0 ?
      BUF_SIZE - (sock_info->snd_next - sock_info->snd_base) :
      -(sock_info->snd_next - sock_info->snd_base);
}

// prepare both snd and rcv buffers of NEW_SOCK_INFO,
// while snd_window info is from ARRIVED_PACKET
void prepare_buffer(struct socket_info *new_sock_info,
                    struct packet_info *arrived_packet) {
  // prepare send buffer
  new_sock_info->snd_buffer = (int8_t *)malloc(BUF_REAL_SIZE);
  memset(new_sock_info->snd_buffer, 0, BUF_REAL_SIZE);
  new_sock_info->snd_base = new_sock_info->snd_buffer;
  new_sock_info->snd_next = new_sock_info->snd_buffer;
  new_sock_info->snd_packet = new_sock_info->snd_buffer;
  new_sock_info->snd_empty_size = BUF_SIZE;
  new_sock_info->snd_count_remaining = 0;
  new_sock_info->snd_window = arrived_packet->rec_win;
  new_sock_info->snd_window_remaining = new_sock_info->snd_window;
  new_sock_info->sent_packets =
      (struct packet_elem *)malloc(sizeof(struct packet_elem));
  new_sock_info->sent_packets->prev = new_sock_info->sent_packets;
  new_sock_info->sent_packets->next = new_sock_info->sent_packets;

  // prepare rcv_buffer
  new_sock_info->rcv_buffer = (int8_t *)malloc(BUF_REAL_SIZE);
  memset(new_sock_info->rcv_buffer, 0, BUF_REAL_SIZE);
  new_sock_info->rcv_base = new_sock_info->rcv_buffer;
  new_sock_info->rcv_next = new_sock_info->rcv_buffer;
  new_sock_info->rcv_window = BUF_SIZE;
}

// send all available packets in the send_buffer of SOCK_INFO
struct Packet send_snd_packets(struct socket_info *sock_info) {
  // do-while
  int packet_length;
  int8_t *packet_buf;
  int8_t *temp;
  tcp_segment *new_tcp_seg;

  in_addr_t host_ip;
  in_addr_t peer_ip;

  int n;
  Packet pkt(1500);

  // count adjusted to not overflow prev step
  // printf("[send_snd_packets 1]\n");
  packet_length =
      min(min(sock_info->snd_count_remaining, sock_info->snd_window_remaining),
          PKT_DATA_LEN);
  packet_buf = (int8_t *)malloc(packet_length);
  n = 0;
  // printf("[send_snd_packets 2] packet length is %d\n", packet_length);
  if (sock_info->snd_packet + packet_length >=
      sock_info->snd_buffer + BUF_SIZE) {
    // if divided within the packet
    n = sock_info->snd_buffer + BUF_SIZE - sock_info->snd_packet;
    memcpy(packet_buf, sock_info->snd_packet, n);
    sock_info->snd_packet = sock_info->snd_buffer;
  }
  memcpy(packet_buf, sock_info->snd_packet, packet_length - n);
  // printf("[send_snd_packets]\n");

  // send packet
  pkt.setSize(54 + packet_length);
  temp = (int8_t *)malloc(54 + packet_length);
  new_tcp_seg =
      get_new_tcp_seg(sock_info->host_addr, sock_info->peer_addr, false, true,
                      sock_info->next_seq, sock_info->waiting_seq);
  new_tcp_seg->checksum = 0;
  host_ip = (sock_info->host_addr.sin_addr.s_addr);
  peer_ip = (sock_info->peer_addr.sin_addr.s_addr);

  memcpy(temp, new_tcp_seg, 20);
  memcpy(temp + 20, packet_buf, packet_length);
  new_tcp_seg->checksum = htons(~NetworkUtil::tcp_sum(
      host_ip, peer_ip, (uint8_t *)temp, 20 + packet_length));
  free(temp);
  pkt.writeData(26, &host_ip, 4);
  pkt.writeData(30, &peer_ip, 4);
  pkt.writeData(34, new_tcp_seg, 20);
  pkt.writeData(54, packet_buf, packet_length);
  // append sent_packet_elem at the end of the list
  struct packet_elem *sent_packet_elem =
      (struct packet_elem *)malloc(sizeof(struct packet_elem));
  sent_packet_elem->ack = sock_info->next_seq;
  sent_packet_elem->data_size = packet_length;
  sent_packet_elem->packet = &pkt;

  sent_packet_elem->next = sock_info->sent_packets;
  sent_packet_elem->prev = sock_info->sent_packets->prev;
  sock_info->sent_packets->prev->next = sent_packet_elem;
  sock_info->sent_packets->prev = sent_packet_elem;
  // update status
  sock_info->next_seq += packet_length;
  sock_info->snd_packet += packet_length;
  update_remaining(sock_info);
  free(packet_buf);

  return pkt;
}

int read_data(int8_t* dest, socket_info* sock_info, int count) {
        
  int remaining_data = sock_info->rcv_next - sock_info->rcv_base;
  if (remaining_data < 0)
    remaining_data += BUF_SIZE;
  
  int read_byte = min(remaining_data, count);
  int read_first = 0;
  
  int8_t *rcv_end = (sock_info->rcv_buffer + BUF_SIZE);

  if (sock_info->rcv_base + read_byte >= rcv_end) {
    // buffer overflow
    read_first = rcv_end - sock_info->rcv_base;
    memcpy(dest, sock_info->rcv_base, read_first);
    sock_info->rcv_base = sock_info->rcv_buffer;
    sock_info->rcv_window += read_first;
    read_byte -= read_first;
  }
  
  memcpy(dest + read_first, sock_info->rcv_base, read_byte);
  sock_info->rcv_base += read_byte;
  sock_info->rcv_window += read_byte;

  return read_first + read_byte;
}

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {
  all_sockets = (socket_info *)malloc(sizeof(socket_info));
  all_sockets->next = all_sockets;
  all_sockets->prev = all_sockets;

  bound_addrs = (addr_entry *)malloc(sizeof(addr_entry));
  bound_addrs->next = bound_addrs;
  bound_addrs->prev = bound_addrs;

  blocked_syscalls = (syscall_entry *)malloc(sizeof(syscall_entry));
  blocked_syscalls->next = blocked_syscalls;
  blocked_syscalls->prev = blocked_syscalls;
}

void TCPAssignment::finalize() {
  for (syscall_entry *cur_syscall = blocked_syscalls->next;
       cur_syscall != blocked_syscalls; cur_syscall = cur_syscall->next) {
    this->returnSystemCall(cur_syscall->uuid, -1);
  }

  free_blocked_list(blocked_syscalls);
  // TODO: free
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {
  socket_info *sock_info;
  socket_info *new_sock_info;
  tcp_segment *new_tcp_seg;

  packet_info *established_pack_info;
  packet_info *new_pack_info;

  int fd;
  int backlog;

  sockaddr *temp_sockaddr;
  in_addr_t host_ip;
  in_addr_t peer_ip;
  sockaddr_in *new_sockaddr;

  sockaddr_in vacant_sockaddr;
  memset(&vacant_sockaddr, 0, sizeof(vacant_sockaddr));
  sockaddr_in *search_sockaddr;
  in_port_t port;
  std::optional<E::ipv4_t> possible_ipv4_op;
  ipv4_t possible_ipv4;
  uint32_t possible_address;

  socklen_t sock_len;
  socklen_t *sock_len_p;

  addr_entry *temp_addr_entry;
  addr_entry *new_addr_entry;

  syscall_entry *temp_syscall;

  bool success = true;

  ipv4_t binding_ip;
  ipv4_t src_ip;
  ipv4_t dst_ip;

  Packet pkt(1500);

  packet_info *sent_packet_info;

  int count;
  int n;
  int8_t *buf;
  int8_t *temp;
  int8_t *packet_buf;
  int packet_length; // current packet length

  switch (param.syscallNumber) {
  case SOCKET:
    // this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    // int socket(int domain, int type__unused, int protocol)
    sock_info = (socket_info *)malloc(sizeof(socket_info));
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
    this->returnSystemCall(syscallUUID, sock_info->fd);
    break;

  case CLOSE:
    // this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    // int close(int fd)
    fd = std::get<int>(param.params[0]);
    sock_info = get_socket_info_by_fd(all_sockets, pid, fd);
    temp_addr_entry =
        get_addr_entry_by_addr(bound_addrs, &sock_info->host_addr);
    this->removeFileDescriptor(pid, fd);
    // handle sock_info
    // if sock_info is null
    if (sock_info == NULL) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
    } else {
      sock_info->tcp_status = TCP_FIN_WAIT1;
      sock_info->self_syscall->syscall_num = CLOSE;
      sock_info->self_syscall->uuid = syscallUUID;
      sock_info->self_syscall->self_socket = sock_info;
      append_syscall_entry(blocked_syscalls, sock_info->self_syscall);
      break;
      // free sent packets list
    }
    // handle addr_entry
    if (temp_addr_entry != NULL) {
      remove_addr_entry(temp_addr_entry);
      free(temp_addr_entry);
    }
    printf("close call ended\n");
    this->returnSystemCall(syscallUUID, 0);
    break;

  case READ:
    // this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
    //                    std::get<void *>(param.params[1]),
    //                    std::get<int>(param.params[2]));
    // int read(int fd, void *buf, size_t count)
    fd = std::get<int>(param.params[0]);
    sock_info = get_socket_info_by_fd(all_sockets, pid, fd);
    buf = (int8_t *)std::get<void *>(param.params[1]);
    count = std::get<int>(param.params[2]);

    if (sock_info == NULL)
      ;
    else if (sock_info->rcv_base == sock_info->rcv_next) {
      sock_info->self_syscall->syscall_num = READ;
      sock_info->self_syscall->uuid = syscallUUID;
      sock_info->self_syscall->self_socket = sock_info;
      sock_info->self_syscall->read_byte = count;
      sock_info->self_syscall->usr_buffer = buf;
      append_syscall_entry(blocked_syscalls, sock_info->self_syscall);
      break;
    }

    count = read_data(buf, sock_info, count);
    this->returnSystemCall(syscallUUID, count);

    break;

  case WRITE:
    // this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
    //                     std::get<void *>(param.params[1]),
    //                     std::get<int>(param.params[2]));
    // int write(int fd, const void *buf, size_t count
    fd = std::get<int>(param.params[0]);
    sock_info = get_socket_info_by_fd(all_sockets, pid, fd);
    buf = (int8_t *)std::get<void *>(param.params[1]);
    count = std::get<int>(param.params[2]);

    if (sock_info->snd_empty_size <= count) {
      // if write length is longer than buffer, block
      sock_info->self_syscall->seq = convert_4byte(sock_info->next_seq);
      sock_info->self_syscall->uuid = syscallUUID;
      sock_info->self_syscall->self_socket = sock_info;
      sock_info->self_syscall->temp_sockaddr = NULL;
      sock_info->self_syscall->sock_len_p = NULL;
      append_syscall_entry(blocked_syscalls, sock_info->self_syscall);
      break;
    } else {
      // copy data to send buffer
      if (sock_info->snd_next > sock_info->snd_base) {
        // not divided
        if (sock_info->snd_next + count < sock_info->snd_buffer + BUF_SIZE) {
          // back space remaining
          memcpy(sock_info->snd_next, buf, count);
          sock_info->snd_next += count;
        } else if (sock_info->snd_next + count <
                   sock_info->snd_base + BUF_SIZE) {
          // total space remaining
          n = (sock_info->snd_buffer + BUF_SIZE) - (sock_info->snd_next);
          memcpy(sock_info->snd_next, buf, n);
          memcpy(sock_info->snd_buffer, buf + n, count - n);
          sock_info->snd_next = sock_info->snd_buffer + count - n;
        } else {
          // error
          ;
        }
      } else if (sock_info->snd_next < sock_info->snd_base) {
        // divided
        assert (sock_info->snd_next + count < sock_info->snd_base);
        // both cases
        memcpy(sock_info->snd_next, buf, count);
        sock_info->snd_next += count;
      } else {
        // no space left or all space left
        memcpy(sock_info->snd_next, buf, count);
        sock_info->snd_next += count;
      }

      update_remaining(sock_info);

      // printf("%d %d\n", sock_info->snd_window_remaining,
      //        sock_info->snd_count_remaining);

      // sending packets
      while (sock_info->snd_window_remaining > 0 &&
             sock_info->snd_count_remaining > 0) {
        pkt = send_snd_packets(sock_info);
        sendPacket("IPv4", pkt);
      }

      update_empty_size(sock_info);
      returnSystemCall(syscallUUID, count);
    }

    break;

  case CONNECT:
    // this->syscall_connect(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
    // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)

    // should convert ip of server addr
    fd = std::get<int>(param.params[0]);
    temp_sockaddr =
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1]));
    sock_len = (socklen_t)std::get<int>(param.params[2]);
    pkt.setSize(54);

    // ERROR: not an existing fd
    sock_info = get_socket_info_by_fd(all_sockets, pid, fd);
    if (sock_info == NULL) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    }
    // if client addr is vacant should bind
    if (!memcmp(&sock_info->host_addr, &vacant_sockaddr,
                sizeof(sock_info->host_addr))) {
      search_sockaddr = (sockaddr_in *)malloc(sizeof(sockaddr_in));
      search_sockaddr->sin_family = AF_INET;

      // find available address and port
      port = 0;
      do {
        possible_ipv4_op = getIPAddr(port++);
        possible_ipv4 = possible_ipv4_op.value();
        possible_address =
            (uint32_t)NetworkUtil::arrayToUINT64<4>(possible_ipv4);
        search_sockaddr->sin_addr.s_addr = (possible_address);
        // ALERT: this port is not the port used here
        search_sockaddr->sin_port = (port - 1);

      } while (is_bound(pid, fd, (sockaddr *)search_sockaddr));

      memcpy(&sock_info->host_addr, search_sockaddr, sizeof(sockaddr_in));

      free(search_sockaddr);
    }

    // peer address copy
    memcpy(&sock_info->peer_addr, temp_sockaddr,
           min(sock_len, (socklen_t)sizeof(sockaddr_in)));

    sock_info->rand_seq = rand();
    new_tcp_seg = get_new_tcp_seg(sock_info->host_addr, sock_info->peer_addr,
                                  true, false, sock_info->rand_seq, 0);

    host_ip = (sock_info->host_addr.sin_addr.s_addr);
    peer_ip = (sock_info->peer_addr.sin_addr.s_addr);

    pkt.writeData(26, &host_ip, 4);
    pkt.writeData(30, &peer_ip, 4);
    pkt.writeData(34, new_tcp_seg, 20);

    sendPacket("IPv4", pkt);
    sock_info->next_seq = sock_info->rand_seq + 1;

    sock_info->tcp_status = TCP_SYN_SENT;
    sock_info->self_syscall->seq = convert_4byte(new_tcp_seg->seq);
    sock_info->self_syscall->uuid = syscallUUID;
    sock_info->self_syscall->self_socket = sock_info;
    sock_info->self_syscall->temp_sockaddr = temp_sockaddr;
    sock_info->self_syscall->sock_len_p = &sock_len;
    append_syscall_entry(blocked_syscalls, sock_info->self_syscall);

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
    if (backlog <= 0) {
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
    temp_sockaddr =
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1]));
    sock_len_p = static_cast<socklen_t *>(std::get<void *>(param.params[2]));

    // ERROR: not an existing fd
    sock_info = get_socket_info_by_fd(all_sockets, pid, fd);
    if (sock_info == NULL) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    }

    // There exists etablished connections
    if (sock_info->established_num != 0) {

      // pop from established list
      established_pack_info = sock_info->established_list->next;
      remove_packet_info(established_pack_info);
      sock_info->established_num--;

      // create a new fd
      new_sock_info = (socket_info *)malloc(sizeof(socket_info));
      memset(new_sock_info, 0, sizeof(socket_info));
      append_socket_info(all_sockets, new_sock_info);

      // initialize
      new_sock_info->fd = this->createFileDescriptor(pid);
      new_sock_info->pid = pid;
      new_sock_info->tcp_status = TCP_ESTABLISHED;
      new_sock_info->self_syscall =
          (syscall_entry *)malloc(sizeof(syscall_entry));
      memset(sock_info->self_syscall, 0, sizeof(syscall_entry));

      memcpy(&new_sock_info->host_addr, &established_pack_info->dst_addr,
             sizeof(sockaddr_in));
      memcpy(&new_sock_info->peer_addr, &established_pack_info->src_addr,
             sizeof(sockaddr_in));
      new_sock_info->rand_seq = sock_info->rand_seq;
      new_sock_info->next_seq = sock_info->rand_seq + 1;
      new_sock_info->waiting_seq = established_pack_info->seq;

      // return
      *sock_len_p = sizeof(sockaddr_in);
      memcpy(temp_sockaddr, &new_sock_info->peer_addr, sizeof(sockaddr_in));
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
    memcpy(&sock_info->host_addr,
           (sockaddr_in *)std::get<void *>(param.params[1]),
           (size_t)min(sock_len, (socklen_t)sizeof(sockaddr_in)));
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

    break;

  case GETSOCKNAME:
    // this->syscall_getsockname(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    // int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)

    fd = std::get<int>(param.params[0]);
    sock_info = get_socket_info_by_fd(all_sockets, pid, fd);
    temp_sockaddr =
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1]));
    sock_len_p = static_cast<socklen_t *>(std::get<void *>(param.params[2]));

    // handle null pointer error
    if (sock_info == NULL) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    }
    memcpy(temp_sockaddr, &sock_info->host_addr,
           min(*sock_len_p, sizeof(sockaddr_in)));
    *sock_len_p = sizeof(sockaddr_in);

    this->returnSystemCall(syscallUUID, 0);
    break;

  case GETPEERNAME:
    // this->syscall_getpeername(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    // int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)

    fd = std::get<int>(param.params[0]);
    sock_info = get_socket_info_by_fd(all_sockets, pid, fd);
    temp_sockaddr =
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1]));
    sock_len_p = static_cast<socklen_t *>(std::get<void *>(param.params[2]));

    // handle null pointer error
    if (sock_info == NULL) {
      success = false;
      this->returnSystemCall(syscallUUID, -1);
      break;
    }
    memcpy(temp_sockaddr, &sock_info->peer_addr,
           min(*sock_len_p, sizeof(sockaddr_in)));
    *sock_len_p = sizeof(sockaddr_in);

    this->returnSystemCall(syscallUUID, 0);

    break;

  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // printf("packet_arrived\n");
  tcp_segment arrived_tcp_seg;
  ipv4_t src_ip;
  ipv4_t dst_ip;

  // read as arrived_tcp_seg and store in arrived_packet
  packet.readData(34, &arrived_tcp_seg, sizeof(tcp_segment));

  int32_t src_addr;
  int32_t dst_addr;
  packet.readData(26, &src_addr, 4);
  packet.readData(30, &dst_addr, 4);

  packet_info *arrived_packet =
      tcp_seg_to_pkt_info(arrived_tcp_seg, src_addr, dst_addr);

  // write packet info in arrived packet
  socket_info *self_sock_info =
      get_socket_info_by_host_and_peer(all_sockets, &arrived_packet->dst_addr, &arrived_packet->src_addr);
  
  // printf("packet received %d\n", self_sock_info->tcp_status);
  int new_pkt_seq;

  Packet pkt(54);
  struct packet_info *sent_packet_info =
      (packet_info *)malloc(sizeof(packet_info));

  if (self_sock_info == NULL) {
    self_sock_info = get_socket_info_by_host_and_peer(all_sockets, &arrived_packet->dst_addr, NULL);
    if (self_sock_info == NULL) {
      // error 
      ;
    } else {
      if (arrived_packet->SYN && !arrived_packet->ACK) {
        // TWH1
        if (self_sock_info->tcp_status != TCP_LISTEN && 
            self_sock_info->tcp_status != TCP_SYN_RECV) {
          return;
        }

        if (self_sock_info->backlog <= self_sock_info->pending_num) {
          return;
        }

        self_sock_info->rand_seq = rand();
        struct tcp_segment *new_tcp_seg = get_new_tcp_seg(
          arrived_packet->dst_addr, arrived_packet->src_addr, true, true,
          self_sock_info->rand_seq, arrived_packet->seq + 1);

        pkt.writeData(26, &arrived_packet->dst_addr.sin_addr.s_addr, 4);
        pkt.writeData(30, &arrived_packet->src_addr.sin_addr.s_addr, 4);
        pkt.writeData(34, new_tcp_seg, 20);

        self_sock_info->tcp_status = TCP_SYN_RECV;

        append_packet_info(self_sock_info->pending_list, arrived_packet);
        self_sock_info->pending_num++;
        free(new_tcp_seg);
        sendPacket("IPv4", pkt);

        self_sock_info->next_seq = self_sock_info->rand_seq + 1;

      } else if (!arrived_packet->SYN && arrived_packet->ACK) {
        // TWH3
        if (self_sock_info->tcp_status != TCP_SYN_RECV) {
          return;
        }

        struct packet_info *sender_packet = pop_packet_info_by_addr(
          self_sock_info->pending_list, &arrived_packet->src_addr);

        if (sender_packet == NULL && 
          self_sock_info->rand_seq + 1 != arrived_packet->ack) {
          return;
        }

        self_sock_info->pending_num--;
        if (self_sock_info->pending_num == 0) {
          self_sock_info->tcp_status = TCP_LISTEN;
        }

        append_packet_info(self_sock_info->established_list, arrived_packet);
        self_sock_info->established_num++;

        // if blocked call exists
        if (self_sock_info->self_syscall->next != NULL) {
          assert(self_sock_info->established_num != 0);
          
          // pop from established list
          packet_info *sender_packet = self_sock_info->established_list->next;
          remove_packet_info(sender_packet);
          self_sock_info->established_num--;

          // create a new fd
          socket_info *new_sock_info =
              (socket_info *)malloc(sizeof(socket_info));
          memset(new_sock_info, 0, sizeof(socket_info));
          append_socket_info(all_sockets, new_sock_info);

          // initialize
          new_sock_info->tcp_status = TCP_ESTABLISHED;
          new_sock_info->fd = this->createFileDescriptor(self_sock_info->pid);
          new_sock_info->pid = self_sock_info->pid;
          new_sock_info->self_syscall =
              (syscall_entry *)malloc(sizeof(syscall_entry));
          new_sock_info->rand_seq = self_sock_info->rand_seq;
          new_sock_info->next_seq = self_sock_info->rand_seq + 1;
          new_sock_info->waiting_seq = sender_packet->seq;
          memset(new_sock_info->self_syscall, 0, sizeof(syscall_entry));
          memcpy(&new_sock_info->host_addr, &sender_packet->dst_addr, sizeof(sockaddr_in));
          memcpy(&new_sock_info->peer_addr, &sender_packet->src_addr, sizeof(sockaddr_in));
          prepare_buffer(new_sock_info, sender_packet);

          // return
          *(self_sock_info->self_syscall->sock_len_p) = sizeof(sockaddr_in);
          memcpy(self_sock_info->self_syscall->temp_sockaddr,
                  &new_sock_info->peer_addr, sizeof(sockaddr_in));
          this->returnSystemCall(self_sock_info->self_syscall->uuid, new_sock_info->fd);
          remove_syscall_entry(self_sock_info->self_syscall);
        }
      } else {
        // error
      }
    }
  } else if (arrived_packet->SYN && arrived_packet->ACK) {
    // TWH2    
    if (self_sock_info->self_syscall->next != NULL) {
      // set tcp status
      self_sock_info->tcp_status = TCP_ESTABLISHED;

      prepare_buffer(self_sock_info, arrived_packet);

      if (arrived_packet->ack != self_sock_info->rand_seq + 1) {
        return;
      }

      // sending TWH3
      struct tcp_segment *new_tcp_seg = get_new_tcp_seg(
          arrived_packet->dst_addr, arrived_packet->src_addr, false, true,
          arrived_packet->ack, arrived_packet->seq + 1);

      pkt.writeData(26, &arrived_packet->dst_addr.sin_addr.s_addr, 4);
      pkt.writeData(30, &arrived_packet->src_addr.sin_addr.s_addr, 4);
      pkt.writeData(34, new_tcp_seg, 20);
      self_sock_info->waiting_seq = arrived_packet->seq + 1;
      free(new_tcp_seg);
      sendPacket("IPv4", pkt);

      returnSystemCall(self_sock_info->self_syscall->uuid, 0);
    }
  } else if (!arrived_packet->SYN && arrived_packet->ACK) {
    // DATA, DATA_ACK, FIN_ACK, FIN 
    if (arrived_packet->FIN) {
      // FIN
      return;
    }
    if (packet.getSize() != PKT_HEADER_LEN) {
      // DATA
      int data_len = packet.getSize() - PKT_HEADER_LEN;
      assert(data_len <= self_sock_info->rcv_window);

      packet.readData(54, self_sock_info->rcv_next, data_len);
      self_sock_info->rcv_next += data_len;
      
      if (self_sock_info->rcv_next >= self_sock_info->rcv_buffer + BUF_SIZE) {
        // printf("if moon\n");
        data_len -=
            self_sock_info->rcv_next - (self_sock_info->rcv_buffer + BUF_SIZE);
        self_sock_info->rcv_next -= BUF_SIZE;
        packet.readData(54 + data_len, self_sock_info->rcv_buffer,
                        self_sock_info->rcv_next - self_sock_info->rcv_buffer);
      }
      
      self_sock_info->waiting_seq = arrived_packet->seq + data_len;
      self_sock_info->rcv_window -= data_len;

      // send ack packet
      struct tcp_segment *new_tcp_seg = get_new_tcp_seg(
          arrived_packet->dst_addr, arrived_packet->src_addr, false, true,
          self_sock_info->next_seq, self_sock_info->waiting_seq);
      // printf("rcv window is %d\n", self_sock_info->rcv_window);
      new_tcp_seg->rec_win = convert_2byte(min(self_sock_info->rcv_window, 51200));
      new_tcp_seg->checksum = 0;
      new_tcp_seg->checksum =
          htons(~NetworkUtil::tcp_sum(self_sock_info->host_addr.sin_addr.s_addr,
                                      self_sock_info->peer_addr.sin_addr.s_addr,
                                      (uint8_t *)new_tcp_seg, 20));

      pkt.writeData(26, &arrived_packet->dst_addr.sin_addr.s_addr, 4);
      pkt.writeData(30, &arrived_packet->src_addr.sin_addr.s_addr, 4);
      pkt.writeData(34, new_tcp_seg, 20);

      free(new_tcp_seg);
      sendPacket("IPv4", pkt);

      if (self_sock_info->self_syscall->next != NULL && self_sock_info->self_syscall->syscall_num == READ) {
        struct syscall_entry *blocked_read = self_sock_info->self_syscall;
        // printf("read from %d\n", self_sock_info->rcv_base);
        int read_byte = read_data(blocked_read->usr_buffer, self_sock_info, blocked_read->read_byte);
        this->returnSystemCall(blocked_read->uuid, read_byte);
      }
    } else {
      // DATA_ACK
      for (struct packet_elem *cur = self_sock_info->sent_packets->next;
         cur != self_sock_info->sent_packets; cur = cur->next) {
        if (arrived_packet->ack == cur->ack) {
          struct packet_elem *acked_packet = self_sock_info->sent_packets->next;
          self_sock_info->sent_packets->next = acked_packet->next;
          self_sock_info->sent_packets->next->prev = self_sock_info->sent_packets;
          self_sock_info->snd_base += acked_packet->data_size;
          if (self_sock_info->snd_base >= self_sock_info->snd_buffer + BUF_SIZE) {
            self_sock_info->snd_base -= BUF_SIZE;
          }
          // self_sock_info->snd_empty_size += acked_packet->data_size;
          self_sock_info->snd_window = arrived_packet->rec_win;
          if (self_sock_info->snd_base != self_sock_info->snd_next) {
            // send packets
            update_remaining(self_sock_info);

            // printf("%d %d\n", self_sock_info->snd_window_remaining,
            //       self_sock_info->snd_count_remaining);

            // sending packets
            while (self_sock_info->snd_window_remaining > 0 &&
                  self_sock_info->snd_count_remaining > 0) {
              pkt = send_snd_packets(self_sock_info);
              sendPacket("IPv4", pkt);
            }
          }
          update_empty_size(self_sock_info);
        }
      }
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
