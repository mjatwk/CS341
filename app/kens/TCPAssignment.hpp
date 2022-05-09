/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

namespace E {

#define min(a, b) (a > b ? b : a)
#define MIN_BACKLOG 1
#define START_PORT 0

#define BUF_REAL_SIZE (1 << 22) // 4MB; 2MB + at min PKT_DATA_LEN
#define BUF_SIZE (1 << 21)      // 2MB
#define PKT_HEADER_LEN 54       // packet header length
#define PKT_DATA_LEN 1024       // same as MSS
#define INIT_RTT 100000000      // 100 ms
#define ALPHA 0.125
#define BETA 0.25

enum tcp_stat {
  TCP_ESTABLISHED = 1, // connected
  TCP_SYN_SENT,        // connect()
  TCP_SYN_RECV,        // connection request
  TCP_FIN_WAIT1,       //
  TCP_FIN_WAIT2,       //
  TCP_TIME_WAIT,
  TCP_CLOSE,      // close
  TCP_CLOSE_WAIT, // close_wait
  TCP_LAST_ACK,
  TCP_LISTEN, // listen
  TCP_CLOSING /* now a valid state */
};

// enum SystemCall {
//     SOCKET = 1,
//     CLOSE,
//     READ,
//     WRITE,
//     CONNECT,
//     LISTEN,
//     ACCEPT,
//     BIND,
//     GETSOCKNAME,
//     GETPEERNAME,

//     NSLEEP,
//     GETTIMEOFDAY,
//   };

struct socket_info {
  int fd;
  int pid;
  sockaddr_in host_addr;
  sockaddr_in peer_addr;
  enum tcp_stat tcp_status;

  struct syscall_entry *self_syscall;

  socket_info *prev;
  socket_info *next;

  int backlog;
  int pending_num;
  struct packet_info *pending_list;
  int established_num;
  struct packet_info *established_list;

  // connection
  int rand_seq;
  int next_seq;
  int waiting_seq;

  // timer
  int estimated_rtt;
  int dev_rtt;
  int timeout_interval;

  // snd_buf
  int8_t *snd_buffer;
  int8_t *snd_base;   // unacked data start pointer = send window base
  int8_t *snd_next;   // where to append next data
  int8_t *snd_packet; // where to start sending next packet
  int snd_empty_size; 
  int snd_window; // send window size
  int snd_count_remaining;
  int snd_window_remaining;
  struct packet_elem *sent_packets; // sent and not acked packet list

  // rcv_buf
  int8_t *rcv_buffer;
  int8_t *rcv_base; // unread data start pointer = receive window base
  int8_t *rcv_next; // where to append next data
  int rcv_window;   // receive window size = empty buffer size
};

struct addr_entry {
  int fd;
  int pid;
  sockaddr_in addr;

  addr_entry *prev;
  addr_entry *next;
};

struct syscall_entry {
  int syscall_num;
  UUID uuid;
  socket_info *self_socket;
  int new_fd;
  sockaddr *temp_sockaddr;
  socklen_t *sock_len_p;
  int seq;
  int read_byte;
  int8_t* usr_buffer;

  syscall_entry *prev;
  syscall_entry *next;
};

struct packet_info {
  sockaddr_in src_addr;
  sockaddr_in dst_addr;

  bool SYN;
  bool ACK;
  bool FIN;

  int32_t seq;
  int32_t ack;
  uint16_t rec_win;
  uint16_t checksum;

  packet_info *prev;
  packet_info *next;
};

struct tcp_segment {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seq;
  uint32_t ack;
  uint16_t flags;
  uint16_t rec_win;
  uint16_t checksum;
  uint16_t urg_pts;
};

struct packet_elem {
  struct packet_elem *prev;
  struct packet_elem *next;

  int ack;
  int data_size;
  UUID timer;

  Packet *packet;
};

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
};

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */
