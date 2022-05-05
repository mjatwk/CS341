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
#define BUF_LEN (1 << 21)       // 2MB
#define PKT_DATA_LEN 1460       // same as MSS
#define INIT_RTT 100            // in milliseconds (should change)
#define ALPHA 0.125
#define BETA 0.25

enum tcp_stat {
  TCP_ESTABLISHED = 1, // connected
  TCP_SYN_SENT,        //
  TCP_SYN_RECV,        //
  TCP_FIN_WAIT1,       //
  TCP_FIN_WAIT2,       //
  TCP_TIME_WAIT,
  TCP_CLOSE,      // close
  TCP_CLOSE_WAIT, // close_wait
  TCP_LAST_ACK,
  TCP_LISTEN, // listen
  TCP_CLOSING /* now a valid state */
};

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

  // timer
  int estimated_rtt = INIT_RTT;
  int dev_rtt = 0;
  int timeout_interval = estimated_rtt;

  // snd_buf
  char *send_base;
  char *send_end = send_base + BUF_LEN;
  int send_margin;  // if data overflow, the length of overflow (MAX a packet)
  char *send_unack; // unacked data start pointer
  char *send_next;  // where to append next data
  char *send_window_start;
  int send_window_size;
  char *send_window_end;

  // rcv_buf
  char *rcv_base;
  char *rcv_end = rcv_base + BUF_LEN;
  int rcv_margin;   // if data overflow, the length of overflow (MAX a packet)
  char *rcv_unread; // unread data start pointer
  char *rcv_next;   // where to append next data
  int rcv_window_size;
};

struct addr_entry {
  int fd;
  int pid;
  sockaddr_in addr;

  addr_entry *prev;
  addr_entry *next;
};

struct syscall_entry {
  UUID uuid;
  socket_info *self_socket;
  int new_fd;
  sockaddr *temp_sockaddr;
  socklen_t *sock_len_p;
  int seq;

  syscall_entry *prev;
  syscall_entry *next;
};

struct packet_info {
  sockaddr_in src_addr;
  sockaddr_in dst_addr;
  int32_t seq;
  int32_t ack;
  uint16_t SYN;
  uint16_t ACK;
  uint16_t FIN;
  int checksum;

  int32_t seq_sent;

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
