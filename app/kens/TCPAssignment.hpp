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

enum tcp_stat
{
  TCP_ESTABLISHED = 1,  // connected
  TCP_SYN_SENT,         // 
  TCP_SYN_RECV,         // 
  TCP_FIN_WAIT1,        //
  TCP_FIN_WAIT2,        //
  TCP_TIME_WAIT,        
  TCP_CLOSE,            // close
  TCP_CLOSE_WAIT,       // close_wait
  TCP_LAST_ACK,
  TCP_LISTEN,           // listen
  TCP_CLOSING   /* now a valid state */
};

enum sock_stat {
  OPENED, 
  BOUND, 
  LISTENING, 
  CONNECTING, 
  ACCEPTING,
  CONNECTED, 
  ERROR
};

struct socket_info {
  std::string host_name;
  int fd;
  sockaddr_in host_addr;
  sockaddr_in peer_addr;
  enum tcp_stat tcp_status;
  enum sock_stat sock_status;
  bool is_bound;

  socket_info *prev;
  socket_info *next;
};

struct addr_entry {
  sockaddr_in addr;

  addr_entry *prev;
  addr_entry *next;
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
