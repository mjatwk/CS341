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
  enum socket_status {OPENED, BOUND, LISTENING, CONNECTING, ACCEPTING, CONNECTED, CLOSED, ERROR};

  struct addr_entry {
    int fd;
    int pid;
    std::string host_name;
    struct syscall_entry *self;
    enum socket_status status;
    struct sockaddr_in host_addr;
    struct sockaddr_in peer_addr;
    struct addr_entry *prev;
    struct addr_entry *next;
    int num_listens;
    int backlog;
    addr_entry* all_listens;
    int host_status;
  };
  
  struct syscall_entry {
    UUID syscall_id;
    UUID timer;
    struct addr_entry *sock;
    struct syscall_entry *prev;
    struct syscall_entry *next;
  };

  struct SYN {
    struct sockaddr_in addr;
    int a;
  };

  struct ACK {
    struct sockaddr_in addr;
    int a;
  };

  // addr_entry* get_addr_entry_by_fd(int fd);

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
