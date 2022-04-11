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

#define for_each_addr_cur for(cur = all_sockets->next; cur != all_sockets; cur = cur->next)

namespace E {

addr_entry* all_sockets;
syscall_entry* blocked_syscalls; 

bool is_addr_used(sockaddr* addr) {
  bool result = false;
  for(addr_entry* cur = all_sockets->next; cur != all_sockets; cur = cur->next) {
    if(!memcmp(&cur->host_addr, addr, sizeof(cur->host_addr))) {
      result = true;
      break;
    }
    for(addr_entry* cur_wait = cur->all_listens->next; cur_wait != cur->all_listens; cur_wait = cur_wait->next) {
      if(!memcmp(&cur->host_addr, addr, sizeof(cur->host_addr))) {
      result = true;
      break;
      }
    }
  }
  return result;
} 

// get addr_entry by PID and FD from HEAD list
addr_entry* get_addr_entry(addr_entry* head, int pid, int fd) {
  for (addr_entry* cur = head->next; cur != head; cur = cur->next) 
  {
    if (cur->pid == pid && cur->fd == fd && cur->status != CONNECTED)
    {
      return cur;
    }
  } 
  return NULL;
}

// get addr_entry by HOST_ADDR from HEAD list
addr_entry* get_addr_entry_by_addr(addr_entry* head, sockaddr_in* host_addr) {
  for (addr_entry* cur = head->next; cur != head; cur = cur->next) 
  {
    if (!memcmp(&cur->host_addr, host_addr, sizeof(sockaddr_in)) ||
      ((cur->host_addr.sin_addr.s_addr == INADDR_ANY || 
        host_addr->sin_addr.s_addr == INADDR_ANY) &&
        cur->host_addr.sin_port == host_addr->sin_port))
    {
      return cur;
    }
  } 
  return NULL;
}

// get addr_entry by HOST_ADDR from HEAD list
void addr_list_iterate(addr_entry* head) {
  printf("iterating...\n");
  for (addr_entry* cur = head->next; cur != head; cur = cur->next) 
  {
    printf("pid:fd is %d:%d, ", cur->pid, cur->fd);
    printf("status is %d\n", cur->status);
  }
  printf("list ended...\n");
}

void append_addr_entry(addr_entry* head, addr_entry* new_addr) {
  head->prev->next = new_addr;
  new_addr->prev = head->prev;
  new_addr->next = head;
  head->prev = new_addr;
}

void remove_addr_entry(addr_entry* new_addr) {
  new_addr->prev->next = new_addr->next;
  new_addr->next->prev = new_addr->prev;
}


void append_syscall_entry(syscall_entry* head, syscall_entry* new_syscall) {
  head->prev->next = new_syscall;
  new_syscall->prev = head->prev;
  new_syscall->next = head;
  head->prev = new_syscall;
}

void remove_syscall_entry(syscall_entry* new_syscall) {
  new_syscall->prev->next = new_syscall->next;
  new_syscall->next->prev = new_syscall->prev;
}

// bind appropriate addr from randomly chosen port and ip, 
// the addr should not be already bound

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {
  all_sockets = (addr_entry *)malloc(sizeof(struct addr_entry));
  memset(&all_sockets->host_addr, 0, sizeof(sockaddr_in));
  all_sockets->prev = all_sockets;
  all_sockets->next = all_sockets;

  blocked_syscalls = (syscall_entry *)malloc(sizeof(struct syscall_entry));
  blocked_syscalls->prev = blocked_syscalls;
  blocked_syscalls->next = blocked_syscalls;
}

void TCPAssignment::finalize() {
  // return all blocked syscalls as -1
  for(syscall_entry *cur = blocked_syscalls->next; cur != blocked_syscalls; cur = cur->next) {
    returnSystemCall(cur->syscall_id, -1);
  }
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  // Remove below
  // (void)syscallUUID;
  // (void)pid;
  int LISTEN_MIN = 1;
  int LISTEN_MAX = 100;
  
  sockaddr_in* new_sock = (sockaddr_in*)malloc(sizeof(sockaddr_in));
  sockaddr_in* temp_sock;
  addr_entry* cur;
  addr_entry* new_addr;
  addr_entry* addr;

  syscall_entry* cur_syscall;
  syscall_entry* new_syscall;
  syscall_entry* temp_syscall;
  
  socklen_t* addr_len;
  in_addr_t addr_addr;
  int fd;
  int backlog;
  bool success;
  int n;
  int count;
  int port;

  size_t packet_size = 100;
  Packet pck (packet_size);
  SYN syn;
  ACK ack;

  UUID timer;
  E::Time TIMER_TIME = 10000000000000;

  switch (param.syscallNumber) {
  case SOCKET:
    // this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));

    new_addr = (addr_entry *)malloc(sizeof(addr_entry));
    new_addr->status = OPENED;
    new_addr->pid = pid;
    new_addr->fd = this->createFileDescriptor(pid);
    memset(&new_addr->host_addr, 0, sizeof(sockaddr_in));
    memset(&new_addr->peer_addr, 0, sizeof(sockaddr_in));

    new_addr->all_listens = (addr_entry *)malloc(sizeof(addr_entry));
    new_addr->all_listens->prev = new_addr->all_listens;
    new_addr->all_listens->next = new_addr->all_listens;
    new_addr->num_listens = 0;
    new_addr->backlog = 0;
    new_addr->host_name.assign(getHostModuleName());

    // append to the linked list
    append_addr_entry(all_sockets, new_addr);
    
    new_syscall = (syscall_entry *)malloc(sizeof(syscall_entry));
    memset(new_syscall, 0, sizeof(syscall_entry));
    new_syscall->sock = new_addr;
    new_syscall->syscall_id = syscallUUID;
    new_addr->self = new_syscall;

    this->returnSystemCall(syscallUUID, new_addr->fd);
    printf("socket() ended\n");
    break;

  case CLOSE:
    // this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    fd = std::get<int>(param.params[0]);
    this->removeFileDescriptor(pid, fd);

    addr = get_addr_entry(all_sockets, pid, fd);
    if (addr == NULL) {
      success = false;
      this->returnSystemCall(syscallUUID, -1); 
    } else {
      remove_addr_entry(addr);
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
    // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
    
    fd = std::get<int>(param.params[0]);
    addr = get_addr_entry(all_sockets, pid, fd);
    *addr_len = (socklen_t)std::get<int>(param.params[2]);
    // preparing client socket
    if (addr == NULL || addr->status != OPENED) {
      success = false;
    } else {
      memset(new_sock, 0, sizeof(sockaddr_in));
      if (!memcmp(&addr->host_addr, new_sock, sizeof(sockaddr_in))) {
        // TODO: bind random address
        // port = 100;
        // addr_addr = INADDR_ANY + 1;
        // new_sock->sin_family = AF_INET;
        // do {
        //   new_sock->sin_port = port;
        //   new_sock->sin_addr.s_addr = addr_addr;
        //   addr_addr++;
        // } while (is_addr_used((sockaddr*) new_sock));
        // memcpy(&addr->host_addr, new_sock, sizeof(sockaddr_in));
      } else {
        // already bound 
        ;
      }
      memcpy(&addr->peer_addr, (struct sockaddr *)(std::get<void *>(param.params[1])), sizeof(sockaddr_in));
    }

    // memcpy(&syn.addr, &addr->host_addr, sizeof(struct sockaddr_in));
    // syn.a = syscallUUID;
    // pck.writeData(0, &syn, sizeof(syn));
    // cur = get_addr_entry_by_addr(all_sockets, &addr->peer_addr);
    // if (cur == NULL) {
    //   success = false;
    // }
    // sendPacket(cur->host_name, std::move(pck));

    // connecting to server socket
    cur = get_addr_entry_by_addr(all_sockets, &addr->peer_addr);
    if (cur = NULL) {
      success = false;
    }
    else if (cur->status == ACCEPTING) {
      cancelTimer(cur->self->timer);
      remove_syscall_entry(cur->self); // remove from blocked syscall list
      // new socket to return to server
      new_addr = (addr_entry *)malloc(sizeof(addr_entry));
      memset(new_addr, 0, sizeof(addr_entry));
      new_addr->pid = cur->pid;
      new_addr->fd = this->createFileDescriptor(cur->pid);
      new_addr->status = CONNECTED;
      memcpy(&new_addr->host_addr, &cur->host_addr, sizeof(sockaddr_in));
      memcpy(&new_addr->peer_addr, &addr->host_addr, sizeof(sockaddr_in));
      new_addr->all_listens->prev = new_addr->all_listens;
      new_addr->all_listens->next = new_addr->all_listens;
      append_addr_entry(all_sockets, new_addr);
      returnSystemCall(cur->self->syscall_id, new_addr->fd);

      // return to client
      addr->status = CONNECTED;
      returnSystemCall(syscallUUID, 0);
    }
    else if (cur->status == LISTENING) {
      addr->status = CONNECTING;
      cur->num_listens++;
      if (cur->num_listens > cur->backlog) {
        success = false;
        cur->num_listens--;
      } else {
        remove_addr_entry(addr);
        append_addr_entry(cur->all_listens, addr);
        addr_list_iterate(cur->all_listens);
        cur->self->timer = addTimer(syscallUUID, TIMER_TIME);
        cur->self->syscall_id = syscallUUID;
        append_syscall_entry(blocked_syscalls, cur->self);
      }
    } else {
      assert(0);
      success = false;
    }

    // success and fail
    if (!success) {
      this->returnSystemCall(syscallUUID, -1);
    }
    printf("connect() ended\n");
    
    break;
  
  case LISTEN:
    // this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
    //                      std::get<int>(param.params[1]));
    // listen(int sockfd, int backlog)
    fd = std::get<int>(param.params[0]);
    backlog = std::get<int>(param.params[1]);
    success = true;
    // if backlog is under 0, behaves like backlog is 0
    if (backlog < 0) {
      backlog = 0;
    }

    /* if backlog = 0, may allow the socket to accept connections, 
    * in which case the length of the listen queue may be set to an implementation-defined minimum value
    * The implementation-defined minimum value defined as LISTEN_MIN (currently 1)
    */
    if (backlog == 0) {
      backlog = LISTEN_MIN;
    }
    /* LISTEN_ARRAY is given in length of LISTEN_MAX, both incompleted and completed connections appended
    * only handling if the number of incompleted connections are below BACKLOG
    */
    // handle backlog

    addr = get_addr_entry(all_sockets, pid, fd);    
    if (addr == NULL || (addr->status != OPENED && addr->status != BOUND)) {
      success = false;
    } else {
      addr->num_listens = 0;
      addr->backlog = backlog;
      addr->all_listens->prev = addr->all_listens;
      addr->all_listens->next = addr->all_listens;
    }

    // success and fail
    if (success) {
      addr->status = LISTENING;
      this->returnSystemCall(syscallUUID, 0);
    } else {
      this->returnSystemCall(syscallUUID, -1);
    }

    printf("listen() ended\n");
    break;
  
  case ACCEPT:
    // this->syscall_accept(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    // accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
    fd = std::get<int>(param.params[0]);
    temp_sock = static_cast<struct sockaddr_in *>(std::get<void *>(param.params[1]));
    addr_len = (socklen_t *)std::get<void *>(param.params[2]);
    success = true;

    addr = get_addr_entry(all_sockets, pid, fd);
    if (addr == NULL) {
      success = false;
    } else {
      if (addr->num_listens < 1) { // no connection to accept
        addr->self->timer = addTimer(syscallUUID, TIMER_TIME);
        addr->self->syscall_id = syscallUUID;
        append_syscall_entry(blocked_syscalls, addr->self);
        addr->status = ACCEPTING;
      } else {
        addr_list_iterate(cur->all_listens);
        cur = addr->all_listens->next;
        assert(cur != addr->all_listens);
        assert(cur->status == CONNECTING);

        // handle syscall        
        cancelTimer(cur->self->timer);
        remove_syscall_entry(cur->self);
        this->returnSystemCall(cur->self->syscall_id, 0);

        // now the client is not wating
        remove_addr_entry(cur);
        append_addr_entry(all_sockets, cur);
        addr->num_listens--;
        cur->status = CONNECTED;

        // should return new socket fd
        new_addr = (addr_entry *)malloc(sizeof(addr_entry));
        memset(new_addr, 0, sizeof(addr_entry));
        new_addr->pid = pid;
        new_addr->fd = this->createFileDescriptor(pid);
        new_addr->status = CONNECTED;
        memcpy(&new_addr->host_addr, &addr->host_addr, sizeof(sockaddr_in));
        memcpy(&new_addr->peer_addr, &cur->host_addr, sizeof(sockaddr_in));
        new_addr->all_listens->prev = new_addr->all_listens;
        new_addr->all_listens->next = new_addr->all_listens;
        append_addr_entry(all_sockets, new_addr);
        if (temp_sock != NULL) {
          memcpy(temp_sock, &cur->host_addr, *addr_len > (socklen_t)sizeof(sockaddr_in) ? (socklen_t)sizeof(sockaddr_in) : *addr_len);
          *addr_len = sizeof(sockaddr_in);
        }

        // connection is complete
        this->returnSystemCall(syscallUUID, new_addr->fd);
      }
    }
    if (!success) {
      this->returnSystemCall(syscallUUID, -1);
    }

    printf("accept() ended\n");
    break;

  case BIND:
    // this->syscall_bind(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     (socklen_t)std::get<int>(param.params[2]));
    // int bind(int socket, const struct sockaddr *address, socklen_t address_len);
    fd = std::get<int>(param.params[0]);
    addr = get_addr_entry(all_sockets, pid, fd);
    *addr_len = (socklen_t)std::get<int>(param.params[2]);
    memcpy(new_sock, static_cast<struct sockaddr *>(std::get<void *> (param.params[1])), *addr_len);

    success = true;

    // check if the address is not bound
    for_each_addr_cur {
      // if fd is already bound
      // printf("[bind] 1\n");
      if (cur->pid == pid && cur->fd == fd && cur->status != OPENED)
      {
        success = false;
        break;
      }
      
      // if INADDR_ANY && same port number
      if ( (cur->host_addr.sin_addr.s_addr == INADDR_ANY || new_sock->sin_addr.s_addr == INADDR_ANY) &&
        !memcmp(&cur->host_addr.sin_port, &new_sock->sin_port, sizeof(new_sock->sin_port))) 
      {
        success = false;
        break;
      }

      // the address is already bound
      if (!memcmp(&cur->host_addr, &new_sock, sizeof(new_sock)))
      {
        success = false;
        break;
      }
      // printf("[bind] 2\n");
    } 
    // printf("[bind] 3\n");
    if (success) {
      addr->status = BOUND;
      // printf("[bind] 4\n");
      memcpy(&addr->host_addr, new_sock, *addr_len);
      // printf("[bind] 5\n");
      this->returnSystemCall(syscallUUID, 0);
    } else {
      this->returnSystemCall(syscallUUID, -1);
      // printf("[bind] fail\n");
    }
    // printf("[bind] 6\n");
    printf("bind() ended\n");
    break;
  
  case GETSOCKNAME:
    // this->syscall_getsockname(
    //     syscallUUID, pid, std::get<int>(param.params[0]),
    //     static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
    //     static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    // int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
    fd = std::get<int>(param.params[0]);

    addr_len = (static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    
    addr = get_addr_entry(all_sockets, pid, fd);
    if (addr == NULL) {
      this->returnSystemCall(syscallUUID, -1);
    } else {
      memcpy(static_cast<sockaddr *>(std::get<void *> (param.params[1])), &addr->host_addr, 
        *addr_len > (socklen_t)sizeof(sockaddr_in) ? (socklen_t)sizeof(sockaddr_in) : *addr_len);
      *addr_len = sizeof(sockaddr_in);
      this->returnSystemCall(syscallUUID, 0);
    }
    printf("getsockname() ended\n");
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

  free(new_sock);
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  // (void)payload;
  printf("[timer] time out\n");
  printf("[timer] %d\n", (int)std::any_cast<E::UUID>(payload));
  this->returnSystemCall(std::any_cast<E::UUID>(payload), -1);
}

} // namespace E
