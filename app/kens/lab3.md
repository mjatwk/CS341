# structure

```cpp
#define BUF_REAL_SIZE 1 << 22 // 4MB; 2MB + at min PKT_DATA_LEN
#define BUF_LEN 1 << 21 // 2MB 
#define PKT_DATA_LEN 1460 // same as MSS
#define INIT_RTT 100 // in milliseconds (should change)
#define ALPHA 0.125 
#define BETA 0.25

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
```

## send buffer
- only store data 
- fixed length

## send_packet_list
- circular linked list 
- elem packet_elem

## rcv_buffer
- similar with send_buffer

## rcv_packet_list
- structure as send_packet_list

## packet_elem
- packet pointer
- packet seq (if needed; for convenience)
- packet data len (if needed; for convenience)
- data pointer on buffer
- prev, next

## timer
- TimerModule
- corresponding packet_elem

---

# sender side

## write()
Two cases below

1. If there is enough space in the corresponding TCP socket’s send buffer for the data, the data is copied to the send buffer. Then,
    1. if the data is sendable (i.e., the data lies in the sender’s window), send the data and the call returns.
    2. if the data is not sendable (i.e., the data lies outside the sender’s window), the call just returns.

2. If there is not enough space, the call blocks until the TCP layer receives ACK(s) and  releases sufficient space for the data. When sufficient space for the given (from application) data becomes available, the data is copied to the send buffer and then,
    1. if the data is sendable (i.e., the data lies in the sender-side window), send the data and the call returns.
    2. if the data is not sendable (i.e., the data lies outside the sender-side window), the call just returns.

## send_data
1. send data
2. set timer

## timer
if timer is not off until set time
1. resend packet
2. reset timer

## ack_packet_arrive
do all 4+1 steps
1. free the send buffer space allocated for acked data + linked list
2. move the sender window (the number of in-flight bytes should be decreased)
3. adjust the sender window size (from advertised receive buffer size)
4. send data if there is waiting data in the send buffer and if the data is sendable (i.e., there is room in sender’s window)
5. update timers (if ack is larger than packet seq, turn off timer)

---
# receiver side

## read
Two cases below

1. If there is already received data in the corresponding TCP socket’s receive buffer, the data is copied to the application’s buffer and the call returns immediately.

2. If there is no received data, the call blocks until any data is received from the sender. When data arrives, the data is copied to the application’s buffer and the call returns.

## data_packet_arrive
do all 2 steps
1. copy the payload to the corresponding TCP socket’s receive buffer
2. acknowledge received packet (i.e., send an ACK packet)

## ack_packet_return
return the first empty seq

---
# functions
```cpp
struct tcp_segment *get_new_tcp_seg(sockaddr_in src_addr, sockaddr_in dst_addr,int seq, int ack)

struct packet_info *tcp_seg_to_pkt_info(struct tcp_segment arrived_tcp_seg,int32_t src_addr, int32_t dst_addr)
}
```
