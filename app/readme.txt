// 2022 Spring CS341 Introduction to Computer Networks 
// readme.txt on Lab4
// Team 12: Minjun Kim(20190100), Hyewon Hwang(20200722)

// IMPORTANT: USAGE OF 0 TOKENS FOR EACH OF MEMBERS FOR LAB4 

>> Added / Modified data structures
1. dist_entry: each entry for distance table
* added dist_entry *all_dist_entry and int total_dist_cnt for each class RoutingAssignment

>> Implementing progress of Lab 4
1. initialize
    - made a circular linked list of dist_entry starting with all_dist_entry, which is the dist_table for given node
    - only IPs of self node is saved in the table
    - send request as broadcast, for each IPs, then setTimer (of 50s)
2. packetArrived
    - if is a request, send response with current dist_table back to the src_addr of given packet
    - if is a response, update self dist_table by comparing metrics
3. timerCallback
    - if timer ends, broadcast response with current dist_table, then setTimer (of 50s) again


// readme.txt on Lab3
// Team 12: Minjun Kim(20190100), Hyewon Hwang(20200722)

// IMPORTANT: USAGE OF 1 TOKEN FOR EACH OF MEMBERS FOR LAB3

>> Added / Modified data structures
1. packet_elem: send and receive in packet units
2. socket_info: send_buffer, receive_buffer, timer properties

>> Implementing progress of Lab 3
1. Reliable: read(), write(), packetArrived()
    - read(): read count bytes from receive_buffer, if received_data is not yet as count bytes, read as given and call read() again 
    - write(): move to send_buffer and send if send_window has vacant space, blocked until send_window has remaining space
    - packetArrived(): if DATA packet arrives, copy to receive_buffer and send DATA-ACK packet, if DATA-ACK packet arrives free send_buffer and packet_elem 
2. Unreliable: timer, checksum, re-send packet if not acked
    - timer: set timer if DATA packet is sent
    - checksum: ignore if checksum bytes does not match with calculated checksum
    - re-send packet: if DATA-ACK packet does not arrive for given DATA packet until the timer ends, re-send it

// readme.txt on Lab2
// Team 12: Minjun Kim(20190100), Hyewon Hwang(20200722)

// IMPORTANT: USAGE OF 2 TOKENS FOR EACH OF MEMBERS FOR LAB2

>> Data structures
1. socket_info : handles socket info
2. addr_entry : linked list entry to record bound addresses
3. syscall_entry : linked list entry containing syscall info, used for blocked syscall return
4. packet_info : linked list entry containing packet info
5. tcp_segment : raw byte-based container for packets

>> Implementing progress of Lab 2
1. Basics: socket(), bind(), getsockname(), close();
    - socket(): create file descriptor and associate it with a socket_info, append to all_sockets: the linked list of all sockets regardless of the status
    - bind(): bind given fd and address. store the binding info at an addr_entry, and append to bound_addrs
    - getsockname(): return host address of given socket
    - close(): remove file descriptor and free all allocated memories 
2. 3-way Handshake: listen(), accept(), connect(), packetArrived();
    - listen(): set backlog in the socket_info, and set status to TCP_LISTEN;
    - accept(): accept an established connection. 2 different behaviors as listed below
        (1) established connection exists:
            create a new file descriptor and it's socket info
            fill the socket info structure with the firstly established connection
            return the new file descriptor
        (2) No established connection:
            appends it's syscall entry to blocked_syscalls and waits until a SYN packet arrives
    - connect(): assign a random address for client, then send an SYN packet to the server
    - packetArrived(): handler function if packet is arrived: three types of packet transmissions implemented as listed below 
        (1) SYN: CLIENT-> SERVER [tcp status: (if sent) CLOSED->SYN_SENT // (if received) -]
            append the socket to the pending list, send SYN-ACK packet back to the client
        (2) SYN-ACK: SERVER-> CLIENT [tcp status: (if sent) TCP_LISTEN->TCP_SYN_RECV // (if received) -]
            return connect() as 0 (success) and send ACK packet back to the server
        (3) ACK: CLIENT -> SERVER[tcp status: (if sent) TCP_SYN_SENT->TCP_ESTABLISHED // (if received) TCP_SYN_RECV->TCP_ESTABLISHED]
            pop a socket from the pending list, append it to the established list, and if accept() is called, make a new socket and return its file descriptor to accept()  
    + getpeername(): return peer address of given socket
    + initialize/finalize: init all linked lists / free them, return -1 for all remaining syscalls in blocked_syscalls