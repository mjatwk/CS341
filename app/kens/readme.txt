// 2022 Spring CS341 Introduction to Computer Networks 
// readme.txt on Lab2
// Team 12: Minjun Kim(20190100), Hyewon Hwang(20200722)

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