# CS341 Network

> 2022 Spring KAIST CS341 Intro to Computer Networks (Prof. Sue Bok Moon)
>
> [Course Github][CourseGithub] | [Github][Github] | [Notion][Notion]
>
> Programming Assignment Instructions (Due Date): [PA1][PA1](29th March), PA2, PA3, PA4
> 
> Lab by [Minjun Kim][HoneyTt21], [Hyewon Hwang][hywnH]

### Commit Message Template
- Happy: 뭔가 달성
- Sorry: 여기까지 하다 막힘

### TA Help
- For QnA, use [Github Discussion][GithubDis]


[CourseGithub]: https://github.com/ANLAB-KAIST/KENSv3
[Github]: https://github.com/HoneyTt21/CS341
[Notion]: https://honeytt21.notion.site/Network-685a433332ae4e4fa654d3e67b6288a9
[HoneyTt21]: https://github.com/HoneyTt21
[hywnH]: https://github.com/hywnH
[GithubDis]: https://github.com/ANLAB-KAIST/KENSv3/discussions
[PA1]: https://docs.google.com/document/d/1b51kyY07EDfP8KI4injuz6JOgKzTWAgH6gTgNhsVa7E/edit#


# KENSv3 (KAIST Educational Network System)

[![Test Linux Environment](https://github.com/ANLAB-KAIST/KENSv3/actions/workflows/test-linux.yml/badge.svg)](https://github.com/ANLAB-KAIST/KENSv3/actions/workflows/test-linux.yml) [![Test Linux Extra Environments](https://github.com/ANLAB-KAIST/KENSv3/actions/workflows/test-linux-extra.yml/badge.svg)](https://github.com/ANLAB-KAIST/KENSv3/actions/workflows/test-linux-extra.yml)  [![Test WSL Environment](https://github.com/ANLAB-KAIST/KENSv3/actions/workflows/test-wsl.yml/badge.svg)](https://github.com/ANLAB-KAIST/KENSv3/actions/workflows/test-wsl.yml) [![Test macOS Environment](https://github.com/ANLAB-KAIST/KENSv3/actions/workflows/test-macos.yml/badge.svg)](https://github.com/ANLAB-KAIST/KENSv3/actions/workflows/test-macos.yml)

KENS series have been used for programming assignment in CS341: Introduction to Computer Network in KAIST.
First version of KENS (v1) had been developed by Network Computing Lab, 2005.
This version had been used until 2013.

KENSv2 is an improvement version from KENSv1, which contains basic unit test mechanism.
Since KENSv2, we provided students an adversary solution which work along with students' solution.
This solution was provided in binary form, and enabled incremental development of network functionalities.
For example, we had to implement both connect and accept for basic execution.
From KENSv2, the implementation could be modularized in system call level.
This version was used in 2014 (https://an.kaist.ac.kr/courses/2014/cs341/) and the experience of using it
has been published at SIGCSE 2015 (http://an.kaist.ac.kr/~sbmoon/paper/intl-conf/2015-sigcse-kensv2.pdf).
The source code is managed by Advanced Networking Lab in KAIST.

KENSv1:
https://github.com/ANLAB-KAIST/KENSv1

KENSv2:
https://github.com/ANLAB-KAIST/KENSv2

From 2015, we are using KENSv3 which is developed from a clean state.
However its philosophy has been adopted from KENSv2 and KENSv1.
KENSv3 has more powerful features than KENSv2.
 
 - POSIX equivalent system call layer.
 - Equivalent simulation power against ns2.
 - Modular architecture for multiple protocol layers to work together.

# What is KENSv3?
## KENSv3 is an educational framework.
KENSv3 provides useful template for building prototypes of
Ethernet/ARP/IP/TCP and many other network layers.
Also, it contains automated grading system to verify the completeness of each implementation.
There are solution binaries in KENSv3 which enables incremental building of network functions.

## KENSv3 is a network simulator
Virtual network devices of KENSv3 simulates queuing effect of switched network.
So it can be used for precise network simulations like ns2.
All packets are recorded as pcap log files which can be analyzed by Wireshark or other analysis tools.

## KENSv3 is a virtual execution environment
KENSv3 can execute actual network application source written in C.
The system call requests from applications are linked with proper network layer.

# How to run KENSv3?

See [KENSv3 wiki](https://github.com/ANLAB-KAIST/KENSv3/wiki).

# How to do KENSv3 project?
## Template source
In TestTCP folder, there are one source file and one header file.
You are allowed to modify TCPAssignment.cpp and TCPAssignment.hpp.
Also, you can add member fields to "class TCPAssignment".
Any source files in TestTCP folder are automatically included in the build path.

## What you have to do?
1. Handling system calls
See the documentation for how to handle with blocking system calls.

2. Context management
You have to manage a global context (usually member variables of TCPAssignment).
Also, you have to split incoming packets and system call requests.
Use IP address and port number for classifying packets,
and pid(process id) and fd(file descriptor number) for classifying application sockets.
Until here is part 1.

3. Handshaking
Implement 3-way handshaking for connect/accept and
4-way handshaking for close.
Until here is part 2.

3. Flow control
You may block read/write calls if you have no data from TCP window or you TCP window is full.
Handle with read/write and generate/process proper TCP packets for data transmission.
Until here is part 3.

4. Recovery
You have to handle with losses, reorders, and packet corruption.

5. Congestion control
Implement AIMD congestion control mechanism for part 4.
You can observe convergence graph from pcap logs.
If you did not implement congestion control algorithm, you may not pass part 4.
There would be retransmission storms and applications may not finish in time.
Until here is part 4.

## How to contribute?
This is an automatically generated source repository from our internal repository.
If you want to contribute to KENSv3 framework,
please use [Github issues](https://github.com/ANLAB-KAIST/KENSv3/issues).

## Requests to students
KENSv3 is an open-source framework. However, it is also an educational framework.
We couldn't get our position between them.
We are asking your favor not to make a public fork, but a private clone for your project.
Please do not upload your solutions online, so that other students can do this project themselves later.

## Requests to instructors
You may modify it freely to customize this project with your courses.
Not only the source contribution, we also receive material contribution.
If you have better presentation slides or other teaching material, you can contribute with them.
Please let your students not to upload their solutions online.
