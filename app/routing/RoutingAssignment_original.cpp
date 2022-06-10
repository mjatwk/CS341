/*
 * E_RoutingAssignment.cpp
 *
 */

#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

#include "RoutingAssignment.hpp"

// true if dealing with extra
#define EXTRA false
#define TIMEOUT 1000000000 // 1s
namespace E {

RoutingAssignment::RoutingAssignment(Host &host)
    : HostModule("UDP", host), RoutingInfoInterface(host),
      TimerModule("UDP", host) {}

RoutingAssignment::~RoutingAssignment() {}

// cyclic linked list containing all dist_entry
struct dist_entry *all_dist_entry;
int total_dist_cnt;

int min(int a, int b) { return a < b ? a : b; }

uint16_t convert_2byte(uint16_t ori) { return (ori << 8) | (ori >> 8); }

uint32_t convert_4byte(uint32_t ori) {
  return ((ori << 24) & 0xFF000000) | ((ori << 8) & 0x00FF0000) |
         ((ori >> 8) & 0x0000FF00) | ((ori >> 24) & 0x000000FF);
}

// convert ipv4_t IPV4 to int32_t
int32_t ipv4toint32(ipv4_t ipv4) {
  return (int32_t)(ipv4[0] << 24) + (ipv4[1] << 16) + (ipv4[2] << 8) + ipv4[3];
}

// convert int32_t INT32 to ipv4_t
ipv4_t int32toipv4(int32_t int32) {
  ipv4_t ret;
  ret[0] = int32 >> 24;
  ret[1] = int32 << 8 >> 24;
  ret[2] = int32 << 16 >> 24;
  ret[3] = int32 << 24 >> 24;
  return ret;
}

// print all dist_entry in all_dist_entry
void iterate_dist_entry() {
  for (dist_entry *cur = all_dist_entry->next; cur != all_dist_entry;
       cur = cur->next) {
    printf("ip: %d, %d, %d, %d, metric: %d\n", cur->ipv4[0], cur->ipv4[1],
           cur->ipv4[2], cur->ipv4[3], cur->metric);
  }
}

// return a.b.c.d
ipv4_t get_ipv4(int a, int b, int c, int d) {
  ipv4_t ret;
  ret[0] = a;
  ret[1] = b;
  ret[2] = c;
  ret[3] = d;
  return ret;
}

// if two ipv4_t FST and SND is same return true, if not false
bool compare_ipv4(ipv4_t fst, ipv4_t snd) {
  if (fst[0] == snd[0] && fst[1] == snd[1] && fst[2] == snd[2] &&
      fst[3] == snd[3]) {
    return true;
  }
  return false;
}

// return the pair ip of IPV4 of the given line
ipv4_t get_pair_ipv4(ipv4_t ipv4) {
  ipv4_t ip = ipv4;
  if (ip[3] == 1) {
    ip[3] = 2;
  } else if (ip[3] == 2) {
    ip[3] = 1;
  } else {
    printf("get_pair_ipv4 error: %d, %d, %d, %d \n", ipv4[0], ipv4[1], ipv4[2],
           ipv4[3]);
    assert(false);
  }
  return ip;
}

// return max metric for both extra and non-extra
int get_infinite_metric(bool extra) {
  if (!extra) {
    return 16;
  } else {
    // for extra
    return 300;
  }
}

// return metric of adjacent node IPV4, which is 1 for non-extra
int get_adjacent_metric(ipv4_t ipv4, bool extra) {
  if (!extra) {
    return 1;
  } else {
    // for extra
    assert(false);
  }
}

// return metric of IPV4 from current table
int get_metric(ipv4_t ipv4) {
  for (dist_entry *cur = all_dist_entry->next; cur != all_dist_entry;
       cur = cur->next) {
    if (compare_ipv4(cur->ipv4, ipv4)) {
      return cur->metric;
    }
  }
  return get_infinite_metric(false);
}

// return UDP packet-IP header, UDP header, RIPv1 header written
Packet prepare_packet(ipv4_t src_ipv4, ipv4_t dst_ipv4, int8_t command,
                      int rip_entry_cnt) {
  Packet pkt(1500);
  int16_t udp_port = convert_2byte(520);
  int16_t checksum = 0; // omit checksum
  int8_t version = 1;
  int16_t zero = 0;

  int length = 46 + 20 * rip_entry_cnt;
  // 34 bytes for header, 8 bytes for UDP header, 4 bytes for RIPv1 header
  pkt.setSize(length);
  length = convert_2byte(length);

  // IP dest
  int32_t src_addr = convert_4byte(ipv4toint32(src_ipv4));
  int32_t dst_addr = convert_4byte(ipv4toint32(dst_ipv4));
  pkt.writeData(26, &src_addr, 4);
  pkt.writeData(30, &dst_addr, 4);

  // UDP header
  int udp_start = 34;
  pkt.writeData(udp_start + 0, &udp_port, 2);
  pkt.writeData(udp_start + 2, &udp_port, 2);
  pkt.writeData(udp_start + 4, &length, 2);
  pkt.writeData(udp_start + 6, &checksum, 2);

  // RIPv1
  pkt.writeData(udp_start + 8, &command, 1);
  pkt.writeData(udp_start + 9, &version, 1);
  pkt.writeData(udp_start + 10, &zero, 2);

  return pkt;
}

// write one rip_entry ENTRY to as INDEX-th entry in PKT
Packet write_rip_packet(Packet pkt, rip_entry_t entry, int index) {
  int entry_start = 46 + 20 * index;
  int address_family = convert_2byte(entry.address_family);
  int ip_addr = convert_4byte(entry.ip_addr);
  int metric = convert_4byte(entry.metric);
  printf("write index %d: ip_addr: %d, metric: %d\n", index, ip_addr,
         convert_4byte(metric));
  pkt.writeData(entry_start + 0, &address_family, 2);
  pkt.writeData(entry_start + 2, &entry.zero_1, 2);
  pkt.writeData(entry_start + 4, &ip_addr, 4);
  pkt.writeData(entry_start + 8, &entry.zero_2, 4);
  pkt.writeData(entry_start + 12, &entry.zero_3, 4);
  pkt.writeData(entry_start + 16, &metric, 4);

  return pkt;
}

// find dist_entry from all_dist_entry by IPV4
// if none found, append new entry with given IPV4
dist_entry *get_dist_entry(ipv4_t ipv4) {
  for (dist_entry *cur = all_dist_entry->next; cur != all_dist_entry;
       cur = cur->next) {
    if (compare_ipv4(cur->ipv4, ipv4)) {
      return cur;
    }
  }
  dist_entry *temp = (dist_entry *)malloc(sizeof(dist_entry));
  temp->ipv4 = ipv4;
  temp->metric = get_infinite_metric(EXTRA);
  temp->prev = all_dist_entry->prev;
  temp->next = all_dist_entry;
  all_dist_entry->prev->next = temp;
  all_dist_entry->prev = temp;
  total_dist_cnt++;
  return temp;
}

void RoutingAssignment::initialize() {

  Packet pkt(1500);

  // init
  all_dist_entry = (dist_entry *)malloc(sizeof(dist_entry));
  all_dist_entry->prev = all_dist_entry;
  all_dist_entry->next = all_dist_entry;

  total_dist_cnt = 0;

  // send first request
  // address family id as 0, IP addr as 0, metric as 16
  // then start timer
  rip_t rip;
  rip.header.command = 1;
  rip.header.version = 1;

  printf("init\n");

  for (int k = 0; k < 10; k++) {
    std::optional<ipv4_t> ip = getIPAddr(k);
    if (ip) {
      printf("ip: %d, %d, %d, %d, port: %d\n", ip.value().at(0),
             ip.value().at(1), ip.value().at(2), ip.value().at(3), k);

      // prepare two dist_entry
      dist_entry *temp_self = (dist_entry *)malloc(sizeof(dist_entry));
      temp_self->ipv4 = ip.value();
      temp_self->metric = 0;

      // dist_entry *temp_pair = (dist_entry *)malloc(sizeof(dist_entry));
      // ip = get_pair_ipv4(ip.value());

      // temp_pair->ipv4 = ip.value();
      // temp_pair->metric = get_adjacent_metric(ip.value(), EXTRA);

      // append both to to all_dist_entry
      temp_self->prev = all_dist_entry->prev;
      temp_self->next = all_dist_entry;
      all_dist_entry->prev->next = temp_self;
      all_dist_entry->prev = temp_self;
      // temp_self->prev = all_dist_entry->prev;
      // temp_self->next = temp_pair;
      // temp_pair->prev = temp_self;
      // temp_pair->next = all_dist_entry;
      // all_dist_entry->prev->next = temp_self;
      // all_dist_entry->prev = temp_pair;

      total_dist_cnt++;
    }
  }
  int32_t dst_addr;
  ipv4_t dst_ipv4;
  // send request for all different interfaces
  for (dist_entry *cur = all_dist_entry->next; cur != all_dist_entry;
       cur = cur->next) {
    if (cur->metric == 0) {
      // pkt = prepare_packet(cur->ipv4, get_pair_ipv4(cur->ipv4), 1, 1);
      pkt = prepare_packet(cur->ipv4, get_ipv4(255, 255, 255, 255), 1, 1);
      rip_entry_t *rip_entry = (rip_entry_t *)malloc(sizeof(rip_entry));
      memset(rip_entry, 0, sizeof(rip_entry));
      rip_entry->address_family = 0;
      rip_entry->ip_addr = 0;
      rip_entry->metric = get_infinite_metric(EXTRA);
      pkt = write_rip_packet(pkt, *rip_entry, 0);

      pkt.readData(30, &dst_addr, 4);
      dst_ipv4 = int32toipv4(convert_4byte(dst_addr));
      printf("packet sent-ip: %d, %d, %d, %d to %d, %d, %d, %d\n", cur->ipv4[0],
             cur->ipv4[1], cur->ipv4[2], cur->ipv4[3], dst_ipv4[0], dst_ipv4[1],
             dst_ipv4[2], dst_ipv4[3]);
      sendPacket("IPv4", std::move(pkt));
      free(rip_entry);
    }
    // start timer
    addTimer(cur->ipv4, TIMEOUT);
  }
}

void RoutingAssignment::finalize() {
  // free all allocated memories
  // for (dist_entry *cur = all_dist_entry->next; cur != all_dist_entry;
  //      cur = cur->next) {
  //   free(cur);
  // }
}

/**
 * @brief Query cost for a host
 *
 * @param ipv4 querying host's IP address
 * @return cost or -1 for no found host
 */
Size RoutingAssignment::ripQuery(const ipv4_t &ipv4) {
  printf("rip query start: %d, %d, %d, %d\n", ipv4[0], ipv4[1], ipv4[2],
         ipv4[3]);
  // return hop-count to reach the IP address
  for (dist_entry *cur = all_dist_entry->next; cur != all_dist_entry;
       cur = cur->next) {
    if (compare_ipv4(cur->ipv4, ipv4)) {
      return cur->metric;
    }
  }
  return get_infinite_metric(EXTRA);
}

void RoutingAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  int32_t src_addr;
  int32_t dst_addr;
  rip_header_t rip_header;
  int16_t pkt_length;
  ipv4_t cur_ipv4;
  dist_entry *cur_dist_entry;
  int index;

  Packet pkt(1500);

  // IP addr
  packet.readData(26, &src_addr, 4);
  packet.readData(30, &dst_addr, 4);
  packet.readData(38, &pkt_length, 2);
  packet.readData(42, &rip_header, 4);

  src_addr = convert_4byte(src_addr);
  dst_addr = convert_4byte(dst_addr);
  pkt_length = convert_2byte(pkt_length);

  ipv4_t src_ipv4 = int32toipv4(src_addr);
  ipv4_t dst_ipv4 = int32toipv4(dst_addr);
  int entry_cnt = (pkt_length - 46) / 20;

  printf("%s pkt arrived from %d, %d, %d, %d to %d, %d, %d, %d, length: %d\n",
         rip_header.command == 1 ? "request" : "response", src_ipv4[0],
         src_ipv4[1], src_ipv4[2], src_ipv4[3], dst_ipv4[0], dst_ipv4[1],
         dst_ipv4[2], dst_ipv4[3], pkt_length);
  iterate_dist_entry();

  rip_entry_t rip_entries[entry_cnt];

  for (int p = 0; p < entry_cnt; p++) {
    packet.readData(46 + 20 * p, &rip_entries[p], 20);
  }

  if (rip_header.command == 1) {
    printf("pkt com 1\n");
    // if receive a request, send distance vector table to the request sender
    assert(entry_cnt = 1);
    // assert(compare_ipv4(dst_ipv4, get_ipv4(255, 255, 255, 255)));

    printf("send response\n");

    // send response for all different interfaces
    for (dist_entry *cur = all_dist_entry->next; cur != all_dist_entry;
         cur = cur->next) {
      if (cur->metric == 0) {
        pkt = prepare_packet(cur->ipv4, src_ipv4, 2, total_dist_cnt);
        index = 0;
        for (dist_entry *curr = all_dist_entry->next; curr != all_dist_entry;
             curr = curr->next) {
          rip_entry_t *rip_entry = (rip_entry_t *)malloc(sizeof(rip_entry));
          memset(rip_entry, 0, sizeof(rip_entry));
          rip_entry->address_family = 2;
          rip_entry->ip_addr = ipv4toint32(curr->ipv4);
          rip_entry->metric = curr->metric;
          pkt = write_rip_packet(pkt, *rip_entry, index++);
          free(rip_entry);
        }
        printf("pkt com 1-pkt sent ip: %d, %d, %d, %d to %d, %d, %d, %d\n",
               cur->ipv4[0], cur->ipv4[1], cur->ipv4[2], cur->ipv4[3],
               src_ipv4[0], src_ipv4[1], src_ipv4[2], src_ipv4[3]);
        sendPacket("IPv4", std::move(pkt));
      }
    }
  } else if (rip_header.command == 2) {
    printf("pkt com 2-entry_cnt: %d\n", entry_cnt);
    // if receive a response, update the distance vector table
    for (int p = 0; p < entry_cnt; p++) {
      cur_ipv4 = int32toipv4(rip_entries[p].ip_addr);
      cur_dist_entry = get_dist_entry(this->all_dist_entry, cur_ipv4);
      this->total_dist_cnt++;
      cur_dist_entry->metric =
          min(cur_dist_entry->metric,
              rip_entries[p].metric + get_metric(int32toipv4(src_addr)));
      printf("compare cur: %d and new1: %d + new2: %d\n",
             cur_dist_entry->metric, rip_entries[p].metric,
             get_metric(int32toipv4(src_addr)));
    }
  } else {
    // error
    assert(false);
  }
}

void RoutingAssignment::timerCallback(std::any payload) {
  printf("timer fin\n");
  int index;

  Packet pkt(1500);

  ipv4_t timer_ipv4 = std::any_cast<ipv4_t>(payload);

  pkt = prepare_packet(timer_ipv4, get_ipv4(255, 255, 255, 255), 2,
                       total_dist_cnt);
  // broadcast a response with current distance vector table
  index = 0;
  for (dist_entry *curr = all_dist_entry->next; curr != all_dist_entry;
       curr = curr->next) {
    if (curr->metric == 0) {
      continue;
    }
    rip_entry_t *rip_entry = (rip_entry_t *)malloc(sizeof(rip_entry));
    memset(rip_entry, 0, sizeof(rip_entry));
    rip_entry->address_family = 2;
    rip_entry->ip_addr = ipv4toint32(curr->ipv4);
    rip_entry->metric = curr->metric;
    pkt = write_rip_packet(pkt, *rip_entry, index++);
    free(rip_entry);
  }
  sendPacket("IPv4", std::move(pkt));
}

} // namespace E
