#include <arpa/inet.h>
#include <netinet/ether.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>

#include <iostream>
#include <unordered_map>
#include <vector>

#define SIZE_ETHERNET 14
#define SIZE_IP 20
#define SIZE_UDP 8
#define SIZE_GRE 8

/* Ethernet header */
struct sniff_ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
  u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
  u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
  u_char ip_vhl;                 /* version << 4 | header length >> 2 */
  u_char ip_tos;                 /* type of service */
  u_short ip_len;                /* total length */
  u_short ip_id;                 /* identification */
  u_short ip_off;                /* fragment offset field */
  u_char ip_ttl;                 /* time to live */
  u_char ip_p;                   /* protocol */
  u_short ip_sum;                /* checksum */
  struct in_addr ip_src, ip_dst; /* source and dest address */
};

#define IP_RF 0x8000      /* reserved fragment flag */
#define IP_DF 0x4000      /* don't fragment flag */
#define IP_MF 0x2000      /* more fragments flag */
#define IP_OFFMASK 0x1fff /* mask for fragmenting bits */

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

void sniff(char *dev);
void parsePacket(u_char *args, const struct pcap_pkthdr *header,
                 const u_char *packet);
void parseEtherHdr(const struct sniff_ethernet *eth_hdr);
void parseIPHdr(const struct sniff_ip *ip_hdr);
void parseUDPHdr(const u_char *packet, int &sport, int &dport);
void parseGREHdr(const u_char *packet, int &proto, int &key);
void createTunnel(std::string ip, int port, int key);

std::unordered_map<int, int> tunnel;
std::string localhost = "140.113.0.2";
int gre_port = 33333;
int pkt = 0, gre = 0;
char filter_exp[500];

int main(int argc, char *argv[]) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevsp, *dev;
  std::vector<char *> devs;
  int id = 0;

  if (pcap_findalldevs(&alldevsp, errbuf) == -1) {
    std::cerr << "pcap_findalldevs: " << errbuf << std::endl;
    exit(EXIT_FAILURE);
  }

  for (dev = alldevsp; dev != NULL; dev = dev->next) {
    std::cout << id++ << " Name: " << dev->name << std::endl;
    devs.push_back(dev->name);
  }

  std::cout << "Insert a number to select interface" << std::endl;
  std::cin >> id;
  std::cout << "Start listening at $" << devs[id] << std::endl;

  std::getchar();
  std::cout << "Insert BPF filter expression" << std::endl;
  std::cin.getline(filter_exp, 50, '\n');
  std::cout << "filter: " << filter_exp << std::endl;

  sniff(devs[id]);
  pcap_freealldevs(alldevsp);

  exit(EXIT_SUCCESS);
}

void sniff(char *dev) {
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program filter;
  bpf_u_int32 net, mask;
  pcap_t *handle;

  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    std::cerr << "pcap_lookupnet: " << errbuf << std::endl;
    exit(EXIT_FAILURE);
  }

  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    std::cerr << "pcap_open_live: " << errbuf << std::endl;
    exit(EXIT_FAILURE);
  }

  while (true) {
    if (pcap_compile(handle, &filter, filter_exp, 0, net) == -1) {
      std::cerr << "pcap_compile: " << pcap_geterr(handle) << std::endl;
      exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &filter) == -1) {
      std::cerr << "pcap_setfilter: " << pcap_geterr(handle) << std::endl;
      exit(EXIT_FAILURE);
    }
    pcap_loop(handle, 1, parsePacket, NULL);
  }

  pcap_close(handle);
}

void parsePacket(u_char *args, const struct pcap_pkthdr *header,
                 const u_char *packet) {
  const struct sniff_ethernet *eth_hdr;
  const struct sniff_ip *ip_hdr;
  int sport, dport, proto, key;

  std::cout << "------------ Packet Num [" << ++pkt << "] ------------"
            << std::endl;

  /* Print Packet Byte Code */
  std::cout << "Packet Byte Code: " << std::endl;
  for (bpf_u_int32 i = 0; i < header->caplen; i++) {
    printf("%02x", packet[i]);
    if (i % 16 == 15 || i == header->caplen - 1) {
      std::cout << std::endl;
    } else if (i % 2) {
      std::cout << " ";
    }
  }
  std::cout << std::endl;

  /* Parse Outer Ethernet Header */
  std::cout << "Outer Ethernet Header: " << std::endl;
  eth_hdr = (struct sniff_ethernet *)(packet);
  parseEtherHdr(eth_hdr);

  /* Parse Outer IP Header */
  std::cout << "Outer IP Header: " << std::endl;
  ip_hdr = (struct sniff_ip *)(packet + SIZE_ETHERNET);
  parseIPHdr(ip_hdr);

  std::string ip_src = std::string(inet_ntoa(ip_hdr->ip_src));
  std::string ip_dst = std::string(inet_ntoa(ip_hdr->ip_dst));

  if (ip_hdr->ip_p != IPPROTO_UDP) {
    return;
  }

  /* Parse UDP Header */
  std::cout << "UDP Header: " << std::endl;
  parseUDPHdr(packet, sport, dport);

  if (sport != gre_port && dport != gre_port) {
    return;
  }

  /* Parse GRE Header */
  std::cout << "GRE Header: " << std::endl;
  parseGREHdr(packet, key, proto);

  /* Parse Inner Ethernet Header */
  std::cout << "Inner Ethernet Header: " << std::endl;
  eth_hdr = (struct sniff_ethernet *)(packet + SIZE_ETHERNET + SIZE_IP + SIZE_UDP + SIZE_GRE);
  parseEtherHdr(eth_hdr);

  /* Create Tunnel */
  if (tunnel.find(key) == tunnel.end() && ip_src != localhost) {
    createTunnel(ip_src, sport, key);
    strcat(filter_exp,
           (" and not (src host " + ip_src +
            " and src port " + std::to_string(sport) + ")" +
            " and not (dst host " + ip_src +
            " and dst port " + std::to_string(sport) + ")")
               .c_str());
  } else if (tunnel.find(key) == tunnel.end() && ip_dst != localhost) {
    createTunnel(ip_dst, dport, key);
    strcat(filter_exp,
           (" and not (src host " + ip_dst +
            " and dst port " + std::to_string(dport) + ")" +
            " and not (dst host " + ip_dst +
            " and dst port " + std::to_string(dport) + ")")
               .c_str());
  }
}

void parseEtherHdr(const struct sniff_ethernet *eth_hdr) {
  printf("Src MAC: %02x-%02x-%02x-%02x-%02x-%02x\n",
         eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
         eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
  printf("Dst MAC: %02x-%02x-%02x-%02x-%02x-%02x\n",
         eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
         eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

  switch (ntohs(eth_hdr->ether_type)) {
    case ETHERTYPE_IP:
      std::cout << "Ethernet Type: IPv4" << std::endl;
      break;
    case ETHERTYPE_IPV6:
      std::cout << "Ethernet Type: IPv6" << std::endl;
      break;
    case ETHERTYPE_ARP:
      std::cout << "Ethernet Type: ARP" << std::endl;
      break;
    case ETHERTYPE_REVARP:
      std::cout << "Ethernet Type: RARP" << std::endl;
      break;
    default:
      std::cout << "Ethernet Type: Others" << std::endl;
      break;
  }

  std::cout << std::endl;
}

void parseIPHdr(const struct sniff_ip *ip_hdr) {
  std::cout << "Src IP: " << inet_ntoa(ip_hdr->ip_src) << std::endl;
  std::cout << "Dst IP: " << inet_ntoa(ip_hdr->ip_dst) << std::endl;

  switch (ip_hdr->ip_p) {
    case IPPROTO_GRE:
      std::cout << "Next Layer Protocol: GRE" << std::endl;
      break;
    case IPPROTO_ICMP:
      std::cout << "Next Layer Protocol: ICMP" << std::endl;
      break;
    case IPPROTO_TCP:
      std::cout << "Next Layer Protocol: TCP" << std::endl;
      break;
    case IPPROTO_UDP:
      std::cout << "Next Layer Protocol: UDP" << std::endl;
      break;
    default:
      std::cout << "Next Layer Protocol: Others" << std::endl;
      break;
  }

  std::cout << std::endl;
}

void parseUDPHdr(const u_char *packet, int &sport, int &dport) {
  sport = 0, dport = 0;
  for (int i = 0; i < 2; i++) {
    if (i != 0) sport <<= 8;
    sport += *(packet + SIZE_ETHERNET + SIZE_IP + i);
  }
  for (int i = 0; i < 2; i++) {
    if (i != 0) dport <<= 8;
    dport += *(packet + SIZE_ETHERNET + SIZE_IP + 2 + i);
  }

  std::cout << "Src Port: " << sport << std::endl;
  std::cout << "Dst Port: " << dport << std::endl
            << std::endl;
}

void parseGREHdr(const u_char *packet, int &key, int &proto) {
  proto = 0, key = 0;
  for (int i = 0; i < 2; i++) {
    if (i != 0) proto <<= 8;
    proto += *(packet + SIZE_ETHERNET + SIZE_IP + SIZE_UDP + 2 + i);
  }
  for (int i = 0; i < 4; i++) {
    if (i != 0) key <<= 8;
    key += *(packet + SIZE_ETHERNET + SIZE_IP + SIZE_UDP + 4 + i);
  }

  if (proto == 0x6558) {
    std::cout << "Next Layer Protocol: Transparent Ethernet Bridging" << std::endl;
  } else {
    std::cout << "Next Layer Protocol: Others" << std::endl;
  }

  std::cout << "Key: " << key << std::endl
            << std::endl;
}

void createTunnel(std::string ip, int port, int key) {
  tunnel[key] = ++gre;

  std::vector<std::string> cmd;

  cmd.push_back("ip link add GRE" + std::to_string(gre) +
                " type gretap remote " + ip +
                " local " + localhost +
                " key " + std::to_string(key) +
                " encap fou encap-sport " + std::to_string(gre_port) +
                " encap-dport " + std::to_string(port));

  cmd.push_back("ip link set GRE" + std::to_string(gre) + " up");

  if (gre == 1) {
    cmd.push_back("ip fou add port " + std::to_string(gre_port) + " ipproto 47");
    cmd.push_back("ip link add br0 type bridge");
    cmd.push_back("ip link set BRGr-GWr master br0");
  }

  cmd.push_back("ip link set GRE" + std::to_string(gre) + " master br0");
  cmd.push_back("ip link set br0 up");

  for (auto &c : cmd) {
    if (system(c.c_str()) == -1) {
      std::cerr << c << std::endl;
      exit(EXIT_FAILURE);
    }
  }

  std::cout << "Tunnel finish" << std::endl
            << std::endl;
}