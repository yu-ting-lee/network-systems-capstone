#!/bin/sh

YELLOW='\033[1;33m'
NC='\033[0m'

# ------------------------------ RUN ONLY ONCE ------------------------------

# Build Docker Image and Container
# docker build -t base .
# docker run -it -d --cap-add=NET_ADMIN --name H1 --net=none --privileged base
# docker run -it -d --cap-add=NET_ADMIN --name H2 --net=none --privileged base
# docker run -it -d --cap-add=NET_ADMIN --name BRG1 --net=none --privileged base
# docker run -it -d --cap-add=NET_ADMIN --name BRG2 --net=none --privileged base
# docker run -it -d --cap-add=NET_ADMIN --name R1 --net=none --privileged base
# docker run -it -d --cap-add=NET_ADMIN --name R2 --net=none --privileged base
# docker run -it -d --cap-add=NET_ADMIN --name BRGr --net=none --privileged base

# Direct Outbound Packet
# iptables -t nat -A POSTROUTING -s 20.0.0.0/8 ! -o GWr -j MASQUERADE

# ----------------------------- INITIALIZATION ------------------------------

# Fix
iptables -P FORWARD ACCEPT

# Reset
docker container stop $(docker ps -a -q)
ip link set br0 down
ip link del br0
ip link set GWr down
ip link del GWr

docker container start H1
docker container start H2
docker container start BRG1
docker container start BRG2
docker container start R1
docker container start R2
docker container start BRGr

echo "${YELLOW}Initialization Done${NC}"

# ----------------------------- CREATE TOPOLOGY -----------------------------

# Connect H1 & BRG1
ip link add H1-BRG1 type veth peer name BRG1-H1
ip link set H1-BRG1 netns $(docker inspect -f '{{.State.Pid}}' H1)
ip link set BRG1-H1 netns $(docker inspect -f '{{.State.Pid}}' BRG1)
docker exec H1 ip link set H1-BRG1 up
docker exec BRG1 ip link set BRG1-H1 up

# Connect H2 & BRG2
ip link add H2-BRG2 type veth peer name BRG2-H2
ip link set H2-BRG2 netns $(docker inspect -f '{{.State.Pid}}' H2)
ip link set BRG2-H2 netns $(docker inspect -f '{{.State.Pid}}' BRG2)
docker exec H2 ip link set H2-BRG2 up
docker exec BRG2 ip link set BRG2-H2 up

# Connect BRG1/BRG2/R1 & br0
ip link add br0 type bridge
ip link add BRG1-br0 type veth peer name br0-BRG1
ip link set BRG1-br0 netns $(docker inspect -f '{{.State.Pid}}' BRG1)
ip link set br0-BRG1 master br0
docker exec BRG1 ip link set BRG1-br0 up
ip link set br0-BRG1 up

ip link add BRG2-br0 type veth peer name br0-BRG2
ip link set BRG2-br0 netns $(docker inspect -f '{{.State.Pid}}' BRG2)
ip link set br0-BRG2 master br0
docker exec BRG2 ip link set BRG2-br0 up
ip link set br0-BRG2 up

ip link add R1-br0 type veth peer name br0-R1
ip link set R1-br0 netns $(docker inspect -f '{{.State.Pid}}' R1)
ip link set br0-R1 master br0
docker exec R1 ip link set R1-br0 up
ip link set br0-R1 up
ip link set br0 up

# Connect R1 & R2
ip link add R1-R2 type veth peer name R2-R1
ip link set R1-R2 netns $(docker inspect -f '{{.State.Pid}}' R1)
ip link set R2-R1 netns $(docker inspect -f '{{.State.Pid}}' R2)
docker exec R1 ip link set R1-R2 up
docker exec R2 ip link set R2-R1 up

# Connect R2 & BRGr
ip link add R2-BRGr type veth peer name BRGr-R2
ip link set R2-BRGr netns $(docker inspect -f '{{.State.Pid}}' R2)
ip link set BRGr-R2 netns $(docker inspect -f '{{.State.Pid}}' BRGr)
docker exec R2 ip link set R2-BRGr up
docker exec BRGr ip link set BRGr-R2 up

# Connect BRGr & GWr
ip link add GWr type bridge
ip link add BRGr-GWr type veth peer name GWr-BRGr
ip link set BRGr-GWr netns $(docker inspect -f '{{.State.Pid}}' BRGr)
ip link set GWr-BRGr master GWr
docker exec BRGr ip link set BRGr-GWr up
ip link set GWr-BRGr up
ip link set GWr up

echo "${YELLOW}Create Topology Done${NC}"

# ------------------------------ CONFIGURATION ------------------------------

# Setup R1
docker exec R1 ip addr add 172.27.0.1/24 dev R1-br0
docker exec R1 ip addr add 140.114.0.1/24 dev R1-R2
docker cp R1/dhcpd.conf R1:/etc/dhcp/
docker exec R1 rm -f /var/run/dhcpd.pid
docker exec R1 service isc-dhcp-server start >/dev/null

# Setup R2
docker exec R2 ip addr add 140.114.0.2/24 dev R2-R1
docker exec R2 ip addr add 140.113.0.1/24 dev R2-BRGr

# Setup BRGr
docker exec BRGr ip addr add 140.113.0.2/24 dev BRGr-R2
docker exec BRGr ip addr add 20.0.0.2/8 dev BRGr-GWr

# Setup GWr
ip addr add 20.0.0.1/8 dev GWr

# Setup BRG1/BRG2
docker exec BRG1 ip addr add 20.0.0.3/8 dev BRG1-H1
docker exec BRG1 dhclient BRG1-br0
docker exec BRG2 ip addr add 20.0.0.4/8 dev BRG2-H2
docker exec BRG2 dhclient BRG2-br0

# Setup NAT
BRG1_addr=$(docker exec BRG1 ip -br addr show BRG1-br0 | awk '{print $3}' | sed 's/\/.*//g')
docker exec R1 iptables -t nat -A POSTROUTING -p udp -s "$BRG1_addr" -o R1-R2 -j SNAT --to-source 140.114.0.1:11111
docker exec R1 iptables -t nat -A PREROUTING -p udp -d 140.114.0.1 --dport 11111 -j DNAT --to-destination "$BRG1_addr":11111
BRG2_addr=$(docker exec BRG2 ip -br addr show BRG2-br0 | awk '{print $3}' | sed 's/\/.*//g')
docker exec R1 iptables -t nat -A POSTROUTING -p udp -s "$BRG2_addr" -o R1-R2 -j SNAT --to-source 140.114.0.1:22222
docker exec R1 iptables -t nat -A PREROUTING -p udp -d 140.114.0.1 --dport 22222 -j DNAT --to-destination "$BRG2_addr":22222

# Setup Routing Rules
docker exec R1 ip route add 140.113.0.0/24 via 140.114.0.2
docker exec BRGr ip route add 140.114.0.0/24 via 140.113.0.1

# Setup Static GRE
modprobe fou
docker exec BRG1 ip link add GRE type gretap remote 140.113.0.2 local "$BRG1_addr" key 1 encap fou encap-sport 11111 encap-dport 33333
docker exec BRG1 ip link set GRE up
docker exec BRG1 ip fou add port 11111 ipproto 47
docker exec BRG1 ip link add br0 type bridge
docker exec BRG1 ip link set GRE master br0
docker exec BRG1 ip link set BRG1-H1 master br0
docker exec BRG1 ip link set br0 up

docker exec BRG2 ip link add GRE type gretap remote 140.113.0.2 local "$BRG2_addr" key 2 encap fou encap-sport 22222 encap-dport 33333
docker exec BRG2 ip link set GRE up
docker exec BRG2 ip fou add port 22222 ipproto 47
docker exec BRG2 ip link add br0 type bridge
docker exec BRG2 ip link set GRE master br0
docker exec BRG2 ip link set BRG2-H2 master br0
docker exec BRG2 ip link set br0 up

# docker exec BRGr ip link add GRE1 type gretap remote 140.114.0.1 local 140.113.0.2 key 1 encap fou encap-sport 33333 encap-dport 11111
# docker exec BRGr ip link set GRE1 up
# docker exec BRGr ip link add GRE2 type gretap remote 140.114.0.1 local 140.113.0.2 key 2 encap fou encap-sport 33333 encap-dport 22222
# docker exec BRGr ip link set GRE2 up
# docker exec BRGr ip fou add port 33333 ipproto 47
# docker exec BRGr ip link add br0 type bridge
# docker exec BRGr ip link set GRE1 master br0
# docker exec BRGr ip link set GRE2 master br0
# docker exec BRGr ip link set BRGr-GWr master br0
# docker exec BRGr ip link set br0 up

# Setup Dynamic GRE
make
docker cp gre_fou BRGr:/tmp/
docker exec BRGr chmod +x /tmp/gre_fou

echo "${YELLOW}Configuration Done${NC}"

# --------------------------------- EXECUTE ---------------------------------

# Setup H1/H2
cp GWr/dhcpd.conf /etc/dhcp/
service isc-dhcp-server restart
# docker exec H1 dhclient H1-BRG1
# docker exec H2 dhclient H2-BRG2

echo "${YELLOW}vCPE is working now...${NC}"
