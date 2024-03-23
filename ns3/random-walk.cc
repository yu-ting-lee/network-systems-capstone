#include "ns3/applications-module.h"
#include "ns3/bridge-helper.h"
#include "ns3/command-line.h"
#include "ns3/config.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/log.h"
#include "ns3/mobility-helper.h"
#include "ns3/mobility-model.h"
#include "ns3/ssid.h"
#include "ns3/wifi-module.h"
#include "ns3/yans-wifi-channel.h"
#include "ns3/yans-wifi-helper.h"

using namespace ns3;

typedef struct {
  int index;
  double rad, speed;
} MOVE;

typedef struct {
  int fragment;
  double x;
  double y;
} STEP;

std::vector<Vector> boundary;
NS_LOG_COMPONENT_DEFINE("RandomWalk");

// OpenFile / GetBoundary are examples for loading target data.
// You can implement your own OpenFile / GetBoundary / or other functions as you
// like.
FILE *OpenFile(char *fileName);
std::vector<Vector> GetBoundary(FILE *fp);
MOVE GetSingleMovement(FILE *fp);
void CheckLinkState(Ptr<Node> node);
void Movement(FILE *fp, std::vector<Vector> &boundary, Ptr<Node> node,
              STEP &step, double stepsTime);
void PrintIllegalMsg(int index);

int main(int argc, char *argv[]) {
  std::string phyMode("DsssRate1Mbps");
  double frequency = 2.43 * 1e9;  // center frequency, Hz
  bool verbose = false;
  uint32_t packetSize = 1024;
  double interval = 1.0;
  double stepsSize = 0.0;
  double stepsTime = 0.2;
  double txPower = 3;
  double snrThreshold = 20.0;
  double ap1Position = 80.0, ap2Position = 120.0;
  char movementFile[64] = {'\0'};
  strcpy(movementFile,
         "testcase_1");  // default path: ~/workspace/ns-allinone-3.32/ns-3.32/

  CommandLine cmd(__FILE__);
  cmd.AddValue("verbose", "turn on all WifiNetDevice log components", verbose);
  cmd.AddValue("packetSize", "size of application packet sent (bytes)",
               packetSize);
  cmd.AddValue("interval", "interval (seconds) between packets", interval);
  cmd.AddValue("txPower", "the transimission power of the access points",
               txPower);
  cmd.AddValue("stepsSize", "the step size of echo client", stepsSize);
  cmd.AddValue("stepsTime", "the period of echo client's movement", stepsTime);
  cmd.AddValue("snrThreshold", "threshold of the signal quality (dB)",
               snrThreshold);
  cmd.AddValue("ap1Position", "AP1 is at (ap1Position, 80.0, 2.5)",
               ap1Position);
  cmd.AddValue("ap2Position", "AP2 is at (ap2Position, 80.0, 2.5)",
               ap2Position);
  cmd.AddValue("fileName", "file name of movement file", movementFile);

  cmd.Parse(argc, argv);

  boundary.clear();

  // basic node setup
  // [index, node]:
  // wirelessNode: [0, echo client], [1, ap1], [2, ap2]
  // csmaNode: [0, echo server], [1, ap1], [2, ap2]
  NodeContainer wirelessNodes;
  wirelessNodes.Create(3);
  NodeContainer csmaNodes;
  csmaNodes.Create(1);
  csmaNodes.Add(wirelessNodes.Get(1));
  csmaNodes.Add(wirelessNodes.Get(2));

  // ethernet setup
  CsmaHelper csma;
  csma.SetChannelAttribute("DataRate", StringValue("100Mbps"));
  csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(6560)));
  NetDeviceContainer csmaDevices;
  csmaDevices = csma.Install(csmaNodes);

  // wireless setup
  WifiHelper wifi;
  if (verbose) {
    wifi.EnableLogComponents();  // Turn on all Wifi logging
  }
  wifi.SetStandard(WIFI_STANDARD_80211b);

  // physical layer setup
  YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default();
  wifiPhy.Set("TxPowerStart", DoubleValue(txPower));
  wifiPhy.Set("TxPowerEnd", DoubleValue(txPower));
  wifiPhy.SetPcapDataLinkType(WifiPhyHelper::DLT_IEEE802_11_RADIO);

  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss("ns3::FriisPropagationLossModel", "Frequency",
                                 DoubleValue(frequency), "SystemLoss",
                                 DoubleValue(10.0));
  wifiPhy.SetChannel(wifiChannel.Create());

  // mac layer setup
  WifiMacHelper wifiMac;
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode",
                               StringValue(phyMode), "ControlMode",
                               StringValue(phyMode));
  Ssid ssid = Ssid("wifi-default");
  wifiMac.SetType("ns3::StaWifiMac", "Ssid", SsidValue(ssid), "SNR_Threshold",
                  DoubleValue(snrThreshold), "ActiveProbing",
                  BooleanValue(true));

  NetDeviceContainer staDevice =
      wifi.Install(wifiPhy, wifiMac, wirelessNodes.Get(0));
  NetDeviceContainer wirelessDevices = staDevice;

  wifiMac.SetType("ns3::ApWifiMac", "Ssid", SsidValue(ssid));
  NetDeviceContainer apDevice =
      wifi.Install(wifiPhy, wifiMac, wirelessNodes.Get(1));
  wirelessDevices.Add(apDevice);

  NetDeviceContainer apDevice2 =
      wifi.Install(wifiPhy, wifiMac, wirelessNodes.Get(2));
  wirelessDevices.Add(apDevice2);

  BridgeHelper bridge;
  NetDeviceContainer bridgeDev, bridgeDev2;
  bridgeDev = bridge.Install(wirelessNodes.Get(1),
                             NetDeviceContainer(apDevice, csmaDevices.Get(1)));
  bridgeDev2 = bridge.Install(
      wirelessNodes.Get(2), NetDeviceContainer(apDevice2, csmaDevices.Get(2)));

  // set wireless nodes' position
  MobilityHelper mobility;
  Ptr<ListPositionAllocator> positionAlloc =
      CreateObject<ListPositionAllocator>();
  positionAlloc->Add(Vector(65.0, 80.0, 0.0));
  positionAlloc->Add(Vector(ap2Position, 80.0, 2.5));
  positionAlloc->Add(Vector(ap1Position, 80.0, 2.5));
  mobility.SetPositionAllocator(positionAlloc);
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(wirelessNodes);

  // aggregate TCP/IP functionality to existing nodes
  InternetStackHelper internet;
  internet.Install(wirelessNodes.Get(0));
  internet.Install(csmaNodes.Get(0));

  Ipv4AddressHelper address;
  address.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer csmaInterfaces = address.Assign(csmaDevices.Get(0));
  Ipv4InterfaceContainer wirelessInterfaces =
      address.Assign(wirelessDevices.Get(0));

  // echo service setup
  UdpEchoServerHelper echoServer(9);
  ApplicationContainer serverApps = echoServer.Install(csmaNodes.Get(0));
  serverApps.Start(Seconds(1.0));
  serverApps.Stop(Seconds(60.0));
  UdpEchoClientHelper echoClient(csmaInterfaces.GetAddress(0), 9);
  echoClient.SetAttribute("MaxPackets", UintegerValue(2000));
  echoClient.SetAttribute("Interval", TimeValue(Seconds(interval)));
  echoClient.SetAttribute("PacketSize", UintegerValue(packetSize));
  ApplicationContainer clientApps = echoClient.Install(wirelessNodes.Get(0));
  clientApps.Start(Seconds(2.0));
  clientApps.Stop(Seconds(60.0));

  // simulation setup
  wifiPhy.EnablePcap("random-waalk", wirelessDevices);

  // open the file of test case
  // you can change its place (to a function for example)
  FILE *fp = OpenFile(movementFile);
  std::vector<Vector> boundary = GetBoundary(fp);

  // [TODO]:
  // Determine the arguments of Schedule()
  STEP step = STEP{5, 0.0, 0.0};
  Simulator::Schedule(Seconds(stepsTime), &Movement, fp, boundary,
                      wirelessNodes.Get(0), step, stepsTime);
  Simulator::Stop(Seconds(60.0));
  Simulator::Run();
  Simulator::Destroy();
  fclose(fp);

  return 0;
}

FILE *OpenFile(char *fileName) {
  FILE *fp = fopen(fileName, "r");
  if (fp == NULL) {
    std::cerr << "ERROR while opening file" << std::endl;
    exit(-1);
  }
  return fp;
}

std::vector<Vector> GetBoundary(FILE *fp) {
  std::vector<Vector> boundary;
  boundary.clear();
  for (int i = 0; i < 2; i++) {
    Vector pos = Vector(0.0, 0.0, 0.0);
    fscanf(fp, "%lf %lf", &pos.x, &pos.y);
    boundary.push_back(pos);
  }
  return boundary;
}

MOVE GetSingleMovement(FILE *fp) {
  int index = 0;
  double rad = 0.0, speed = 0.0;
  fscanf(fp, "%d %lf %lf", &index, &rad, &speed);
  return MOVE{index, rad, speed};
}

void CheckLinkState(Ptr<Node> node) {
  Ptr<NetDevice> wifidevice = node->GetDevice(0);
  Ptr<WifiMac> apMac = DynamicCast<WifiNetDevice>(wifidevice)->GetMac();
  std::cout << Simulator::Now().As(Time::S) << " ";
  if (DynamicCast<StaWifiMac>(apMac)->IsAssociated()) {
    std::cout << "Client connects to AP "
              << DynamicCast<RegularWifiMac>(apMac)->GetBssid() << std::endl;
  } else {
    std::cout << "Client does not connect to AP" << std::endl;
  }
  return;
}

void Movement(FILE *fp, std::vector<Vector> &boundary, Ptr<Node> node,
              STEP &step, double stepsTime) {
  // [TODO]:
  // Determine the arguments of your Movement() function
  // Update position based on movement data
  // If (the currrent movement would reach the boundary) then:
  // {
  //  1. PrintIllegalMsg();
  //  2. Skip this movement
  // }

  Ptr<MobilityModel> mobility = node->GetObject<MobilityModel>();
  Vector pos = Vector(0.0, 0.0, 0.0);
  pos = mobility->GetPosition();

  if (step.fragment == 5) {
    MOVE move = GetSingleMovement(fp);
    std::cout << move.index << " " << move.rad << " " << move.speed
              << std::endl;
    step.x = move.speed * cos(move.rad);
    step.y = move.speed * sin(move.rad);

    if (pos.x + step.x > boundary[0].x || pos.y + step.y > boundary[0].y ||
        pos.x + step.x < boundary[1].x || pos.y + step.y < boundary[1].y) {
      PrintIllegalMsg(move.index);
      Simulator::Schedule(Seconds(1), &Movement, fp, boundary, node, step, 1);
      return;
    }
  }

  mobility->SetPosition(Vector(pos.x + step.x / 5, pos.y + step.y / 5, pos.z));
  pos = mobility->GetPosition();
  std::cout << "Current position: ( " << pos.x << ", " << pos.y << ", " << pos.z
            << " )" << std::endl;
  step.fragment = (step.fragment == 5) ? 1 : step.fragment + 1;

  CheckLinkState(node);
  Simulator::Schedule(Seconds(0.2), &Movement, fp, boundary, node, step, 0.2);
}

void PrintIllegalMsg(int index) {
  std::cerr << "[ERROR]: " << index << "-th movement is illegal" << std::endl;
}
