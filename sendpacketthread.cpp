#include "sendpacketthread.h"
#include <QDebug>


SendPacketThread::SendPacketThread()
{

}

//
//
SendPacketThread::SendPacketThread(pcap_t *handle,HostInfo *hostInfo,u_short type,
                                   QString ips,QString ipe)
{
    this->handle = handle;

    this->hostInfo = new HostInfo();

    memcpy(this->hostInfo,hostInfo,sizeof(HostInfo));

    this->type = type;
    ipStart = ips;
    ipEnd = ipe;

    if(this->type == ARP_PACKET_SCAN){
        qDebug()<< "ARP_PACKET_SCAN Thread";
        arppacket = new YArpPacket();
    }
    if(this->type == TCP_PACKET){
        tcppacket = new YTcpPacket();
    }
}


SendPacketThread::~SendPacketThread()
{
    //delete hostInfo;
    //if(this->type == ARP_PACKET_SCAN)delete arppacket;
    delete this;
}

// 获取arppacket
YArpPacket* &SendPacketThread::getArpPacket()
{
    return arppacket;
}

// 发送ARP扫描包
/*
void SendPacketThread::sendArpScanPacket()
{
    QByteArray ipStartSB = ipStart.toUtf8();
    QByteArray ipEndSB = ipEnd.toUtf8();

    const char *ipS = ipStartSB.data();
    const char *ipE = ipEndSB.data();
    // 获取局域网主机有效ip地址个数
    const char *broadcast = "255.255.255.255";
    u_long nbroadcast = my_inet_addr(broadcast);
    u_long nnetmask = my_inet_addr(hostInfo->netmask);
    u_long hostNum = nbroadcast - nnetmask -2;
    // start~end host num
    u_long nipS = my_inet_addr(ipS);
    u_long nipE = my_inet_addr(ipE);
    u_long startEndNum = nipE - nipS;

    if(startEndNum > hostNum)startEndNum = hostNum;

    char ipStr[4] = {0};
    for(unsigned int i = 0; i < startEndNum; i++){
        arppacket->setDestIpAdd(my_htonl(nipS + i));
        qDebug("send ip: %s \n",iptos(my_htonl(nipS + i),ipStr));

        // 如果发送成功
        if (pcap_sendpacket(handle, arppacket->getData(), ARP_PACKET_LENGTH) == 0){
            //printf("\nPacketSend succeed\n");
        } else {
            printf("PacketSendPacket in getmine Error");
        }
        // 每隔多少微秒向指定ip发送ARP包
        QThread::sleep(2);
    }
}
*/

void SendPacketThread::sendArpScanPacket()
{   
    pcap_t *adhandle = this->handle;
    char *ip = hostInfo->ip;
    unsigned char *mac = hostInfo->mac;
    char *netmask = hostInfo->netmask;
    //qDebug("Host Mac:%02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2],mac[3], mac[4], mac[5]);
    //qDebug("Host Ip:%s\n", ip);
    //qDebug("Host Netmask:%s\n", netmask);
    //qDebug("\n");
    unsigned char sendbuf[42]; 			//arp包结构大小
    EthernetHeader eh;
    ArpHeader ah;
    //赋值MAC地址
    memset(eh.DestMAC, 0xff, 6);       	//目的地址为全为广播地址
    memcpy(eh.SourMAC, mac, 6);
    eh.EthType = my_htons(0x0806);

    ah.HardwareType = my_htons(ARP_HARDWARE);
    ah.ProtocolType = my_htons(IP_TYPE);

    ah.HardwareAddLen = 6;
    ah.ProtocolAddLen = 4;
    ah.OperationField = my_htons(ARP_REQUEST);

    memcpy(ah.SourceMacAdd, mac, 6);
    u_long srcIpN =  my_htonl(my_inet_addr(ip));
    memcpy(ah.SourceIpAdd,(u_char*)&srcIpN,4);
    memset(ah.DestMacAdd, 0x00, 6);

    // 获取局域网主机有效ip地址个数
    const char *broadcast = "255.255.255.255";
    u_long nbroadcast = my_inet_addr(broadcast);
    u_long nnetmask = my_inet_addr(netmask);
    u_long hostNum = nbroadcast - nnetmask -2;
    // start~end host num
    QByteArray ipStartSB = ipStart.toUtf8();
    QByteArray ipEndSB = ipEnd.toUtf8();
    char *ipS = ipStartSB.data();
    char *ipE = ipEndSB.data();
    u_long nipS = my_inet_addr(ipS);
    u_long nipE = my_inet_addr(ipE);
    u_long startEndNum = nipE - nipS;

    if(startEndNum > hostNum)startEndNum = hostNum;

    // 发送
    for (u_long i = 0; i <= startEndNum; i++) {
        u_long tempIp = my_htonl(nipS + i);
        memcpy(ah.DestIpAdd,(u_char*)&tempIp,4);
        qDebug("send ip: %s \n",my_iptos(tempIp));
        //构造一个ARP请求
        memset(sendbuf, 0, sizeof(sendbuf));
        memcpy(sendbuf, &eh, sizeof(eh));
        memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
        //如果发送成功
        if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
            //printf("\nPacketSend succeed\n");
        } else {
            printf("PacketSendPacket in getmine Error");
        }
        sleep(1);
    }
}

// 发送ARP欺骗包
void SendPacketThread::sendArpCheatPacket()
{

}

// 线程运行函数
void SendPacketThread::run()
{
    if(type == ARP_PACKET_SCAN){
        // run scan fun
        sendArpScanPacket();

    }
    if(type == ARP_PACKET_CHEAT){
        // ...
    }
}

/*
void SendPacketThread::sendArpPacket()
{
    pcap_t *adhandle = handle;
    char *ip = hostInfo.ip;
    unsigned char *mac = hostInfo.mac;
    char *netmask = hostInfo.netmask;
    //printf("Host Mac:%02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2],mac[3], mac[4], mac[5]);
    //printf("Host Ip:%s\n", ip);
    //printf("Host Netmask:%s\n", netmask);
    unsigned char sendbuf[42];
    EthernetHeader eh;
    ArpHeader ah;
    // 赋值MAC地址
    memset(eh.DestMAC, 0xff, 6);
    memcpy(eh.SourMAC, mac, 6);
    memcpy(ah.SourceMacAdd, mac, 6);
    memset(ah.DestMacAdd, 0x00, 6);
    eh.EthType = my_htons(ARP_TYPE);
    ah.HardwareType = my_htons(ARP_HARDWARE);
    ah.ProtocolType = my_htons(IP_TYPE);
    ah.HardwareAddLen = 6;
    ah.ProtocolAddLen = 4;
    ah.SourceIpAdd = my_inet_addr(ip);
    ah.OperationField = my_htons(ARP_REQUEST);
    // 向局域网内广播发送arp包
    unsigned long myip = my_inet_addr(ip);
    unsigned long mynetmask = my_inet_addr(netmask);
    unsigned long hisip = my_htonl((myip & mynetmask));

    printf("Host ip Num: %ld\n",hisip);
    // 向N个主机发送
    char ipStr[4] = {0};
    for(unsigned int i = 0; i < hisip; i++){
        ah.DestIpAdd = my_htonl(hisip + i);
        printf("send ip: %s \n",iptos(ah.DestIpAdd,ipStr));
        // 构造一个ARP请求
        memset(sendbuf, 0, sizeof(sendbuf));
        memcpy(sendbuf, &eh, sizeof(eh));
        memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
        // 如果发送成功
        if (pcap_sendpacket(adhandle, sendbuf, 42) == 0){
            //printf("\nPacketSend succeed\n");
        } else {
            printf("PacketSendPacket in getmine Error");
        }
        // 每隔多少微秒向指定ip发送ARP包
        QThread::usleep(100000);
    }
}
*/
