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

}

// TCP PORT SCAN1:libnet
SendPacketThread::SendPacketThread(const char *device,HostInfo *hostInfo,u_short type,HostInfo *destInfo,u_short sport,u_short eport)
{
    qDebug()<< "SendPacketThread Init!";
    portStart = sport;
    portEnd = eport;
    this->type = type;
    this->handle = handle;
    // srcMac是网关？还是目标Mac
    if(this->type == TCP_PACKET){
        //tcppacket = new YTcpPacket(hostInfo->mac,hostInfo->gatewayMac,hostInfo->ip,destInfo->ip,sport);
        scan_inst = new SYN_Scan_Inst(device);
        scan_inst->setDestinationIP(destInfo->ip);
        scan_inst->setPortRange(sport,eport);
        scan_inst->setSourceIP(hostInfo->ip);
    }
}

// TCP PORT SCAN2:WinPcap
SendPacketThread::SendPacketThread(pcap_t *handle,HostInfo *hostInfo,u_short type,HostInfo *destInfo,u_short sport,u_short eport)
{
    qDebug()<< "SendPacketThread Init!";
    portStart = sport;
    portEnd = eport;
    this->type = type;
    this->handle = handle;
    // srcMac是网关？还是目标Mac
    if(this->type == TCP_PACKET){
        tcppacket = new YTcpPacket(hostInfo->mac,destInfo->mac,hostInfo->ip,destInfo->ip,sport);
    }
}

SendPacketThread::SendPacketThread(pcap_t *handle,HostInfo *hostInfo,u_short type,HostInfo *cheatHostInfo)
{
    quitFg = false;
    this->handle = handle;

    this->type = type;
    if(this->type == ARP_PACKET_CHEAT){
        this->cheatHostInfo = new HostInfo();
        memcpy(this->cheatHostInfo,cheatHostInfo,sizeof(HostInfo));
        arppacket = new YArpPacket();
    }
}

SendPacketThread::~SendPacketThread()
{
}

// 获取arppacket
YArpPacket* &SendPacketThread::getArpPacket()
{
    return arppacket;
}

// 获取被欺骗主机IP
QString SendPacketThread::getTheCheatHostIp()
{
    if(this->type == ARP_PACKET_CHEAT){
        return QString(cheatHostInfo->ip);
    }
    return "0.0.0.0";
}

// 退出线程
void SendPacketThread::quitThread()
{
    qDebug()<< "SendThread is quit!" << this->type;
    quitFg = true;
    if(!cheatHostInfo)delete cheatHostInfo;
    if(!hostInfo)delete hostInfo;
    if(this->type == ARP_PACKET_SCAN)delete arppacket;
    if(this->type == ARP_PACKET_CHEAT)delete arppacket;
    if(this->type == TCP_PACKET){
        //delete tcppacket;
        delete scan_inst;
    }
    this->quit();
}

// 发送ARP扫描包
void SendPacketThread::sendArpScanPacket()
{
    QByteArray ipStartSB = ipStart.toUtf8();
    QByteArray ipEndSB = ipEnd.toUtf8();

    char *ipS = ipStartSB.data();
    char *ipE = ipEndSB.data();
    // 获取局域网主机有效ip地址个数
    char *broadcast = "255.255.255.255";
    u_long nbroadcast = my_inet_addr(broadcast);
    u_long nnetmask = my_inet_addr(hostInfo->netmask);
    u_long hostNum = nbroadcast - nnetmask -2;
    // start~end host num
    u_long nipS = my_inet_addr(ipS);
    u_long nipE = my_inet_addr(ipE);
    u_long startEndNum = nipE - nipS;

    if(startEndNum > hostNum)startEndNum = hostNum;

    // char ipStr[4] = {0};
    for(unsigned int i = 0; i <= startEndNum; i++){
        arppacket->setDestIpAdd(my_htonl(nipS + i));
        emit scanCurrentIpSig(QString(my_iptos(my_htonl(nipS + i))));
        // 发送
        if (pcap_sendpacket(handle, arppacket->getData(), ARP_PACKET_LENGTH) == 0){
            //printf("\nPacketSend succeed\n");
        } else {
            printf("PacketSendPacket in getmine Error");
        }
        // 每隔多少微秒向指定ip发送ARP包
        QThread::usleep(150000);
    }
    // 等待接收线程足够时间接受reply包
    sleep(5);
    emit scanHostFinishedSig();
}

// 发送ARP欺骗包
void SendPacketThread::sendArpCheatPacket()
{
    while(!quitFg){
        // 发送
        if (pcap_sendpacket(handle, arppacket->getData(), ARP_PACKET_LENGTH) == 0){
            //printf("\nPacketSend succeed\n");
        } else {
            printf("PacketSendPacket in getmine Error");
        }
        // 每隔多少微秒向指定ip发送ARP包
        QThread::usleep(5000);
    }
}

// 发送端口扫描tcp包
void SendPacketThread::sendTcpSYNPortScanPacket()
{
    int range = portEnd - portStart;
    qDebug()<< "range : " << range;
    for(int i = 0; i < range; ++i){
        // 发送
        if (pcap_sendpacket(handle, tcppacket->getData(), TCP_PACKET_LENGTH) == 0){
            //printf("\nPacketSend succeed\n");
        } else {
            printf("PacketSendPacket in getmine Error");
        }
        tcppacket->setScanPort(portStart + i);
        // 每隔多少微秒向指定ip发送ARP包
        QThread::usleep(5000);
    }
    // 等待接收线程足够时间接受SYN-ACK包
    sleep(5);
    emit scanHostFinishedSig();
}

// 线程运行函数
void SendPacketThread::run()
{
    if(type == ARP_PACKET_SCAN){
        // run scan fun
        sendArpScanPacket();
        delete hostInfo;
        if(this->type == ARP_PACKET_SCAN)delete arppacket;
        qDebug() << "Send ARP_PACKET_SCAN is quit";
        this->quit();
    }
    if(type == ARP_PACKET_CHEAT){
        // ...
        sendArpCheatPacket();        
    }
    if(type == TCP_PACKET){
        scan_inst->doSend();
        sleep(5);
        emit scanHostFinishedSig();
        //sendTcpSYNPortScanPacket();
        quitThread();
    }
}
