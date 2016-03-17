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
    //delete hostInfo;
    //if(this->type == ARP_PACKET_SCAN)delete arppacket;
    //if(this->type == ARP_PACKET_CHEAT)delete arppacket;
    //delete this;
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
}

// 退出线程
void SendPacketThread::quitThread()
{
    qDebug()<< "Quit send Arp Cheat Thread : " << cheatHostInfo->ip;
    quitFg = true;
    if(!cheatHostInfo)delete cheatHostInfo;
    if(this->type == ARP_PACKET_SCAN)delete arppacket;
    if(this->type == ARP_PACKET_CHEAT)delete arppacket;
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
        QThread::usleep(200000);
    }
    // 等待接收线程足够时间接受replay包
    sleep(3);
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
        QThread::usleep(200000);
    }
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
}
