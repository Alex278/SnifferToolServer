#include "receivepacketthread.h"
#include <QDebug>

ReceivePacketThread::ReceivePacketThread()
{

}

ReceivePacketThread::ReceivePacketThread(pcap_t *handle,HostInfo *hostInfo,u_short type)
{
    // 注册自定义结构参数
    qRegisterMetaType< QPair<QString,QString> >("QPair<QString,QString>");

    scanIsFinished = false;
    this->handle = handle;
    this->hostInfo = new HostInfo();
    memcpy(this->hostInfo,hostInfo,sizeof(HostInfo));
    this->type = type;

    if(this->type == ARP_PACKET_SCAN){
        qDebug()<< "ARP_PACKET_SCAN  Recv Thread";
        arppacket = new YArpPacket();
    }
    if(type == ARP_PACKET_CHEAT){

    }
}

void ReceivePacketThread::recvArpScanPacket()
{
    pcap_t *adhandle = this->handle;
    int res;    
    struct pcap_pkthdr * pktHeader;
    const u_char * pktData;
    while (!scanIsFinished) {
        if ((res = pcap_next_ex(adhandle, &pktHeader, &pktData)) >= 0) {            
            arppacket->setData(pktData);
            if ((arppacket->getEtherNetType()) == my_ntohs(ARP_TYPE)
                    && ((arppacket->getOperationField()) == my_ntohs(ARP_REPLY))
                ){
                QPair<QString,QString> pair;
                pair.first = QString(my_iptos(arppacket->getSourceIpAdd()));
                pair.second = arppacket->getSourceMacAdd();
                emit scanGetHostInfoSig(pair);
//                qDebug("-------------------------------------------\n");
//                qDebug("IP Address: %s",my_iptos(arppacket->getSourceIpAdd()));
//                qDebug() << arppacket->getSourceMacAdd();
//                qDebug("\n");
            }
        }
        //usleep(10000);
    }
}

void ReceivePacketThread::run()
{
    if(type == ARP_PACKET_SCAN){
        // 获取reply包 emit到pcapcommon
        recvArpScanPacket();
        //
        delete hostInfo;
        if(type == ARP_PACKET_SCAN)delete arppacket;
        qDebug() << "Rece ARP_PACKET_SCAN is quit";
        this->quit();
    }
    if(type == ARP_PACKET_CHEAT){

    }
}

void ReceivePacketThread::scanHostFinishedSlot()
{
    qDebug() << "Scan host is finished slot";
    scanIsFinished = true;
}

