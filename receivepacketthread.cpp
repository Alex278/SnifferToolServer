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
        //qDebug()<< "ARP_PACKET_SCAN  Recv Thread";
        arppacket = new YArpPacket();        

    }
    if(type == ARP_PACKET_CHEAT){

    }
    if(type == TCP_PACKET){
        etherpacket = new YEthernetPacket();
        ipheaderpacket = new YIPHeaderPacket();
        tcppacket = new YTcpPacket();
    }
}

ReceivePacketThread::ReceivePacketThread(pcap_t *handle,HostInfo *hostInfo,u_short type,QString scanIp)
{
    scanIsFinished = false;
    this->handle = handle;
    this->hostInfo = new HostInfo();
    memcpy(this->hostInfo,hostInfo,sizeof(HostInfo));
    this->type = type;
    this->scanIp = scanIp;

    if(type == TCP_PACKET){
        portServiceMap = new PortServiceMap();
        etherpacket = new YEthernetPacket();
        ipheaderpacket = new YIPHeaderPacket();
        tcppacket = new YTcpPacket();
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
    }
}

void ReceivePacketThread::recvTCPSYNACKPortScanPacket()
{
    pcap_t *adhandle = this->handle;
    int res;
    struct pcap_pkthdr * pktHeader;
    const u_char * pktData;
    while (!scanIsFinished) {
        if ((res = pcap_next_ex(adhandle, &pktHeader, &pktData)) >= 0) {
            etherpacket->setData(pktData);
            if ((etherpacket->getEtherNetType() == my_htons(IP_TYPE))){
                ipheaderpacket->setData(pktData);
                if((ipheaderpacket->getProtocolType() == "TCP")){
                    tcppacket->setData(pktData);
                    if((ipheaderpacket->getDestIpAddStr() == QString(hostInfo->ip)) &&
                        (ipheaderpacket->getSourceIpAddStr() == scanIp)){
                        // 端口开放
                        if(tcppacket->getFlag() == (TCP_SYN_ACK)){
                            //qDebug() << my_htons(tcppacket->getSrcPort()) << " 端口已开放";

                            QString service = portServiceMap->getService(my_htons(tcppacket->getSrcPort()));
                            QString msg = QString("端口:%1  协议:tcp  服务:%2").arg(QString::number(my_htons(tcppacket->getSrcPort())),service);
                            //qDebug()<< msg;
                            emit portScanRecvUpdataSig(msg);
                        }
                        // 端口未开放
                        else if(tcppacket->getFlag() == (TCP_RST_ACK)){
                            //qDebug() << my_htons(tcppacket->getSrcPort()) << " 端口未开放";
                        }
                    }
                }
            }
        }
    }
}

void ReceivePacketThread::run()
{
    if(type == ARP_PACKET_SCAN){
        // 获取reply包 emit到pcapcommon
        recvArpScanPacket();
        //
        delete hostInfo;
        //
        if(type == ARP_PACKET_SCAN)delete arppacket;
        qDebug() << "Rece ARP_PACKET_SCAN is quit";
        this->quit();
    }
    if(type == ARP_PACKET_CHEAT){

    }
    if(type == TCP_PACKET){
        recvTCPSYNACKPortScanPacket();
        //
        delete hostInfo;
        //
        delete etherpacket;
        delete ipheaderpacket;
        delete tcppacket;
        qDebug() << "Recv PortScan is quit";
        this->quit();
    }
}

void ReceivePacketThread::scanHostFinishedSlot()
{
    qDebug() << "Recv is finished slot";
    scanIsFinished = true;
}

