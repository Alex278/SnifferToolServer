#include "filterthread.h"
#include <QDebug>

FilterThread::FilterThread()
{

}

FilterThread::FilterThread(HostInfo *hostInfo,const char*dev,QString filter)
{
    char errBuf[PCAP_ERRBUF_SIZE] = {0};
    quitFg = false;

    this->filter = filter;
    //混杂模式
    this->handle = pcap_open_live(dev,65535,1,0,errBuf);

    if(!this->handle){
        printf("Open live dev is error: %s\n",errBuf);
        exit(1);
    }

    this->hostInfo = new HostInfo();
    memcpy(this->hostInfo,hostInfo,sizeof(HostInfo));

    ethernetPacket = new YEthernetPacket();
    arppacket = new YArpPacket();
    eippacket = new YIPHeaderPacket();
}

// 退出线程
void FilterThread::quitThread()
{
    qDebug()<< "Quit filter Thread";
    quitFg = true;
    delete hostInfo;
    delete ethernetPacket;
    delete arppacket;
    delete eippacket;

    pcap_close(this->handle);
    this->quit();
}

bool FilterThread::init()
{
    bpf_program fcode;
    // 不用关心掩码，在这个过滤器中，它不会被使用
    QByteArray bytearray = this->filter.toUtf8();
    char * filterCS = bytearray.data();
    // 编译过滤器
    if(pcap_compile(handle, &fcode, filterCS, 1, my_htonl(my_inet_addr(hostInfo->netmask))) < 0){
        qDebug("Unable to compile the packet filter. Check the syntax.");
        // 释放设备列表
        return false;
    }
    // 设置过滤器
    if(pcap_setfilter(handle, &fcode) < 0){
        qDebug("Error setting the filter.");
        // 释放设备列表
        return false;
    }

    return true;
}

void FilterThread::filterStart()
{
    pcap_t *adhandle = this->handle;
    int res;
    struct pcap_pkthdr * pktHeader;
    const u_char * pktData;

    while (!quitFg) {
        if ((res = pcap_next_ex(adhandle, &pktHeader, &pktData)) >= 0) {
            ethernetPacket->setData(pktData);
            // 先通过以太网头判断是IP包还是ARP包
            if(ethernetPacket->getEtherNetType() == my_ntohs(ARP_TYPE)){
                //qDebug()<<"[ARP][Source Mac][Source Ip] to [Dest Mac][Dest Ip][Len Bytes]";
                arppacket->setData(pktData);
                QString msg = QString("[ARP][%1][%2]  send to  [%3][%4]  [%5bytes]").arg(arppacket->getSourceMacAdd(),
                                        arppacket->getSourceIpAddStr(),arppacket->getDestMacAdd(),
                                        arppacket->getDestIpAddStr(),QString::number(pktHeader->len));
                //qDebug()<< msg;
                emit filterUpdateDataSig(msg);
            }
            else if(ethernetPacket->getEtherNetType() == my_ntohs(IP_TYPE)){
                //qDebug()<<"[IPV4][UDP/TCP/ICMP][Source Mac][Source Ip] to [Dest Mac][Dest Ip] [Len Bytes]";
                eippacket->setData(pktData);

                QString msg = QString("[IPV4][%1][%2][%3] send to [%4][%5] [%6bytes]").arg(eippacket->getProtocolType(),
                                        eippacket->getEtherSrcMacAdd(),eippacket->getSourceIpAddStr(),
                                        eippacket->getEtherDestMacAdd(),eippacket->getDestIpAddStr(),QString::number(pktHeader->len));
                //qDebug()<< msg;
                emit filterUpdateDataSig(msg);
            }
            else if(ethernetPacket->getEtherNetType() == my_ntohs(IPV6_TYPE)){
                //qDebug()<< "[IPV6][Source Mac] to [Dest Mac]";
                QString msg = QString("[IPV6][%1] send to [%2] [%3bytes]").arg(ethernetPacket->getEtherSrcMacAdd(),
                                        ethernetPacket->getEtherDestMacAdd(),QString::number(pktHeader->len));
                //qDebug()<< msg;
                emit filterUpdateDataSig(msg);
            }
        }
        // 接收缓冲下，会间歇性丢包
        usleep(100000);
    }
}

void FilterThread::run()
{
    if(init()){
        qDebug()<< "Filter thread init finished!";
        filterStart();
    }
}
