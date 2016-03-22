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
    emit filterStatusSig(1,QString(tr("停止过滤抓包")));
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
        emit filterStatusSig(-1,QString(tr("过滤语法错误！")));
        quitThread();
        // 释放设备列表
        return false;
    }
    // 设置过滤器
    if(pcap_setfilter(handle, &fcode) < 0){
        qDebug("Error setting the filter.");
        emit filterStatusSig(-2,QString(tr("设置过滤器出错！")));
        quitThread();
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
    char timestr[16] = {0};
    time_t local_tv_sec;
    struct tm *ltime;

    while (!quitFg) {
        if ((res = pcap_next_ex(adhandle, &pktHeader, &pktData)) >= 0) {
            ethernetPacket->setData(pktData);
            local_tv_sec = pktHeader->ts.tv_sec;
            ltime=localtime(&local_tv_sec);
            strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);            
            // 先通过以太网头判断是IP包还是ARP包
            if(ethernetPacket->getEtherNetType() == my_ntohs(ARP_TYPE)){
                //qDebug()<<"[ARP][Source Mac][Source Ip] to [Dest Mac][Dest Ip][Len Bytes]";
                arppacket->setData(pktData);
                QString msg = QString("[%1][ARP][%2][%3]  send to  [%4][%5]  [%6bytes]").arg(QString(timestr),
                                        arppacket->getSourceMacAdd(),arppacket->getSourceIpAddStr(),
                                        arppacket->getDestMacAdd(),arppacket->getDestIpAddStr(),QString::number(pktHeader->len));
                //qDebug()<< msg;
                emit filterUpdateDataSig(msg);
            }
            else if(ethernetPacket->getEtherNetType() == my_ntohs(IP_TYPE)){
                //qDebug()<<"[IPV4][UDP/TCP/ICMP][Source Mac][Source Ip] to [Dest Mac][Dest Ip] [Len Bytes]";
                eippacket->setData(pktData);

                QString msg = QString("[%1][IPV4][%2][%3][%4] send to [%5][%6] [%7bytes]").arg(QString(timestr),eippacket->getProtocolType(),
                                        ethernetPacket->getEtherSrcMacAdd(),eippacket->getSourceIpAddStr(),
                                        ethernetPacket->getEtherDestMacAdd(),eippacket->getDestIpAddStr(),QString::number(pktHeader->len));
                //qDebug()<< msg;
                emit filterUpdateDataSig(msg);
            }
            else if(ethernetPacket->getEtherNetType() == my_ntohs(IPV6_TYPE)){
                //qDebug()<< "[IPV6][Source Mac] to [Dest Mac]";
                QString msg = QString("[%1][IPV6][%2] send to [%3] [%4bytes]").arg(QString(timestr),
                                        ethernetPacket->getEtherSrcMacAdd(),ethernetPacket->getEtherDestMacAdd(),
                                        QString::number(pktHeader->len));
                //qDebug()<< msg;
                emit filterUpdateDataSig(msg);
            }
        }
        // 接收缓冲下，会间歇性丢包
        //usleep(100000);
    }
}

void FilterThread::run()
{
    if(init()){
        qDebug()<< "Filter thread init finished!";
        emit filterStatusSig(0,QString(tr("开始过滤抓包")));
        filterStart();
    }
}
