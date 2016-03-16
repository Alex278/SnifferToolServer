#include "trafficstatistic.h"
#include <QDebug>


TrafficStatistic::TrafficStatistic()
{

}

TrafficStatistic::TrafficStatistic(HostInfo *hostInfo,const char *dev)
{
    char errBuf[PCAP_ERRBUF_SIZE] = {0};
    //混杂模式
    this->handle = pcap_open_live(dev,65535,1,0,errBuf);

    if(!this->handle){
        printf("Open live dev is error: %s\n",errBuf);
        exit(1);
    }

    this->hostInfo = new HostInfo();
    memcpy(this->hostInfo,hostInfo,sizeof(HostInfo));
    //arppacket = new YArpPacket();
}

TrafficStatistic::~TrafficStatistic()
{
    delete hostInfo;
    //delete arppacket;
}

bool TrafficStatistic::init()
{
    // 不用关心掩码，在这个过滤器中，它不会被使用
    netmask = 0xffffff;
    // 编译过滤器
    if(pcap_compile(handle, &fcode, "tcp", 1, netmask) < 0){
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
    // 将接口设置为统计模式
//    if(pcap_setmode(handle, MODE_STAT) < 0){
//        qDebug("Error setting the mode.");
//        // 释放设备列表
//        return false;
//    }

    return true;
}

void TrafficStatistic::statistic()
{
    pcap_t *adhandle = this->handle;
    int res;
    struct pcap_pkthdr * pktHeader;
    const u_char * pktData;

    bool onceFg = true;
    u_long delay = 0;

    u_int captureNum = 0;

    while (true) {
        if ((res = pcap_next_ex(adhandle, &pktHeader, &pktData)) >= 0) {
            ++captureNum;
            if(onceFg){
                oldts.tv_sec  = pktHeader->ts.tv_sec;
                oldts.tv_usec = pktHeader->ts.tv_usec;
                onceFg = false;
            }
            else {
                // 抓N个包后计算流量
                if(captureNum == 40){
                    delay = (pktHeader->ts.tv_sec - oldts.tv_sec);
//                    qDebug("%lu\t%lu\t%lu\t%d\t%d kb/s",oldts.tv_sec,pktHeader->ts.tv_sec,
//                           pktHeader->caplen,delay,(delay > 0) ? (pktHeader->caplen/delay) : 0);

                    float netSpeed = (delay > 0) ? ((float)(pktHeader->caplen)/(float)delay) : 0.0;
                    emit trafficStatisticNetSpeedSig(QString::number(netSpeed,'f',1));

                    oldts.tv_sec  = pktHeader->ts.tv_sec;
                    oldts.tv_usec = pktHeader->ts.tv_usec;

                    captureNum = 0;
                }
            }
        }
    }
}

void TrafficStatistic::run()
{
    if(init()){
        qDebug()<< "Traffic Statistic init finished!";
        statistic();
    }
}
