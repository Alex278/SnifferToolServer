// ---------------------------------------------
// 过滤抓包（ICMP 指定IP包）单线程
// ---------------------------------------------
#ifndef MYPINGTHREAD_H
#define MYPINGTHREAD_H

#include <QThread>
#include "tcpipcommon.h"
#include "tcpipprotocol.h"
#include "pcap.h"

class MyPingThread : public QThread
{
    Q_OBJECT

public:
    MyPingThread();
    MyPingThread(HostInfo *hostInfo,const char*dev,QString filter);
    void quitThread();
private:
    bool init();
    void filterStart();
    void run();
private:
    pcap_t * handle;
    HostInfo *hostInfo;
    QString filter;
    bool quitFg;

    YEthernetPacket * ethernetPacket;
    YArpPacket *arppacket;
    YIPHeaderPacket *eippacket;
signals:
    void pingUpdateDataSig(QString data);
};

#endif // MYPINGTHREAD_H
