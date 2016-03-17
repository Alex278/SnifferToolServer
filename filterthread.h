#ifndef FILTERTHREAD_H
#define FILTERTHREAD_H

#include <QByteArray>
#include <QThread>
#include "tcpipcommon.h"
#include "tcpipprotocol.h"
#include "pcap.h"

class FilterThread : public QThread
{
    Q_OBJECT

public:
    FilterThread();
    FilterThread(HostInfo *hostInfo,const char*dev,QString filter);
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
    void filterUpdateDataSig(QString data);
};

#endif // FILTERTHREAD_H
