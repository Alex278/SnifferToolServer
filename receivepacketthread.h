#ifndef RECEIVEPACKETTHREAD_H
#define RECEIVEPACKETTHREAD_H

#include <QObject>
#include <QThread>
#include <QPair>
#include <QMetaType>
#include "pcapcommon.h"
#include "tcpipcommon.h"
#include "tcpipprotocol.h"


class ReceivePacketThread : public QThread
{
    Q_OBJECT

public:
    ReceivePacketThread();
    ReceivePacketThread(pcap_t *handle,HostInfo *hostInfo,u_short type);
    void recvArpScanPacket();
    void run();
private:
    pcap_t * handle;
    HostInfo *hostInfo;
    u_short type;
    bool scanIsFinished;

    YArpPacket *arppacket;

public slots:
    void scanHostFinishedSlot();
signals:
    void scanGetHostInfoSig(QPair<QString,QString>);
};

#endif // RECEIVEPACKETTHREAD_H
