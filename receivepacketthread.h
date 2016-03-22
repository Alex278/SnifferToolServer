// ---------------------------------------------
// 抓包多线程
// ---------------------------------------------
#ifndef RECEIVEPACKETTHREAD_H
#define RECEIVEPACKETTHREAD_H

#include <QObject>
#include <QThread>
#include <QPair>
#include <QMetaType>
#include "pcapcommon.h"
#include "tcpipcommon.h"
#include "tcpipprotocol.h"
#include "portservicemap.h"

class ReceivePacketThread : public QThread
{
    Q_OBJECT

public:
    ReceivePacketThread();
    ReceivePacketThread(pcap_t *handle,HostInfo *hostInfo,u_short type);
    ReceivePacketThread(pcap_t *handle,HostInfo *hostInfo,u_short type,QString scanIp);
    void recvArpScanPacket();
    void recvTCPSYNACKPortScanPacket();
    void run();
private:
    pcap_t * handle;
    HostInfo *hostInfo;
    u_short type;
    bool scanIsFinished;

    QString scanIp;
    YArpPacket *arppacket;
    YEthernetPacket *etherpacket;
    YIPHeaderPacket *ipheaderpacket;
    YTcpPacket * tcppacket;

    PortServiceMap *portServiceMap;
public slots:
    void scanHostFinishedSlot();
signals:
    void scanGetHostInfoSig(QPair<QString,QString>);
    void portScanRecvUpdataSig(QString);
};

#endif // RECEIVEPACKETTHREAD_H
