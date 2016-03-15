#ifndef SENDPACKETTHREAD_H
#define SENDPACKETTHREAD_H

#include <QObject>
#include <QThread>
#include "pcap.h"
#include "tcpipcommon.h"
#include "tcpipprotocol.h"

class SendPacketThread : public QThread
{
    Q_OBJECT

public:
    //
    SendPacketThread();    
    //
    SendPacketThread(pcap_t *handle,HostInfo *hostInfo,u_short type,QString ips,QString ipe);
    //
    ~SendPacketThread();

    // 获取packet 对象
//    template <typename T>
//    T &getPacket(u_short type){
//        if(type == ARP_PACKET)
//            return arppacket;
//        if(type == TCP_PACKET)
//            return tcppacket;
//    }
    // 获取arppacket
    YArpPacket* &getArpPacket();
    // 发送ARP扫描包
    void sendArpScanPacket();
    // 发送ARP欺骗包
    void sendArpCheatPacket();
    // 线程运行函数
    void run();
private:
    pcap_t *handle;
    HostInfo *hostInfo;
    u_short type;
    QString ipStart;
    QString ipEnd;

    YArpPacket *arppacket;
    YTcpPacket *tcppacket;
signals:
    void scanHostFinishedSig();
    void scanCurrentIpSig(QString);
};

#endif // SENDPACKETTHREAD_H
