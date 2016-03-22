// ---------------------------------------------
// 发包多线程
// ---------------------------------------------
#ifndef SENDPACKETTHREAD_H
#define SENDPACKETTHREAD_H

#include <QObject>
#include <QThread>
#include "pcap.h"
#include "tcpipcommon.h"
#include "tcpipprotocol.h"
#include "syn_scan.h"

class SendPacketThread : public QThread
{
    Q_OBJECT

public:
    //
    SendPacketThread();    
    //
    SendPacketThread(pcap_t *handle,HostInfo *hostInfo,u_short type,QString ips,QString ipe);
    //
    SendPacketThread(pcap_t *handle,HostInfo *hostInfo,u_short type,HostInfo *cheatHostInfo);
    //
    SendPacketThread(const char *device,HostInfo *hostInfo,u_short type,HostInfo *destInfo,u_short sport,u_short eport);
    //
    SendPacketThread(pcap_t *handle,HostInfo *hostInfo,u_short type,HostInfo *destInfo,u_short sport,u_short eport);
    //
    ~SendPacketThread();

    // 获取arppacket
    YArpPacket* &getArpPacket();
    // 发送ARP扫描包
    void sendArpScanPacket();
    // 发送ARP欺骗包
    void sendArpCheatPacket();
    // 发送端口扫描tcp包
    void sendTcpSYNPortScanPacket();
    // 获取被欺骗主机IP
    QString getTheCheatHostIp();
    // 退出线程
    void quitThread();
    // 线程运行函数
    void run();
private:
    pcap_t *handle;
    HostInfo *hostInfo;
    HostInfo *cheatHostInfo;
    u_short type;
    QString ipStart;
    QString ipEnd;
    u_short portStart;
    u_short portEnd;

    YArpPacket *arppacket;
    YTcpPacket *tcppacket;

    bool quitFg;

    SYN_Scan_Inst *scan_inst;
signals:
    void scanHostFinishedSig();
    void scanCurrentIpSig(QString);
};

#endif // SENDPACKETTHREAD_H
