// ---------------------------------------------
// pcap操作相关，中间层
// ---------------------------------------------
#ifndef PCAPCOMMON_H
#define PCAPCOMMON_H

#include "pcap.h"
#include "tcpipcommon.h"
#include <QString>
#include <QVector>
#include <QObject>
#include <QPair>
#include <QMetaType>
#include <QQueue>
#include <QTimer>
#include "sendpacketthread.h"
#include "filterthread.h"

typedef struct _DEVInfo{
    QString name;
    QString description;
    QString familyName;         //协议族，
    QString address;            //主机ip
    QString netmask;            //子网掩码
}DEVInfo;


class PcapCommon : public QObject
{
    Q_OBJECT

public:
    PcapCommon();
    ~PcapCommon();

public:
    // Windows Socket 初始化
    void winSocketInit();
    //
    u_char hexStr2UChar(QString hexS);
    // 设置Pcap的状态
    void setPcapStatus(bool status);
    // 获取Pcap的状态
    bool getPcapStatus();
    // 扫描本机所有的适配器，并获取每个适配器的信息
    QVector<DEVInfo> findAllDev();
    // 打开一个适配器
    void openLiveDev(const char *);
    // 获取当前打开的适配器描述符
    pcap_t *&getCurrentHandle();
    // 通过适配器名获取相应IP
    QString getHostIpByDevName(QString);    
    // 获取本机Mac
    void getSelfMac(void);
    //QString getSelfMac(void);
    // 设置本机信息：ip 、 掩码 、 Mac
    void setHostInfo(const char *devName);
    // 获取本机信息：ip 、 掩码 、 Mac
    HostInfo getHostInfo();
    // 获取Host IP
    QString getHostIp();
    // 获取Host IP(通过winsock2)
    QString getHostIpByWinSock();
    // 获取本机网关(通过winsock2)
    QString getGateway();
    // 设置网关
    void setGatewayMac(QString);
    // 获取Host Mac(是在getSelfMac的前提下，方便第二次调用，不需要通过发送ARP包来获取MAC地址)
    QString getHostMac();
    // 获取子网掩码
    QString getHostNetmask();
    //ipStart ipEnd是否有效
    bool ipStart2EndIsValid(QString ipStart,QString ipEnd);
    // 扫描局域网中所有主机：
    // ip地址&掩码地址 =
    // 有效主机地址的数量=2^(主机地址二进制位数)-2
    void scanLANHost(QString ipStart,QString ipEnd);
    // ARP欺骗指定主机,主机欺骗：向网关发送请求包，源ip为欺骗ip,源mac为本机mac,即向网关伪装为主机
    // ARP欺骗网关，向欺骗主机发送replay包，源ip为网关ip，源mac为本机mac,即向主机伪装为网关
    void arpCheatHost(QString cheatIp,QString cheatMac,QString gatewayMac);

    //void arpCheatG
    // 退出ARP Cheat Thread
    void quitArpCheatThread(QString);
    // 统计本机流量
    void trafficStatistic(const char *dev);
    // 应用过滤规则
    void applyFilter(const char *dev,QString filter);
    // 停止过滤
    void stopFilter();
    // 获取当前过滤线程的状态：停止or运行中
    bool getFilterThreadStatus();
    // Ping Ip
    void applyPing(QString ip,int num);
    // 端口扫描
    //void applyPortScan(const char *device,QString ip,QString scanMac,u_short startPort,u_short endPort);
    void applyPortScan(const char *device,QString ip,QString scanMac,u_short startPort,u_short endPort);

public slots:
    // 获取本机Mac地址完成槽函数处理
    void getSelfMacFinishedSlot(QString mac);   
    // 扫描主机结束
    void scanHostFinishedSlot();
    // 接收当前正在扫描的ip地址
    void scanCurrentIpSlot(QString);
    // 接收扫描到的主机信息
    void scanGetHostInfoSlot(QPair<QString,QString>);
    // 定时器溢出槽函数
    void getDataFromQQueueTimerUpdateSlot();
    // 定时取filter buffer数据槽函数
    void getDataFromFilterBufferSlot();
    // 获取网速
    void trafficStatisticNetSpeedSlot(QString);
    // 获取filter发送的数据
    void filterUpdateDataSlot(QString data);
    // 过滤线程出现错误
    void filterStatusSlot(int num,QString msg);
    // 端口扫描结束
    void portScanIsFinishedSlot();
    // 端口扫描获取SYN-ACK更新
    void portScanRecvUpdataSlot(QString);
signals:
    void getSelfMacFinishedSig(QString mac);
    void scanHostFinishedSig();
    void scanCurrentIpSig(QString);
    // ip ,hostname,mac
    void scanGetHostInfoSig(QPair< QString,QString >);
    void trafficStatisticNetSpeedSig(QString);
    void filterUpdateDataSig(QString data);
    void filterStatusSig(int num,QString msg);
    void pingUpdateEchoSig(QString echo);
    void portScanIsFinishedSig();
    void portScanRecvUpdataSig(QString);
protected:
    pcap_t * handle;
    bool pcapStatus;
    HostInfo hostInfo;
    pcap_if_t *alldevs;
    QTimer *getDataFromQQueueTimer;
    QTimer *getDataFromFilterBufferTimer;

    QMap< QString,SendPacketThread * > *sendThreadAdd;
    QQueue< QPair<QString,QString> > *hostInfoBuffer;
    QQueue< QString > *filterDataBuffer;
    FilterThread *filterThread;


};

#endif // PCAPCOMMON_H
