#ifndef PCAPCOMMON_H
#define PCAPCOMMON_H

#include "pcap.h"
#include "tcpipcommon.h"
#include <QString>
#include <QVector>
#include <QObject>
#include "getmacthread.h"


#define PCAP_SRC_IF_STRING  "rpcap://"
#define IP_PACKET           0x10                //IP包
#define ARP_PACKET_SCAN     0x11                //ARP主机扫描包
#define ARP_PACKET_CHEAT    0x12                //ARP欺骗包
#define UDP_PACKET          0x13                //UDP包
#define TCP_PCAKET          0x14                //TCP包

//typedef struct _Sparam {
//    pcap_t *adhandle;
//    char *ip;
//    unsigned char *mac;
//    char *netmask;
//}Sparam;

//typedef struct _Gparam {
//    pcap_t *adhandle;
//}Gparam;


typedef struct _DEVInfo{
    QString name;
    QString description;
    QString familyName;         //协议族，
    QString address;            //主机ip
    QString netmask;            //子网掩码
}DEVInfo;


typedef struct _HostInfo{
    unsigned char mac[6];
    char ip[16];
    char netmask[16];
}HostInfo;

class PcapCommon : public QObject
{
    Q_OBJECT

public:
    PcapCommon();
    ~PcapCommon();
public:            
    // 扫描本机所有的适配器，并获取每个适配器的信息
    QVector<DEVInfo> findAllDev();
    // 打开一个适配器
    void openLiveDev(const char *);
    // 获取当前打开的适配器描述符
    pcap_t *&getCurrentHandle();
    // 通过适配器名获取相应IP
    QString getHostIpByDevName(QString);    
    // 获取本机Mac
    QString getSelfMac(void);
    void getSelfMac(const char *devname,const char *ip_addr);
    // 设置本机信息：ip 、 掩码 、 Mac
    void setHostInfo(const char *devName);
    // 获取本机信息：ip 、 掩码 、 Mac
    HostInfo getHostInfo();
    // 获取Host IP
    QString getHostIp();
    // 获取Host Mac(是在getSelfMac的前提下，方便第二次调用，不需要通过发送ARP包来获取MAC地址)
    QString getHostMac();
    // 获取子网掩码
    QString getHostNetmask();

    // 向局域网内所有主机广播ARP请求包
    //void sendArpPacket();
public slots:
    // 获取本机Mac地址完成槽函数处理
    void getSelfMacFinishedSlot(QString mac);
signals:
    void getSelfMacFinishedSig(QString mac);

protected:
    pcap_t * handle;
    HostInfo hostInfo;
    pcap_if_t *alldevs;

};

#endif // PCAPCOMMON_H
