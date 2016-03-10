#ifndef PCAPCOMMON_H
#define PCAPCOMMON_H

#include "pcap.h"
#include "tcpipcommon.h"
#include <QString>
#include <QVector>


#define PCAP_SRC_IF_STRING   "rpcap://"

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

class PcapCommon
{
public:
    PcapCommon();
public:            
    // 扫描本机所有的适配器，并获取每个适配器的信息
    QVector<DEVInfo> findAllDev();
    // 打开一个适配器
    void openLiveDev(const char *);
    // 获取当前打开的适配器描述符
    pcap_t *&getCurrentHandle();
    // 获取本机Mac
    QString getSelfMac(pcap_t *adhandle,const char *ip_addr);
    // 设置本机信息：ip 、 掩码 、 Mac
    void setHostInfo(const char *devName);
    // 获取本机信息：ip 、 掩码 、 Mac
    HostInfo getHostInfo();
    // 向局域网内所有主机广播ARP请求包
    void sendArpPacket();

private:
    pcap_t * handle;
    HostInfo hostInfo;
};

#endif // PCAPCOMMON_H
