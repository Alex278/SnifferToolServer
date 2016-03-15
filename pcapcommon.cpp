#include "pcapcommon.h"
#include <QThread>
//#include <winsock.h>
#include "getmacthread.h"
#include "sendpacketthread.h"
#include "receivepacketthread.h"
#include <QDebug>


PcapCommon::PcapCommon()
{
    // 注册自定义结构参数
    qRegisterMetaType< QPair<QString,QString> >("QPair<QString,QString>");

    handle = NULL;
    memset(hostInfo.mac,0x00,6);
}

PcapCommon::~PcapCommon()
{
    pcap_freealldevs(alldevs);
    if(handle != NULL)pcap_close(handle);
}



// 扫描本机所有的适配器，并获取每个适配器的信息
QVector<DEVInfo> PcapCommon::findAllDev()
{
    QVector<DEVInfo> allDev;
    DEVInfo tempDevInfo;

    pcap_if_t *p;

    char errbuf[PCAP_ERRBUF_SIZE];

    // 获取本地机器设备列表
    if(pcap_findalldevs(&alldevs,errbuf) == -1){
        printf("Find all devices is error: %s\n",errbuf);
        exit(1);
    }

    for(p = alldevs;p;p = p->next){
        tempDevInfo.name = p->name;
        //printf("\tIS loopback address : %s\n",(p->flags & PCAP_IF_LOOPBACK)?"yes":"no");
        if(p->description){            
            tempDevInfo.description = p->description;
        }
        else{
            tempDevInfo.description = "(No description available)";
        }

        pcap_addr_t *a;

        for(a = p->addresses;a;a = a->next){
            switch(a->addr->sa_family){
                case AF_INET:                    
                    tempDevInfo.familyName = "AF_INET";
                    if (a->addr){                        
                        tempDevInfo.address = my_iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr);
                    }
                    if (a->netmask){                        
                        tempDevInfo.netmask = my_iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr);
                    }
                    if (a->broadaddr)
                        //printf("\tBroadcast Address: %s\n",my_iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
                    if (a->dstaddr)
                        //printf("\tDestination Address: %s\n",my_iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
                    break;
                case AF_INET6:                    
                    if (a->addr)
                        //printf("\tAddress: %d\n", inet_ntop(a->addr, ip6str, sizeof(ip6str)));
                    break;
                default:
                    //printf("\tAddress Family Name: Unknown\n");
                    break;
            }
        }
        allDev.append(tempDevInfo);        
    }

    return allDev;
}

// 打开一个适配器
void PcapCommon::openLiveDev(const char *dev)
{    
    char errBuf[PCAP_ERRBUF_SIZE] = {0};

    //混杂模式
    handle = pcap_open_live(dev,65535,1,0,errBuf);

    if(!handle){
        printf("Open live dev is error: %s\n",errBuf);
        exit(1);
    }
}

// 获取当前打开的适配器描述符
pcap_t *& PcapCommon::getCurrentHandle()
{
    return handle;
}

// 通过适配器名获取相应IP
QString PcapCommon::getHostIpByDevName(QString dev)
{
    pcap_if_t *p = alldevs;

    for(; p ; p = p->next){
        QString sname = p->name;
        if(dev == sname){
            pcap_addr_t *a;
            for(a = p->addresses; a ; a = a->next) {
                switch (a->addr->sa_family) {
                case AF_INET:
                    if (a->addr) {
                        char *ipstr;
                        char ipAddr[16] = {0};
                        //将地址转化为字符串
                        ipstr = my_iptos(((struct sockaddr_in *) a->addr)->sin_addr.s_addr);
                        memcpy(ipAddr, ipstr, 16);
                        return QString(ipAddr);
                    }
                    break;
                case AF_INET6:
                    continue;
                    break;
                }
            }
        }
    }
    return QString("0.0.0.0");
}

// 获取本机Mac
void PcapCommon::getSelfMac()
{
    GetMacThread *getHostMacThread = new GetMacThread(handle,hostInfo.ip);

    connect(getHostMacThread,SIGNAL(getSelfMacFinishedSig(QString)),this,SLOT(getSelfMacFinishedSlot(QString)));    

    getHostMacThread->start();
}

// 获取本机信息：ip 、 掩码 、 Mac
void PcapCommon::setHostInfo(const char *devName)
{
    pcap_if_t *alldevs;
    pcap_if_t *p;

    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    if(pcap_findalldevs(&alldevs,errbuf) == -1){
        printf("Find all devices is error: %s\n",errbuf);
        exit(1);
    }

    QString dev = QString(devName);
    for(p = alldevs ; p ; p = p->next){
        QString sname = p->name;
        if(dev == sname){
            pcap_addr_t *a;
            for(a = p->addresses ; a ; a = a->next) {
                switch (a->addr->sa_family) {
                case AF_INET:
                    if (a->addr) {
                        char *ipstr;
                        ipstr = my_iptos(((struct sockaddr_in *) a->addr)->sin_addr.s_addr);
                        memcpy(hostInfo.ip, ipstr, 16);
                    }
                    if (a->netmask) {
                        char *netmaskstr;
                        netmaskstr = my_iptos(((struct sockaddr_in *) a->netmask)->sin_addr.s_addr);
                        memcpy(hostInfo.netmask, netmaskstr, 16);
                    }
                case AF_INET6:
                    continue;
                    break;
                }
            }
        }
    }
}

// 获取本机信息：ip 、 掩码 、 Mac
HostInfo PcapCommon::getHostInfo()
{
    return hostInfo;
}

// 获取Host IP
QString PcapCommon::getHostIp()
{
    if(strlen(hostInfo.ip) <= 0)
        return QString("0.0.0.0");
    return QString(hostInfo.ip);
}

// 获取Host Mac
QString PcapCommon::getHostMac()
{
    char macStr[256] = {0};
    sprintf(macStr,"%02x-%02x-%02x-%02x-%02x-%02x",hostInfo.mac[0],hostInfo.mac[1],hostInfo.mac[2],hostInfo.mac[3], hostInfo.mac[4], hostInfo.mac[5]);

    return QString(macStr);
}

// 获取子网掩码
QString PcapCommon::getHostNetmask()
{
    if(strlen(hostInfo.netmask) <= 0)
        return QString("255.255.255.255");
    return QString(hostInfo.netmask);
}

//ipStart ipEnd是否有效
bool PcapCommon::ipStart2EndIsValid(QString ipStart,QString ipEnd)
{
    QByteArray start = ipStart.toUtf8();
    QByteArray end = ipEnd.toUtf8();
    const char *ips = start.data();
    const char *ipe = end.data();
    u_long ipsn = my_inet_addr(ips);
    u_long ipen = my_inet_addr(ipe);

    return ipen > ipsn ? true : false;
}

void PcapCommon::scanLANHost(QString ipStart,QString ipEnd)
{
    // 可New多个线程出来，防止抓包线程漏包
    SendPacketThread *sendScan = new SendPacketThread(handle,&hostInfo,
                                                      ARP_PACKET_SCAN,ipStart,ipEnd);
    // 填充以太网头，为广播方式
    u_char edestMac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    u_char adestMac[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
    sendScan->getArpPacket()->getEthernetPacket().fillEthernetHeader(hostInfo.mac,edestMac,ARP_TYPE);
    // 填充arp 头
    sendScan->getArpPacket()->fillArpPacket(ARP_HARDWARE,IP_TYPE,ARP_REQUEST,hostInfo.mac,hostInfo.ip,adestMac,"");
    // 设置待发送的ARP包完毕
    sendScan->getArpPacket()->setData();    

    // New 接收扫描线程
    ReceivePacketThread *recvScan = new ReceivePacketThread(handle,&hostInfo,ARP_PACKET_SCAN);
    connect(sendScan,SIGNAL(scanHostFinishedSig()),recvScan,SLOT(scanHostFinishedSlot()));
    connect(sendScan,SIGNAL(scanHostFinishedSig()),this,SLOT(scanHostFinishedSlot()));
    connect(sendScan,SIGNAL(scanCurrentIpSig(QString)),this,SLOT(scanCurrentIpSlot(QString)));
    connect(recvScan,SIGNAL(scanGetHostInfoSig(QPair<QString,QString>)),this,SLOT(scanGetHostInfoSlot(QPair<QString,QString>)));

    sendScan->start();
    recvScan->start();
}

u_char PcapCommon::hexStr2UChar(QString hexS)
{
    QByteArray array = hexS.toUtf8();
    char *data = array.data();
    char *str;
    u_char ret = (u_char)strtol(data,&str,16);
    //printf("%d %02x\n",ret,ret);
    return ret;
}


void PcapCommon::getSelfMacFinishedSlot(QString mac)
{     
    //printf("PcapCommon getSelfMacFinishedSlot\n");
    QStringList list = mac.split("-");
    //qDebug()<< list;
    for(int i = 0; i < list.length(); ++i){
        hostInfo.mac[i] = hexStr2UChar(list.at(i));
    }

    emit getSelfMacFinishedSig(mac);
}

void PcapCommon::scanCurrentIpSlot(QString currentIp)
{
    emit scanCurrentIpSig(currentIp);
}

void PcapCommon::scanHostFinishedSlot()
{
    emit scanHostFinishedSig();
}

void PcapCommon::scanGetHostInfoSlot(QPair<QString,QString> info)
{
    //qDebug() << info.first << " " << info.second;
    emit scanGetHostInfoSig(info);
}
