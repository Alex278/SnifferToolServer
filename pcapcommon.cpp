#include "pcapcommon.h"
#include <QThread>
//#include <winsock.h>
#include <QDebug>


PcapCommon::PcapCommon()
{
    handle = NULL;
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

QString PcapCommon::getSelfMac(void)
{
    unsigned char mac[6] = {0};
    unsigned char sendbuf[42] = {0};
    int res;
    const char * hostIp = "10.10.1.100";
    EthernetHeader eh;
    ArpHeader ah;
    struct pcap_pkthdr * pktHeader;
    const u_char * pktData;

    if(!handle){
        printf("The Adapter is not be opened! Please Check!\n");
        return NULL;
    }
    //将已开辟内存空间 eh.dest_mac_add 的首6个字节的值设为值 0xff。
    memset(eh.DestMAC, 0xFF, 6);
    memset(eh.SourMAC, 0x00, 6);
    memset(ah.DestMacAdd, 0xFF, 6);
    memset(ah.SourceMacAdd, 0x00, 6);
    //htons将一个无符号短整型的主机数值转换为网络字节顺序
    eh.EthType = my_htons(ARP_TYPE);
    ah.HardwareType= my_htons(ARP_HARDWARE);
    ah.ProtocolType = my_htons(IP_TYPE);
    ah.HardwareAddLen = 6;
    ah.ProtocolAddLen = 4;
    ah.OperationField = my_htons(ARP_REQUEST);
    ah.DestIpAdd = my_inet_addr(hostIp);
    memset(sendbuf, 0, sizeof(sendbuf));
    memcpy(sendbuf, &eh, sizeof(eh));
    memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
    if(pcap_sendpacket(handle, sendbuf, 42) == 0) {
    }
    else{
        printf("PacketSendPacket in getmine Error:\n");
        return NULL;
    }

    union IP{
        unsigned int ip;
        unsigned char nip[4];
    }ipUnion;

    char ipStr[3*4+3+1] = {0};

    while((res = pcap_next_ex(handle, &pktHeader, &pktData)) >= 0){
        if (*(unsigned short *) (pktData + 12) == my_htons(ARP_TYPE)
                && *(unsigned short*) (pktData + 20) == my_htons(ARP_REPLY)){
            //获取Source ip
            for(int i=0; i < 4 ; i++){
                ipUnion.nip[i] = *(unsigned char *)(pktData + 28 + i);
            }
            iptos(ipUnion.ip,ipStr);
            //收到的arp包的源ip等于本机ip,则获取本机Mac（源Mac）
            if(strncmp(hostIp,ipStr,strlen(hostIp)) == 0){
                for(int i = 0; i < 6; i++) {
                    mac[i] = *(unsigned char *) (pktData + 22 + i);
                }
                break;
            }
            //获取接收的Dest ip
            for(int i = 0; i < 4 ; i++){
                ipUnion.nip[i] = *(unsigned char *)(pktData + 38 + i);
            }
            iptos(ipUnion.ip,ipStr);
            //收到的arp包的源ip等于本机ip,则获取本机Mac（源Mac）
            if(strncmp(hostIp,ipStr,strlen(hostIp)) == 0){
                for (int i = 0; i < 6; i++) {
                    mac[i] = *(unsigned char *) (pktData + 32 + i);
                }
                break;
            }
        }
        else{
            qDebug() << "Not Reply Packet";
        }
    }

    char macStr[256] = {0};
    sprintf(macStr,"%02x-%02x-%02x-%02x-%02x-%02x",mac[0],mac[1],mac[2],mac[3], mac[4], mac[5]);
    printf("thread get mac: %s\n ",macStr);

    return QString(macStr);
}


// 获取本机Mac
void PcapCommon::getSelfMac(const char *devname,const char *ipAddr)
{    
    GetMacThread * getHostMacThread = new GetMacThread(devname,ipAddr);

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

// 向局域网内所有主机广播ARP请求包
/*
void PcapCommon::sendArpPacket()
{
    pcap_t *adhandle = handle;
    char *ip = hostInfo.ip;
    unsigned char *mac = hostInfo.mac;
    char *netmask = hostInfo.netmask;
    //printf("Host Mac:%02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2],mac[3], mac[4], mac[5]);
    //printf("Host Ip:%s\n", ip);
    //printf("Host Netmask:%s\n", netmask);
    unsigned char sendbuf[42];
    EthernetHeader eh;
    ArpHeader ah;
    // 赋值MAC地址
    memset(eh.DestMAC, 0xff, 6);
    memcpy(eh.SourMAC, mac, 6);
    memcpy(ah.SourceMacAdd, mac, 6);
    memset(ah.DestMacAdd, 0x00, 6);
    eh.EthType = my_htons(ARP_TYPE);
    ah.HardwareType = my_htons(ARP_HARDWARE);
    ah.ProtocolType = my_htons(IP_TYPE);
    ah.HardwareAddLen = 6;
    ah.ProtocolAddLen = 4;
    ah.SourceIpAdd = my_inet_addr(ip);
    ah.OperationField = my_htons(ARP_REQUEST);
    // 向局域网内广播发送arp包
    unsigned long myip = my_inet_addr(ip);
    unsigned long mynetmask = my_inet_addr(netmask);
    unsigned long hisip = my_htonl((myip & mynetmask));

    printf("Host ip Num: %ld\n",hisip);
    // 向N个主机发送
    char ipStr[4] = {0};
    for(unsigned int i = 0; i < hisip; i++){
        ah.DestIpAdd = my_htonl(hisip + i);
        printf("send ip: %s \n",iptos(ah.DestIpAdd,ipStr));
        // 构造一个ARP请求
        memset(sendbuf, 0, sizeof(sendbuf));
        memcpy(sendbuf, &eh, sizeof(eh));
        memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
        // 如果发送成功
        if (pcap_sendpacket(adhandle, sendbuf, 42) == 0){
            //printf("\nPacketSend succeed\n");
        } else {
            printf("PacketSendPacket in getmine Error");
        }
        // 每隔多少微秒向指定ip发送ARP包
        QThread::usleep(100000);
    }
}
*/



void PcapCommon::getSelfMacFinishedSlot(QString mac)
{
    printf("PcapCommon getSelfMacFinishedSlot \n");
    emit getSelfMacFinishedSig(mac);
}
