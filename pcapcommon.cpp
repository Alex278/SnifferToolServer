#include "pcapcommon.h"
#include <QThread>
#include <windows.h>
#include <winsock.h>
#include <Iphlpapi.h>
#include "getmacthread.h"
#include "receivepacketthread.h"
#include "trafficstatistic.h"
#include "libping.h"
#include <QDebug>



PcapCommon::PcapCommon()
{
    // 注册自定义结构参数
    qRegisterMetaType< QPair<QString,QString> >("QPair<QString,QString>");

    handle = NULL;
    pcapStatus = false;
    memset(hostInfo.mac,0x00,6);
    //
    //filterThread
    //
    hostInfoBuffer = new QQueue< QPair<QString,QString> >;
    filterDataBuffer = new QQueue< QString >;
    sendThreadAdd = new QMap< QString,SendPacketThread* >;

    // 取数据定时器
    getDataFromQQueueTimer = new QTimer();
    connect(getDataFromQQueueTimer, SIGNAL(timeout()), this, SLOT(getDataFromQQueueTimerUpdateSlot()));
    getDataFromQQueueTimer->start(400);
    // 取filter缓冲数据定时器
    getDataFromFilterBufferTimer = new QTimer();
    connect(getDataFromFilterBufferTimer,SIGNAL(timeout()),this,SLOT(getDataFromFilterBufferSlot()));
    getDataFromFilterBufferTimer->start(300);
}

PcapCommon::~PcapCommon()
{
    delete getDataFromQQueueTimer;
    pcap_freealldevs(alldevs);
    WSACleanup();
    if(handle != NULL)pcap_close(handle);
}


// Windows Socket 初始化
void PcapCommon::winSocketInit()
{
    WSADATA wsaData;
    // 调用Windows Sockets DLL
    if (WSAStartup(MAKEWORD(2,1),&wsaData)){
        qDebug() << tr("Winsock无法初始化!");
        WSACleanup();
        return ;
    }
}

// 设置Pcap的状态
void PcapCommon::setPcapStatus(bool status)
{
    pcapStatus = status;
}

// 获取Pcap的状态
bool PcapCommon::getPcapStatus()
{
    return pcapStatus;
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

// 获取Host IP(通过winsock2)
QString PcapCommon::getHostIpByWinSock()
{
    char hostname[256] = {0};    
    char ip[128] = {0};

    if(gethostname(hostname, sizeof(hostname)) == 0){
        // 结构
        struct hostent * pHost;
        pHost = gethostbyname(hostname);
        //只取主网卡 ip
        BYTE *p;
        p =(BYTE *)pHost->h_addr;
        sprintf(ip,"%d.%d.%d.%d", p[0], p[1],p[2], p[3]);
    }

    return QString(ip);
}

// 获取本机网关(通过winsock2)
QString PcapCommon::getGateway()
{
    // PIP_ADAPTER_INFO结构体指针存储本机网卡信息
    PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
    // 得到结构体大小,用于GetAdaptersInfo参数
    unsigned long stSize = sizeof(IP_ADAPTER_INFO);
    // 调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量;其中stSize参数既是一个输入量也是一个输出量
    int nRel = GetAdaptersInfo(pIpAdapterInfo,&stSize);
    // 记录网卡数量
    // int netCardNum = 0;
    // 记录每张网卡上的IP地址数量
    // int IPnumPerNetCard = 0;
    if (ERROR_BUFFER_OVERFLOW == nRel){
        // 如果函数返回的是ERROR_BUFFER_OVERFLOW
        // 则说明GetAdaptersInfo参数传递的内存空间不够,同时其传出stSize,表示需要的空间大小
        // 这也是说明为什么stSize既是一个输入量也是一个输出量
        // 释放原来的内存空间
        delete pIpAdapterInfo;
        // 重新申请内存空间用来存储所有网卡信息
        pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
        // 再次调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量
        nRel=GetAdaptersInfo(pIpAdapterInfo,&stSize);
    }
    if (ERROR_SUCCESS == nRel){
        // 输出网卡信息
        //可能有多网卡,因此通过循环去判断
        while (pIpAdapterInfo){
            //cout<<"Net Card Num:"<<++netCardNum<<endl;
            //cout<<"Net Card Name:"<<pIpAdapterInfo->AdapterName<<endl;
            //cout<<"Net Card Dis:"<<pIpAdapterInfo->Description<<endl;
            switch(pIpAdapterInfo->Type){
            case MIB_IF_TYPE_OTHER:
                //cout<<"Net Card Type:"<<"OTHER"<<endl;
                break;
            case MIB_IF_TYPE_ETHERNET:
                //cout<<"Net Card Type:"<<"ETHERNET"<<endl;
                break;
            case MIB_IF_TYPE_TOKENRING:
                //cout<<"Net Card Type:"<<"TOKENRING"<<endl;
                break;
            case MIB_IF_TYPE_FDDI:
                //cout<<"Net Card Type:"<<"FDDI"<<endl;
                break;
            case MIB_IF_TYPE_PPP:
                //printf("PP\n");
                //cout<<"Net Card Type:"<<"PPP"<<endl;
                break;
            case MIB_IF_TYPE_LOOPBACK:
                //cout<<"Net Card Type:"<<"LOOPBACK"<<endl;
                break;
            case MIB_IF_TYPE_SLIP:
                //cout<<"Net Card Type:"<<"SLIP"<<endl;
                break;
            default:

                break;
            }
            //cout<<"Net Card MAC Add:";
            for (DWORD i = 0; i < pIpAdapterInfo->AddressLength; i++)
                if (i < pIpAdapterInfo->AddressLength-1){
                    //printf("%02X-", pIpAdapterInfo->Address[i]);
                }
                else{
                    //printf("%02X\n", pIpAdapterInfo->Address[i]);
                }
                //cout<<"Net Card IP Add:"<<endl;
                // 可能网卡有多IP,因此通过循环去判断
                IP_ADDR_STRING *pIpAddrString =&(pIpAdapterInfo->IpAddressList);
                do{
                    //cout<<"The Net Card IP Num:"<<++IPnumPerNetCard<<endl;
                    //cout<<"IP Add:"<<pIpAddrString->IpAddress.String<<endl;
                    if(QString(pIpAddrString->IpAddress.String) == getHostIpByWinSock()){
                        //qDebug()<< QString(pIpAddrString->IpAddress.String);
                        return QString(pIpAdapterInfo->GatewayList.IpAddress.String);
                    }
                    //cout<<"NetMask:"<<pIpAddrString->IpMask.String<<endl;
                    //cout<<"Gateway:"<<pIpAdapterInfo->GatewayList.IpAddress.String<<endl;
                    pIpAddrString=pIpAddrString->Next;
                } while (pIpAddrString);
                pIpAdapterInfo = pIpAdapterInfo->Next;
                //cout<<"--------------------------------------------------------------------"<<endl;
        }

    }
    //释放内存空间
    if (pIpAdapterInfo){
        delete pIpAdapterInfo;
    }

    return "0.0.0.0";
}

// 设置网关
void PcapCommon::setGatewayMac(QString gatewayMac)
{
    // 转化网关MAC
    QStringList list2 = gatewayMac.split("-");
    for(int i = 0; i < list2.length(); ++i){
        hostInfo.gatewayMac[i] = hexStr2UChar(list2.at(i));
    }
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
    char iptemp[] = "";
    sendScan->getArpPacket()->fillArpPacket(ARP_HARDWARE,IP_TYPE,ARP_REQUEST,hostInfo.mac,hostInfo.ip,adestMac,iptemp);
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

// ARP欺骗指定主机
void PcapCommon::arpCheatHost(QString cheatIp,QString cheatMac,QString gatewayMac)
{
    //qDebug()<< cheatIp << " " << cheatMac;

    HostInfo cheatHostInfo;
    memset(&cheatHostInfo,0,sizeof(HostInfo));
    // 转化目标MAC
    QStringList list1 = cheatMac.split("-");
    for(int i = 0; i < list1.length(); ++i){
        cheatHostInfo.mac[i] = hexStr2UChar(list1.at(i));
    }
    // 转化网关MAC
    QStringList list2 = gatewayMac.split("-");
    for(int i = 0; i < list2.length(); ++i){
        cheatHostInfo.gatewayMac[i] = hexStr2UChar(list2.at(i));
        hostInfo.gatewayMac[i] = hexStr2UChar(list2.at(i));
    }
    // 转换目标IP
    QByteArray byteArray = cheatIp.toUtf8();
    char * cstring = byteArray.data();
    memcpy(cheatHostInfo.ip,cstring,cheatIp.length());
    // 转换网关
    QString gatewayIp = getGateway();
    byteArray = gatewayIp.toUtf8();
    cstring = byteArray.data();
    memcpy(hostInfo.getwayIp,cstring,gatewayIp.length());
    memcpy(cheatHostInfo.getwayIp,cstring,gatewayIp.length());

    // 可New多个线程出来，防止抓包线程漏包
    SendPacketThread *sendCheat = new SendPacketThread(handle,&hostInfo,
                                                      ARP_PACKET_CHEAT,&cheatHostInfo);
    // 保存线程地址，用以停止指定ARP攻击    
    if(!sendThreadAdd->contains(cheatIp)){
        sendThreadAdd->insert(sendCheat->getTheCheatHostIp(),sendCheat);
    }

    // 设定ip和mac，并开始攻击
    // 主机欺骗
    sendCheat->getArpPacket()->getEthernetPacket().fillEthernetHeader(hostInfo.mac,cheatHostInfo.gatewayMac,ARP_TYPE);
    sendCheat->getArpPacket()->fillArpPacket(ARP_HARDWARE,IP_TYPE,ARP_REQUEST,hostInfo.mac,cheatHostInfo.ip,hostInfo.gatewayMac,hostInfo.getwayIp);
    sendCheat->getArpPacket()->setData();
    sendCheat->start();

    // 网关欺骗，不能有效，以太头源mac为广播地址
//    u_char broadcastmac[] = {0xff,0xff,0xff,0xff,0xff,0xff};
//    SendPacketThread *sendCheat1 = new SendPacketThread(handle,&hostInfo,ARP_PACKET_CHEAT,&cheatHostInfo);
//    sendCheat1->getArpPacket()->getEthernetPacket().fillEthernetHeader(broadcastmac,cheatHostInfo.mac,ARP_TYPE);
//    sendCheat1->getArpPacket()->fillArpPacket(ARP_HARDWARE,IP_TYPE,ARP_REPLY,hostInfo.mac,cheatHostInfo.getwayIp,cheatHostInfo.mac,cheatHostInfo.ip);
//    sendCheat1->getArpPacket()->setData();
//    sendCheat1->start();
}

// 退出ARP Cheat Thread
void PcapCommon::quitArpCheatThread(QString cheatIp)
{
    QMap< QString,SendPacketThread * >::const_iterator iterator = sendThreadAdd->begin();
    while(iterator != sendThreadAdd->end()){
        if(iterator.key() == cheatIp){
            iterator.value()->quitThread();
            sendThreadAdd->remove(cheatIp);
            break;
        }
        ++iterator;
    }
}

// 统计本机流量
void PcapCommon::trafficStatistic(const char *dev)
{
    qDebug()<< "Start traffic statistic!";
    TrafficStatistic * trafficStatistic = new TrafficStatistic(&hostInfo,dev);

    connect(trafficStatistic,SIGNAL(trafficStatisticNetSpeedSig(QString)),this,SLOT(trafficStatisticNetSpeedSlot(QString)));

    trafficStatistic->start();
}

// 应用过滤规则
void PcapCommon::applyFilter(const char *dev,QString filter)
{
    qDebug()<< "Start applyFilter!";    
    //
    filterThread = new FilterThread(&hostInfo,dev,filter);

    connect(filterThread,SIGNAL(filterUpdateDataSig(QString)),this,SLOT(filterUpdateDataSlot(QString)));
    connect(filterThread,SIGNAL(filterStatusSig(int,QString)),this,SLOT(filterStatusSlot(int,QString)));
    //    
    filterThread->start();
}

// 停止过滤
void PcapCommon::stopFilter()
{
    filterDataBuffer->clear();    
    if(filterThread->isRunning())
        filterThread->quitThread();
}

// 获取当前过滤线程的状态：停止or运行中
bool PcapCommon::getFilterThreadStatus()
{
    if(!filterThread)return false;
    if(filterThread->isRunning())
        return true;
    return false;
}

// Ping Ip
void PcapCommon::applyPing(QString ip,int num)
{
    qDebug()<< "Apply ping ip = " << ip << " " << num;
    //前面设置IP后面设置ping的次数
    PingProc *ping_proc=new PingProc(ip,num);
    //连接ping_Proc的信号EchoReport就可以得到ping的结果
    //使用C++11的lambda表达式做槽
    QObject::connect(ping_proc,&PingProc::EchoReport,[=](QString rep)
    {
        //qDebug("%s",qPrintable(rep));
        emit pingUpdateEchoSig(rep);
    });

    ping_proc->run();
}

// 端口扫描:
void PcapCommon::applyPortScan(const char *device,QString ip,QString scanMac,u_short startPort,u_short endPort)
{
//    qDebug() << ip << " " << startPort << " " << endPort;
    // 转化目标MAC
    HostInfo targetHost;
    QStringList list1 = scanMac.split("-");
    for(int i = 0; i < list1.length(); ++i){
        targetHost.mac[i] = hexStr2UChar(list1.at(i));
    }
    // 转换目标IP
    QByteArray byteArray = ip.toUtf8();
    char * cstring = byteArray.data();
    memcpy(targetHost.ip,cstring,ip.length());
    //
    SendPacketThread *sendPortScan = new SendPacketThread(device,&hostInfo,TCP_PACKET,&targetHost,startPort,endPort);
    //SendPacketThread *sendPortScan = new SendPacketThread(handle,&hostInfo,TCP_PACKET,&targetHost,startPort,endPort);
    ReceivePacketThread *recvPortScan = new ReceivePacketThread(handle,&hostInfo,TCP_PACKET,ip);
    connect(sendPortScan,SIGNAL(finished()),recvPortScan,SLOT(scanHostFinishedSlot()));
    connect(sendPortScan,SIGNAL(finished()),this,SLOT(portScanIsFinishedSlot()));
    connect(recvPortScan,SIGNAL(portScanRecvUpdataSig(QString)),this,SLOT(portScanRecvUpdataSlot(QString)));
    sendPortScan->start();
    recvPortScan->start();
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
    hostInfoBuffer->enqueue(info);
}

void PcapCommon::getDataFromQQueueTimerUpdateSlot()
{
    QPair<QString ,QString> info;
    // ip , hostname , mac
    if(!hostInfoBuffer->isEmpty()){
        info = hostInfoBuffer->dequeue();
        emit scanGetHostInfoSig(info);
    }
}

void PcapCommon::getDataFromFilterBufferSlot()
{
    if(!filterDataBuffer->isEmpty()){
        QString data = filterDataBuffer->dequeue();
        emit filterUpdateDataSig(data);
    }
}

void PcapCommon::trafficStatisticNetSpeedSlot(QString netSpeed)
{
    emit trafficStatisticNetSpeedSig(netSpeed);
}

void PcapCommon::filterUpdateDataSlot(QString data)
{
    filterDataBuffer->enqueue(data);
}

void PcapCommon::filterStatusSlot(int num,QString msg)
{
    emit filterStatusSig(num,msg);
}

// 端口扫描结束
void PcapCommon::portScanIsFinishedSlot()
{
    emit portScanIsFinishedSig();
}

// 端口扫描获取SYN-ACK更新
void PcapCommon::portScanRecvUpdataSlot(QString msg)
{
    emit portScanRecvUpdataSig(msg);
}
