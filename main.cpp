#include "widget.h"
#include <QApplication>
#include <QDebug>

#include "pcapcommon.h"

//#define M_QStrToCStr(QStr,CStr) do{QByteArray QStr##tmp_ = QStr.toLocal8Bit();\
//                                 CStr = QStr##tmp_.data();}while(0)

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

//    unsigned long myip = my_inet_addr("10.10.1.100");
//    unsigned long mynetmask = my_inet_addr("255.255.240.0");
//    unsigned long hisip = my_htonl((myip & mynetmask));

//    printf("Host ip Num: %ld\n",hisip);

    Widget w;
    w.show();

    return a.exec();

//    Test
//    PcapCommon pcap;
//    QVector<DEVInfo> devInfo(pcap.findAllDev());
//    for(int i = 0; i < devInfo.length(); ++i){
//        qDebug()<< devInfo.at(i).name;
//    }
//    QByteArray ba = devInfo.at(devInfo.length()-1).name.toLatin1();
//    const char *devname = ba.data();
//    printf("%s\n",devname);
//    pcap.openLiveDev(devname);
//    QByteArray add = devInfo.at(devInfo.length()-1).address.toUtf8();
//    const char *hostIp = add.data();
//    qDebug() << pcap.getSelfMac();
//    pcap.setHostInfo(devname);
//    HostInfo  hostInfo = pcap.getHostInfo();
//    qDebug() << hostInfo.ip;
//    qDebug() << hostInfo.mac;
//    qDebug() << hostInfo.netmask;
//    return 0;
}

