#include "widget.h"
#include <QApplication>
#include <QDebug>

#include "pcapcommon.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

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
//    pcap.openLiveDev(devname);
//    QByteArray add = devInfo.at(devInfo.length()-1).address.toUtf8();
//    const char *hostIp = add.data();
//    qDebug() << pcap.getSelfMac(pcap.getCurrentHandle(),hostIp);
//    pcap.setHostInfo(devname);
//    HostInfo  hostInfo = pcap.getHostInfo();
//    qDebug() << hostInfo.ip;
//    qDebug() << hostInfo.mac;
//    qDebug() << hostInfo.netmask;
//    pcap_close(pcap.getCurrentHandle());
//    return 0;
}

