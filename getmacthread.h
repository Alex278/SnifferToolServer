#ifndef GETMACTHREAD_H
#define GETMACTHREAD_H

#include <QThread>
#include "pcap.h"
#include "tcpipcommon.h"

class GetMacThread : public QThread
{
    Q_OBJECT

public:
    GetMacThread():handle(NULL){}
    GetMacThread(const char *devname,const char *ipAddr);
    QString getSelfMac();
    void run();

private:
    pcap_t *handle;
    char hostIp[16];
signals:
    void getSelfMacFinishedSig(QString mac);

};

#endif // GETMACTHREAD_H
