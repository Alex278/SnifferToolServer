// ---------------------------------------------
// 本机流量统计单线程
// ---------------------------------------------
#ifndef TRAFFICSTATISTIC_H
#define TRAFFICSTATISTIC_H

#include <QThread>
#include <stdlib.h>
#include "pcap.h"
#include "tcpipcommon.h"
#include "tcpipprotocol.h"

class TrafficStatistic : public QThread
{
    Q_OBJECT
public:
    explicit TrafficStatistic();
    TrafficStatistic(HostInfo *hostInfo,const char *dev);
    ~TrafficStatistic();
private:
    bool init();
    void statistic();    
    void run();

private:
    pcap_t * handle;
    HostInfo *hostInfo;    
    u_int netmask;
    bpf_program fcode;
    struct timeval oldts;
    struct timeval newts;
signals:
    void trafficStatisticNetSpeedSig(QString);
public slots:
};

#endif // TRAFFICSTATISTIC_H
