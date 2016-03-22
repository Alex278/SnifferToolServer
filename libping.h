// ---------------------------------------------
// Ping 功能，基于winsock实现
// ---------------------------------------------
#ifndef LIBPING_H
#define LIBPING_H

#include <QObject>
#include <QThread>
#include <QQueue>
#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdexcept>
#include <exception>


//***********************************************************************************
//PingReport
//***********************************************************************************
class PingReport
{
public:
    PingReport()
    {}
    DWORD DWError;
    DWORD Status;
    QString DestAddr;
    QString ReplyAddr;
    int DataSize;
    int RoundTripTime;
    unsigned char TTL;
public:
    QString genReplyReport();
};

//***********************************************************************************
//Ping_Inst
//***********************************************************************************
class Ping_Inst:public QObject
{
    Q_OBJECT
public:
    Ping_Inst(){}
    Ping_Inst(QString Target,int CountOfPing):
        _TargetIP(Target),_CountOfPing(CountOfPing),_TimeOut(1000),_IsInfinite(false){
        qRegisterMetaType< PingReport >("PingReport");

        _HIcmpFile = IcmpCreateFile();
        if (_HIcmpFile == INVALID_HANDLE_VALUE) {
            QString error;
            error.sprintf("IcmpCreatefile returned error: %ld\n", GetLastError());
            throw std::runtime_error(qPrintable(error));
        }
        _ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(_SendData);
        _ReplyBuff=new char[_ReplySize];
        if (_ReplyBuff == NULL) {
                throw std::runtime_error("Unable to allocate memory");
            }
        memset(_ReplyBuff,'\0',_ReplySize);
    }
    void setTargetIP(QString T);
    QString getTargetIP();
    void setTimeOut(DWORD TO);
    DWORD getTimeOut();
    void setCountOfPing(int C);
    int getCountOfPing();
    void setInfinitePing(bool Choice);
    bool isInfinitePing();
signals:
    void ErrorPending(QString Error);
    void ReportPending(PingReport Report_Info);
public slots:
    void doEcho();
private:
    HANDLE _HIcmpFile;
    QString _TargetIP;
    DWORD _TimeOut;
    char _SendData[32]={0};
    int _CountOfPing=0;
    bool _IsInfinite=false;
    DWORD _ReplySize=0;
    char* _ReplyBuff=nullptr;
};

//***********************************************************************************
//PingProc
//***********************************************************************************
class PingProc:public QObject
{
    Q_OBJECT
public:
    PingProc();
    PingProc(QString Target);
    PingProc(QString Target,int CountOfPing);
    void bindInst(Ping_Inst* PI);
    void run();
signals:
    void EchoReport(QString Rep);
private slots:
    void onReport(PingReport Rep);
    void onError(QString Err);
private:
    QQueue<PingReport> _ReportQueue;
    Ping_Inst* _P_Inst;
    QThread* _P_Proc;

};
#endif // LIBPING_H
