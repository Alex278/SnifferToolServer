#include "libping.h"


//***********************************************************************************
//PingReport
//***********************************************************************************
QString PingReport::genReplyReport()
{
    QString result;
    if(DWError==0)
    {
    switch (Status) {
        case IP_SUCCESS:
            result=QObject::tr("来自 ");
            result+=ReplyAddr+QObject::tr(" 的回复:");
            result+=QObject::tr(" 字节=")+QString::number(DataSize);
            result+=QObject::tr(" 时间=")+QString::number(RoundTripTime);
            result+=QObject::tr(" TTL=")+QString::number((int)(TTL));
        break;
        case IP_DEST_HOST_UNREACHABLE:
            result=QObject::tr("来自 ");
            result+=ReplyAddr+QObject::tr(" 的回复: ");
            result+=QObject::tr("目标主机不可到达");
        break;
        case IP_DEST_NET_UNREACHABLE:
            result=QObject::tr("来自 ");
            result+=ReplyAddr+QObject::tr(" 的回复: ");
            result+=QObject::tr("目标网络不可到达");
        break;
        case IP_REQ_TIMED_OUT:
            result=QObject::tr("请求超时");
            break;
        default:
            result=QObject::tr("Ping发生了未知错误");
        break;
        }
    }else{
        switch (DWError) {
            case IP_BUF_TOO_SMALL:
                result=QObject::tr("应答缓冲太小");
                break;
            case IP_REQ_TIMED_OUT:
                result=QObject::tr("请求超时");
                break;
            default:
                result.sprintf("Extended error returned: %ld\n", DWError);
                break;
           }
    }
    return result;
 }


//***********************************************************************************
//Ping_Inst
//***********************************************************************************
void Ping_Inst::setTargetIP(QString T)
{
    _TargetIP=T;
}

QString Ping_Inst::getTargetIP()
{
    return _TargetIP;
}

void Ping_Inst::setTimeOut(DWORD TO)
{
    _TimeOut=TO;
}

DWORD Ping_Inst::getTimeOut()
{
    return _TimeOut;
}

void Ping_Inst::setCountOfPing(int C)
{
    _CountOfPing=C;
}

int Ping_Inst::getCountOfPing()
{
    return _CountOfPing;
}

void Ping_Inst::setInfinitePing(bool Choice)
{
    _IsInfinite=Choice;
}

bool Ping_Inst::isInfinitePing()
{
    return _IsInfinite;
}

void Ping_Inst::doEcho()
{
    unsigned long ipaddr =inet_addr(qPrintable(_TargetIP));
    DWORD dwRetVal;
    for(int i=0;(i<_CountOfPing)||(_IsInfinite);i++){
        dwRetVal = IcmpSendEcho2(_HIcmpFile, NULL,NULL,NULL,ipaddr, _SendData, sizeof(_SendData),
                NULL, _ReplyBuff, _ReplySize, _TimeOut);

        if (dwRetVal != 0) {
            PingReport ret;
            PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)_ReplyBuff;
            PIP_OPTION_INFORMATION pEchoIpHeader=(PIP_OPTION_INFORMATION)&pEchoReply->Options;
            struct in_addr ReplyAddr;
            ReplyAddr.S_un.S_addr = pEchoReply->Address;
            ret.DWError=0;
            ret.DestAddr=_TargetIP;
            ret.ReplyAddr=QString(inet_ntoa(ReplyAddr));
            ret.RoundTripTime=pEchoReply->RoundTripTime;
            ret.Status=pEchoReply->Status;
            ret.TTL=pEchoIpHeader->Ttl;
            ret.DataSize=pEchoReply->DataSize;
            emit ReportPending(ret);
        }else {
            //QString err;
            //err.sprintf("Call to IcmpSendEcho2 failed. and IcmpSendEcho returned error:%ld",GetLastError());
            PingReport ret;
            ret.DWError=GetLastError();
            emit ReportPending(ret);
            //emit ErrorPending(err);
            //return;
        }
    }    
}

//***********************************************************************************
//PingProc
//***********************************************************************************
PingProc::PingProc()
{
    //_P_Inst=new Ping_Inst;
     _P_Inst = NULL;
    _P_Proc=new QThread;
}

PingProc::PingProc(QString Target)
{
    _P_Proc=new QThread;
    bindInst(new Ping_Inst(Target,4));
}

PingProc::PingProc(QString Target,int CountOfPing)
{
    //_P_Inst=new Ping_Inst(Target,CountOfPing);
    _P_Proc=new QThread;
    bindInst(new Ping_Inst(Target,CountOfPing));
}

void PingProc::bindInst(Ping_Inst* PI)
{
   if(_P_Proc->isRunning())
   {
       throw std::runtime_error("You Can't bing Ping Instance to a running thread!");
   }

    _P_Inst=PI;
    QObject::connect(_P_Inst,&Ping_Inst::ReportPending,this,&PingProc::onReport,Qt::DirectConnection);
    QObject::connect(_P_Inst,&Ping_Inst::ErrorPending,this,&PingProc::onError,Qt::DirectConnection);
    QObject::connect(_P_Proc,&QThread::started,_P_Inst,&Ping_Inst::doEcho,Qt::QueuedConnection);
    QObject::connect(_P_Proc,&QThread::finished,_P_Inst,&Ping_Inst::deleteLater);
}

void PingProc::run()
{
    if(_P_Inst==NULL)
    {
        throw std::runtime_error("You should Bind Ping Instance first");
    }
    _P_Inst->moveToThread(_P_Proc);
    emit EchoReport("正在Ping "+_P_Inst->getTargetIP());
    _P_Proc->start();

}

void PingProc::onReport(PingReport Rep)
{
    //如果Ping的次数太多则不使用队列
    if (_ReportQueue.size()<50)
    {
        _ReportQueue.enqueue(Rep);
    }
    QString curRep=Rep.genReplyReport();
    emit EchoReport(curRep);
}
void PingProc::onError(QString Err)
{
    qDebug("%s",qPrintable(Err));
}
