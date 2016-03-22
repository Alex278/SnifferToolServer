#ifndef SYN_SCAN_H
#define SYN_SCAN_H

#include <QFile>
#include <QObject>
#include <cstdlib>
#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdexcept>
#include <QThread>
#include "libnet.h"

class SYN_Scan_Inst:public QObject
{
    Q_OBJECT
public:
    SYN_Scan_Inst()=delete;
    SYN_Scan_Inst(const SYN_Scan_Inst&)=delete;
    const SYN_Scan_Inst& operator=(const SYN_Scan_Inst&)=delete;
    SYN_Scan_Inst(const char* Device)
    {
        _Device=Device;
        _Handle=libnet_init(
                        LIBNET_RAW4,
                        Device,
                        _Error_Buf
                        );
        _Src_Port=(std::rand()%10000)+30000;
    }
    ~SYN_Scan_Inst()
    {
        libnet_destroy(_Handle);
    }
    void setSourceIP(char* IP)
    {
        if(_Handle==NULL)
        {
            throw std::runtime_error("libnet handle without init");
        }
        _Src_IP=libnet_name2addr4(_Handle,IP,LIBNET_RESOLVE);
    }
    void setDestinationIP(char* IP)
    {
        if(_Handle==NULL)
        {
            throw std::runtime_error("libnet handle without init");
        }
        _Dst_Ip=libnet_name2addr4(_Handle,IP,LIBNET_RESOLVE);
    }
    void setPortRange(u_short BeginPort, u_short EndPort)
    {
        if(_Handle==NULL)
        {
            throw std::runtime_error("libnet handle without init");
        }
        if(BeginPort>EndPort)
        {
            throw std::invalid_argument("the value of port invaild");
        }
        _Begin_Port=BeginPort;
        _End_Port=EndPort;
    }
signals:
    SYN_SCanFinished();
    ErrorPending(QString Error);
    StatusPending(QString Report_Info);
public slots:
    void doSend()
    {
        for(int cur_port=_Begin_Port;cur_port<=_End_Port;cur_port++)
        {
            _Protocol_Tag=libnet_build_tcp(
                         _Src_Port,         //源端口
                         cur_port,    //目的端口
                         1006,          //序列号
                         1006,          //确认序列号
                         TH_SYN,        //控制标记
                         1024,          //窗口大小
                         0,             //校验和
                         0,             //紧急指针
                         LIBNET_TCP_H, //数据包大小
                         NULL,          //负载
                         0,             //负载大小
                         _Handle,       //libnet句柄
                         0              //协议标记
                         );
            _Protocol_Tag=libnet_build_ipv4(
                        LIBNET_IPV4_H+LIBNET_TCP_H,//包的长度
                        0,                      //服务质量 tos
                        10,                     //标识
                        0,                      //flag偏移
                        64,                    //TTL
                        IPPROTO_TCP,            //协议
                        0,                      //校验和
                        _Src_IP,            //源地址
                        _Dst_Ip,            //目的地址
                        NULL,               //负载指针
                        0,
                        _Handle,
                        0
                        );
            int packet_size=libnet_write(_Handle);
            emit StatusPending("Send "+QString::number(cur_port)+" "+QString::number(packet_size));
            libnet_clear_packet(_Handle);
            QThread::usleep(200);
        }
        //槽函数完了以后退出线程
        //this->thread()->exit(0);
    }
private:
    QString _Device;
    u_short _Src_Port=0;
    u_short _Begin_Port=0;
    u_short _End_Port=0;
    u_long _Src_IP=0;
    u_long _Dst_Ip=0;
    libnet_t* _Handle=NULL;
    libnet_ptag_t _Protocol_Tag=0;
    char _Error_Buf[LIBNET_ERRBUF_SIZE]={0};

};

//class SYN_Scan_Proc
//{
//public:
//    SYN_Scan();

//};
#endif // SYN_SCAN_H
