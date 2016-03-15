#ifndef TCPIPPROTOCOL_H
#define TCPIPPROTOCOL_H

#include "tcpipcommon.h"
#include <QString>


namespace TcpIpProtocol {
    class YEthernetPacket;
    class YArpPacket;
    class YIPPacket;
    class YTcpPacket;
    class YUdpPacket;
    class YHttPPacket;
}


//***********************************************************************************
//YEthernetPacket Class
//***********************************************************************************
class YEthernetPacket
{
public:
    YEthernetPacket();

public:
    /** 单独设置 **/
    // setSrcMac(0xFF,0xFF,0xFF,0xFF,0xFF,0xFF);
    void setSrcMac(u_char m0,u_char m1,u_char m2,u_char m3,u_char m4,u_char m5);
    // setDestMac(0xFF,0xFF,0xFF,0xFF,0xFF,0xFF);
    void setDestMac(u_char m0,u_char m1,u_char m2,u_char m3,u_char m4,u_char m5);
    // setType(0x0806);
    void setType(u_short type);
    // void getData(&dataStruct);
    u_char* getData();
    /** 一次设置 **/
    void fillEthernetHeader(u_char* srcMac, u_char* detMac, u_short type);
private:    
    u_char data[ETHERNET_HEAD_LENGTH];
};


//***********************************************************************************
//YArpPacket Class
//***********************************************************************************
class YArpPacket
{
public:
    YArpPacket();
public:
    // setHardwareType(ARP_HARDWARE);
    void setHardwareType(u_short type = 0x0001);
    //
    void setProtocolType(u_short type = 0x0800);
    //
    void setHardwareAddLen(u_char len = 0x06);
    //
    void setProtocolAddLen(u_char len = 0x04);
    //
    void setOperationField(u_short type);
    //
    void setSourceMacAdd(u_char m0,u_char m1,u_char m2,u_char m3,u_char m4,u_char m5);
    //
    void setSourIpAdd(u_int);
    //
    void setSourIpAdd(const char *ipStr);
    //
    void setDestMacAdd(u_char m0,u_char m1,u_char m2,u_char m3,u_char m4,u_char m5);\
    //
    void setDestIpAdd(u_int);
    //
    void setDestIpAdd(const char *ipStr);
    /** fillArpPacket 硬件len=6,协议len=4已默认 **/
    void fillArpPacket(u_short hdType,u_short proType,u_short opFilt,
                       u_char *srcMac,char *srcIp,u_char *destMac,char *destIp);
    // 将EthernetHeader 和 ArpHeader 整合成ArpPacket data
    void setData();
    void setData(const u_char *data);
    /** 获取数据 **/
    //
    u_char * getData();
    //
    u_short getEtherNetType();
    //
    u_short getHardwareType();
    //
    u_short getProtocolType();
    //
    u_short getOperationField();
    //
    QString getSourceMacAdd();
    //
    u_long getSourceIpAdd();
    //
    u_long getDestIpAdd();
    //
    QString getDestMacAdd();
    //
    YEthernetPacket &getEthernetPacket();
private:
    YEthernetPacket etherPacket;
    ArpPacket arpPacket;
    ArpHeader arpBody;
    u_char data[ARP_PACKET_LENGTH];
};

//***********************************************************************************
//YIPPacket Class
//***********************************************************************************
class YIPPacket
{

};

//***********************************************************************************
//YTcpPacket Class
//***********************************************************************************
class YTcpPacket
{

};

//***********************************************************************************
//YUdpPacket Class
//***********************************************************************************
class YUdpPacket
{

};

//***********************************************************************************
//YHttPPacket Class
//***********************************************************************************
class YHttPPacket
{

};

#endif // TCPIPPROTOCOL_H
