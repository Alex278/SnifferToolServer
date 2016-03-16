#include "tcpipprotocol.h"

//***********************************************************************************
//EthernetPacket Class
//***********************************************************************************
YEthernetPacket::YEthernetPacket()
{

}

void YEthernetPacket::fillEthernetHeader(u_char* srcMac, u_char* detMac, u_short type)
{
    memset(data,0,ETHERNET_HEAD_LENGTH);
    EthernetHeader* ethHdr = (EthernetHeader*)data;

    memcpy(ethHdr->SourMAC, srcMac, sizeof(u_char) * 6);
    memcpy(ethHdr->DestMAC, detMac, sizeof(u_char) * 6);
    ethHdr->EthType = my_htons(type);
}

u_char* YEthernetPacket::getData()
{
    return data;
}

//***********************************************************************************
//ArpPacket Class
//***********************************************************************************
YArpPacket::YArpPacket()
{
    memset(data,0,ARP_PACKET_LENGTH);
}

//
YEthernetPacket &YArpPacket::getEthernetPacket()
{
    return etherPacket;
}

void YArpPacket::setDestIpAdd(u_int hdestIp)
{
    ArpPacket *packet = (ArpPacket *)data;
    memcpy(packet->ah.DestIpAdd,(u_char*)&hdestIp,4);
}

// fillArpPacket 硬件len=6,协议len=4已默认
void YArpPacket::fillArpPacket(u_short hdType,u_short proType,u_short opFilt,
                   u_char* srcMac,char *srcIp,u_char *destMac,char *destIp)
{
    ArpHeader *ah = &arpBody;

    ah->HardwareAddLen = 6;
    ah->ProtocolAddLen = 4;

    ah->HardwareType = my_htons(hdType);
    ah->ProtocolType = my_htons(proType);
    ah->OperationField = my_htons(opFilt);
    memcpy(ah->SourceMacAdd, srcMac, 6);
    memcpy(ah->DestMacAdd, destMac, 6);    
    u_long srcIpN = my_htonl(my_inet_addr(srcIp));
    memcpy(ah->SourceIpAdd,(u_char*)&srcIpN,4);
    u_long destIpN = my_htonl(my_inet_addr(destIp));
    memcpy(ah->DestIpAdd,(u_char*)&destIpN,4);
}

// 将EthernetHeader 和 ArpHeader 整合成ArpPacket data
void YArpPacket::setData()
{
    memcpy(data,etherPacket.getData(),ETHERNET_HEAD_LENGTH);
    memcpy(data+ETHERNET_HEAD_LENGTH,&arpBody,ARP_BODY_LENGTH);
}

void YArpPacket::setData(const u_char *data)
{
    memcpy(this->data,data,ARP_PACKET_LENGTH);
}

void YArpPacket::clearData()
{
    memset(data,0x00,ARP_PACKET_LENGTH);
}

u_char * YArpPacket::getData()
{
    return data;
}

u_short YArpPacket::getEtherNetType()
{
    u_short etherType = (*(u_short *)(data + 12));
    return etherType;
}

//
u_short YArpPacket::getHardwareType()
{

}

//
u_short YArpPacket::getProtocolType()
{

}

//
u_short YArpPacket::getOperationField()
{
    u_short opFiled = (*(u_short *)(data + 20));
    return opFiled;
}

//
QString YArpPacket::getSourceMacAdd()
{
    u_char mac[6] = {0};
    char macBuf[64] = {0};
    for (int i = 0; i < 6; i++) {
        mac[i] = *(unsigned char *) (data + 22 + i);
    }
    sprintf(macBuf,"%02x-%02x-%02x-%02x-%02x-%02x",mac[0],mac[1],mac[2],mac[3], mac[4], mac[5]);
    return QString(macBuf);
}

//
u_long YArpPacket::getSourceIpAdd()
{
    u_long ipN = *(u_long *) (data + 28);
    return ipN;
}

//
QString YArpPacket::getDestMacAdd()
{
    u_char mac[6] = {0};
    char macBuf[64] = {0};
    for (int i = 0; i < 6; i++) {
        mac[i] = *(unsigned char *) (data + 32 + i);
    }
    sprintf(macBuf,"%02x-%02x-%02x-%02x-%02x-%02x",mac[0],mac[1],mac[2],mac[3], mac[4], mac[5]);
    return QString(macBuf);
}

//
u_long YArpPacket::getDestIpAdd()
{

}

