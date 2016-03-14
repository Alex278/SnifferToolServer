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

    ah->HardwareType = my_htons(0x0001);
    ah->ProtocolType = my_htons(0x0800);
    ah->OperationField = my_htons(opFilt);
    memcpy(ah->SourceMacAdd, srcMac, 6);
    memcpy(ah->DestMacAdd, destMac, 6);
    u_long srcIpN = my_inet_addr(srcIp);
    memcpy(ah->SourceIpAdd,(u_char*)&srcIpN,4);
    u_long destIpN = my_inet_addr(destIp);
    memcpy(ah->DestIpAdd,(u_char*)&destIpN,4);
}

// 将EthernetHeader 和 ArpHeader 整合成ArpPacket data
void YArpPacket::setData()
{
    memcpy(data,etherPacket.getData(),ETHERNET_HEAD_LENGTH);
    memcpy(data+ETHERNET_HEAD_LENGTH,&arpBody,ARP_BODY_LENGTH);
}

u_char * YArpPacket::getData()
{
    return data;
}
