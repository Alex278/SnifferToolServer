#ifndef TCPIPCOMMON_H
#define TCPIPCOMMON_H

typedef unsigned char       u_char;
typedef unsigned short int  u_short;
typedef unsigned int        u_int;
typedef unsigned long       u_long;

#define  DLC_HEAD_LENGTH	14

#define ARP_TYPE            0x0806
#define IP_TYPE             0x0800
#define MPLS_TYPE           0x8847
#define IPX_TYPE            0x8137
#define IS_IS_TYPE          0x8000
#define LACP_TYPE           0x8809
#define _802_1x_TYPE        0x888E
#define ARP_HARDWARE        1
#define ARP_REQUEST         1
#define ARP_REPLY           2


//**************常用网路自定义结构体*********************//
// 4 bytes IP address
typedef struct _IPAddress{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}IPAddress;

// IPv4 header
typedef struct _IpHeader{
    u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
    u_char	tos;			// Type of service
    u_short tlen;			// Total length
    u_short identification; // Identification
    u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
    u_char	ttl;			// Time to live
    u_char	proto;			// Protocol
    u_short crc;			// Header checksum
    IPAddress	saddr;		// Source address
    IPAddress	daddr;		// Destination address
    u_int	op_pad;			// Option + Padding
}IPHeader;

// UDP header
typedef struct _UDPHeader{
    u_short sport;			// Source port
    u_short dport;			// Destination port
    u_short len;			// Datagram length
    u_short crc;			// Checksum
}UDPHeader;

// Ethernet addresses are 6 bytes
#define ETHER_ADDR_LEN 6
typedef struct _EthernetHeader
{
    u_char DestMAC[ETHER_ADDR_LEN];          //目的MAC地址 6字节
    u_char SourMAC[ETHER_ADDR_LEN];          //源MAC地址 6字节
    u_short EthType;                         //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp  2字节
}EthernetHeader;

// 28 bytes ARP request/reply
typedef struct _ArpHeader {
    unsigned short HardwareType;          //硬件类型,2字节，定义运行ARP的网络的类型，以太网是类型1
    unsigned short ProtocolType;          //协议类型,2字节，定义上层协议类型，对于IPV4协议，该字段值为0800
    unsigned char HardwareAddLen;         //硬件地址长度,8位字段，定义对应物理地址长度，以太网中这个值为6
    unsigned char ProtocolAddLen;         //协议地址长度,8位字段，定义以字节为单位的逻辑地址长度，对IPV4协议这个值为4
    unsigned short OperationField;        //操作字段,数据包类型,ARP请求（值为1），或者ARP应答（值为2）
    unsigned char SourceMacAdd[6];        //源（发送端）mac地址,可变长度字段，对以太网这个字段是6字节长
    unsigned int SourceIpAdd;             //源（发送短）ip地址,发送端协议地址，可变长度字段，对IP协议，这个字段是4字节长
    unsigned char DestMacAdd[6];          //目的（接收端）mac地址
    unsigned int DestIpAdd;               //目的（接收端）ip地址
}ArpHeader;

//arp packet = 14 bytes ethernet header + 28 bytes request/reply
typedef struct _ArpPacket {
    EthernetHeader ed;
    ArpHeader ah;
}ArpPacket;


//**************常用网路自定义转换函数*******************//
//my_htonl函数，本机字节序转网络字节序(32位字节序)
//my_ntohl函数，网络字节序转本机字节序(32位字节序)
//my_htons函数，本机字节序转网络字节序(16位字节序)
//my_ntohs函数，网络字节序转本机字节序(16位字节序)
//my_iptos函数，将字节序ip地址转为点分十进制的字符串地址
//iptos   函数，将字节序ip地址转为点分十进制的字符串地址,并获取
//my_inet_addr

inline int checkCPUendian();
inline u_long my_inet_addr(const char *ptr);
inline char *my_iptos(u_long in);
inline u_long my_ntohl(u_long n);
inline u_long my_htonl(u_long h);

// 短整型大小端互换
#define BigLittleSwap16(A)  ((((u_short)(A) & 0xff00) >> 8) | \
                            (((u_short)(A) & 0x00ff) << 8))
// 长整型大小端互换
#define BigLittleSwap32(A)  ((((u_long)(A) & 0xff000000) >> 24) | \
                            (((u_long)(A) & 0x00ff0000) >> 8) | \
                            (((u_long)(A) & 0x0000ff00) << 8) | \
                            (((u_long)(A) & 0x000000ff) << 24))



// 本机大端返回1，小端返回0
int checkCPUendian()
{
    union{
          u_long i;
          u_char s[4];
    }c;

    c.i = 0x12345678;
    return (0x12 == c.s[0]);
}

// 模拟htonl函数，本机字节序转网络字节序
u_long my_htonl(u_long h)
{
    // 若本机为大端，与网络字节序同，直接返回
    // 若本机为小端，转换成大端再返回
    return checkCPUendian() ? h : BigLittleSwap32(h);
}

// 模拟ntohl函数，网络字节序转本机字节序
u_long my_ntohl(u_long n)
{
    // 若本机为大端，与网络字节序同，直接返回
    // 若本机为小端，网络数据转换成小端再返回
    return checkCPUendian() ? n : BigLittleSwap32(n);
}

// 模拟htons函数，本机字节序转网络字节序
inline u_short my_htons(u_short h)
{
    // 若本机为大端，与网络字节序同，直接返回
    // 若本机为小端，转换成大端再返回
    return checkCPUendian() ? h : BigLittleSwap16(h);
}

// 模拟ntohs函数，网络字节序转本机字节序
inline u_short my_ntohs(u_short n)
{
    // 若本机为大端，与网络字节序同，直接返回
    // 若本机为小端，网络数据转换成小端再返回
    return checkCPUendian() ? n : BigLittleSwap16(n);
}

// 数字类型的IP地址转换成点分十进制字符串类型的
inline char *iptos(u_long in,char * ipStr)
{
    u_char *p;
    p = (u_char *)&in;
    sprintf(ipStr, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return ipStr;
}

#define IPTOSBUFFERS    12
inline char *my_iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

u_long my_inet_addr(const char *ptr)
{
    int a[4],i=0;
    char str[255] = {0};
    unsigned long num;

    strcpy(str,ptr);
    char *p1=str,*p2,*p3;
    while(*p1!='\0' && i<4 ){
        p2=strstr(p1,".");
        if(i!=3){
            p3=p2+1;
            *p2='\0';
        }
        a[i]=atoi(p1);
        if(a[i]<0 || a[i]>255){
         printf("Invalid IP address!\n");
         exit(1);
        }
        p1=p3;
        i++;
     }
     num=a[0]*256*256*256+a[1]*256*256+a[2]*256+a[3];
     return num;
}


#endif // TCPIPCOMMON_H

