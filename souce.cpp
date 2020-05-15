#include<stdio.h>
#include <stdlib.h>
#include<WinSock2.h>
#pragma comment(lib,"WS2_32")
#include <windows.h>

// 声明IP头数据结构
typedef struct _IPHeader  // 20字节的IP头
{
    UCHAR     iphVerLen;      // 版本号和头长度（各占4位）
    UCHAR     ipTOS;            // 服务类型 
    USHORT    ipLength;       // 封包总长度，即整个IP报的长度
    USHORT    ipID;	    // 封包标识，惟一标识发送的每一个数据报
    USHORT    ipFlags;	      // 标志和片偏移
    UCHAR     ipTTL;	      // 生存时间，就是TTL
    UCHAR     ipProtocol;     // 协议，可能是TCP、UDP、ICMP等
    USHORT    ipChecksum;     // 校验和
    ULONG     ipSource;          // 源IP地址
    ULONG     ipDestination;  // 目标IP地址
} IPHeader, * PIPHeader;

//ICMP头数据结构
typedef struct icmp_hdr
{
    unsigned char   icmp_type;		// 消息类型
    unsigned char   icmp_code;		// 代码
    unsigned short  icmp_checksum;	// 校验和
    unsigned short  icmp_id; // 用来惟一标识此请求的ID号，通常设置为进程ID
    unsigned short  icmp_sequence;	// 序号
    unsigned long   icmp_timestamp; // 数据传输时间
} ICMP_HDR, * PICMP_HDR;

//ICMP回送请求的数据结构
typedef struct _EchoRequest {
    ICMP_HDR icmphdr;
    char cData[65500];
}ECHOREQUEST, * PECHOREQUEST;

//ICMP回送应答的数据结构
#define REQ_DATASIZE 32
typedef struct _EchoReply {
    IPHeader iphdr;
    ECHOREQUEST echoRequest;
}ECHOREPLAY, * PECHOREPLAY;

// 校验和的计算
// 以16位的字为单位将缓冲区的内容相加，如果缓冲区长度为奇数，
// 则再加上一个字节。它们的和存入一个32位的双字中

USHORT checksum(USHORT* buff, int size)
{
    u_long cksum = 0;
    while (size > 1)                        // 将数据以字为单位累加到cksum 中
    {
        cksum = cksum + *buff;
        buff = buff + 1;
        size = size - sizeof(USHORT); //等价于size=size-2;
    }
    if (size == 1)                    // 共有奇数个字节将最后一个字节扩展为字，再累加
    {
        USHORT u = 0;
        u = (USHORT)(*(UCHAR*)buff);
        cksum = cksum + u;
    }
    // 校验位计算
    //高16位和低16位相加
    cksum = (cksum >> 16) + (cksum & 0x0000ffff);
    cksum = cksum + (cksum >> 16);//本身再加上当前的高16位 
    u_short  answer = (u_short)(~cksum);//取反并转换为16位数
    return (answer);
}



void LoadLib(WSADATA& wd)
{
	WORD version = MAKEWORD(2, 2);
	if (WSAStartup(version, &wd) != 0)
	{
		printf("fail to load winsock lib...\n");
		exit(0);
	}
}



int main(int argc, char* argv[])
{
    WSADATA wsadata;//用于返回winsock库详细信息
    LoadLib(wsadata);//加载winsock库

    SOCKET sRaw = WSASocket(AF_INET, SOCK_RAW,
        IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
    SOCKADDR_IN dest;
    SOCKADDR_IN from;
    int nLen = sizeof(from);
    USHORT   nSeq = 0;
    int delivNum = 4;
    int dataSize = 32;

    if (argc < 2)
    {
        printf("ping [des ip]\n");
        printf("-l:指定发送数据包大小\n");
        printf("-n:指定发送数据包数量\n");
        return 0;
    }
    if (argc != 4 && argc != 6 && argc != 2)
    {
        printf("请正确输入命令格式\n");
        return 0;
    }
    switch (argc)
    {
    case 6:
        if (!strcmp(argv[4], "-l"))
        {
            int temp = atoi(argv[5]);
            if (temp <= 0 || temp > 65500)
            {
                printf("指定数据包长度应为1-65500字节\n");
                return 0;
            }
            dataSize = atoi(argv[5]);
        }
        if (!strcmp(argv[4], "-n"))
            delivNum = atoi(argv[5]);
    case 4:
        if (!strcmp(argv[2], "-l"))
        {
            int temp = atoi(argv[3]);
            if (temp <= 0 || temp > 65500)
            {
                printf("指定数据包长度应为1-65500字节\n");
                return 0;
            }
            dataSize = atoi(argv[3]);
        }
        if (!strcmp(argv[2], "-n"))
            delivNum = atoi(argv[3]);
    }

    if (inet_addr(argv[1]) != INADDR_NONE)
    {


        dest.sin_family = AF_INET;
        dest.sin_port = htons(0);
        dest.sin_addr.S_un.S_addr = inet_addr(argv[1]);
        // 创建ICMP封包(回送请求)
        ECHOREQUEST echoReq;
        // 填写ICMP封包数据
        echoReq.icmphdr.icmp_type = 8;	// 请求一个ICMP回显
        echoReq.icmphdr.icmp_code = 0;
        echoReq.icmphdr.icmp_id = (USHORT)GetCurrentProcessId();
        echoReq.icmphdr.icmp_checksum = 0;
        echoReq.icmphdr.icmp_sequence = 0;
        // 填充数据部分，可以为任意
        memset(&echoReq.cData, 'E', dataSize);
        //发送icmp包
        while (TRUE) {
            static int nCount = 0;   int nRet;
            if (nCount++ == delivNum)   break;
            echoReq.icmphdr.icmp_checksum = 0;
            // GetTickCount() 系统开始后，已经经过的毫秒数
            echoReq.icmphdr.icmp_timestamp = GetTickCount();
            echoReq.icmphdr.icmp_sequence = nSeq++;
            echoReq.icmphdr.icmp_checksum = checksum((USHORT*)&echoReq, sizeof(echoReq));
            //目的地址
            nRet = sendto(sRaw, (char*)&echoReq, sizeof(echoReq), 0, (SOCKADDR*)&dest, sizeof(dest));
            if (nRet == SOCKET_ERROR) {
                printf(" sendto() failed: %d \n", WSAGetLastError());
                return -1;
            }

            //接收应答包
            ECHOREPLAY echoReply;
            nRet = recvfrom(sRaw, (char*)&echoReply, sizeof(ECHOREPLAY), 0, (sockaddr*)&from, &nLen);
            if (nRet == SOCKET_ERROR) {
                if (WSAGetLastError() == WSAETIMEDOUT) {
                    printf(" timed out\n");
                    continue;
                }
                printf(" recvfrom() failed: %d\n", WSAGetLastError());
                return -1;
            }
            //解析
            if (nRet < sizeof(ECHOREPLAY)) {
                printf("目标无响应\n");
            }
            // 接收到的数据中包含IP头，IP头大小为20个字节
            if (echoReply.echoRequest.icmphdr.icmp_type != 0) { // 回显
                //printf(" nonecho type %d recvd \n", echoReply.echoRequest.icmphdr.icmp_type);
                return -1;
            }
            if (echoReply.echoRequest.icmphdr.icmp_id != GetCurrentProcessId()) {
                printf(" someone else's packet! \n");
                return -1;
            }

            //显示信息
            printf("第%d个数据包，", echoReply.echoRequest.icmphdr.icmp_sequence);
            printf("来自 %s 的回复： ", inet_ntoa(from.sin_addr));
            printf("发送设置字节=%d ", strlen(echoReq.cData));
            printf("接收字节=%d ", nRet);
            int nTick = GetTickCount();
            printf("传输时间=%dms ", nTick - echoReply.echoRequest.icmphdr.icmp_timestamp);
            printf("TTL=%d ", echoReply.iphdr.ipTTL);
            printf("发送IP包总长度=%d", echoReply.iphdr.ipLength);
            printf("\n");
            Sleep(1000);
        }
    }
    else
        printf("地址输入错误\n");
}

