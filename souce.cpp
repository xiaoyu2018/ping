#include<stdio.h>
#include <stdlib.h>
#include<WinSock2.h>
#pragma comment(lib,"WS2_32")
#include <windows.h>

// ����IPͷ���ݽṹ
typedef struct _IPHeader  // 20�ֽڵ�IPͷ
{
    UCHAR     iphVerLen;      // �汾�ź�ͷ���ȣ���ռ4λ��
    UCHAR     ipTOS;            // �������� 
    USHORT    ipLength;       // ����ܳ��ȣ�������IP���ĳ���
    USHORT    ipID;	    // �����ʶ��Ωһ��ʶ���͵�ÿһ�����ݱ�
    USHORT    ipFlags;	      // ��־��Ƭƫ��
    UCHAR     ipTTL;	      // ����ʱ�䣬����TTL
    UCHAR     ipProtocol;     // Э�飬������TCP��UDP��ICMP��
    USHORT    ipChecksum;     // У���
    ULONG     ipSource;          // ԴIP��ַ
    ULONG     ipDestination;  // Ŀ��IP��ַ
} IPHeader, * PIPHeader;

//ICMPͷ���ݽṹ
typedef struct icmp_hdr
{
    unsigned char   icmp_type;		// ��Ϣ����
    unsigned char   icmp_code;		// ����
    unsigned short  icmp_checksum;	// У���
    unsigned short  icmp_id; // ����Ωһ��ʶ�������ID�ţ�ͨ������Ϊ����ID
    unsigned short  icmp_sequence;	// ���
    unsigned long   icmp_timestamp; // ���ݴ���ʱ��
} ICMP_HDR, * PICMP_HDR;

//ICMP������������ݽṹ
typedef struct _EchoRequest {
    ICMP_HDR icmphdr;
    char cData[65500];
}ECHOREQUEST, * PECHOREQUEST;

//ICMP����Ӧ������ݽṹ
#define REQ_DATASIZE 32
typedef struct _EchoReply {
    IPHeader iphdr;
    ECHOREQUEST echoRequest;
}ECHOREPLAY, * PECHOREPLAY;

// У��͵ļ���
// ��16λ����Ϊ��λ����������������ӣ��������������Ϊ������
// ���ټ���һ���ֽڡ����ǵĺʹ���һ��32λ��˫����

USHORT checksum(USHORT* buff, int size)
{
    u_long cksum = 0;
    while (size > 1)                        // ����������Ϊ��λ�ۼӵ�cksum ��
    {
        cksum = cksum + *buff;
        buff = buff + 1;
        size = size - sizeof(USHORT); //�ȼ���size=size-2;
    }
    if (size == 1)                    // �����������ֽڽ����һ���ֽ���չΪ�֣����ۼ�
    {
        USHORT u = 0;
        u = (USHORT)(*(UCHAR*)buff);
        cksum = cksum + u;
    }
    // У��λ����
    //��16λ�͵�16λ���
    cksum = (cksum >> 16) + (cksum & 0x0000ffff);
    cksum = cksum + (cksum >> 16);//�����ټ��ϵ�ǰ�ĸ�16λ 
    u_short  answer = (u_short)(~cksum);//ȡ����ת��Ϊ16λ��
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
    WSADATA wsadata;//���ڷ���winsock����ϸ��Ϣ
    LoadLib(wsadata);//����winsock��

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
        printf("-l:ָ���������ݰ���С\n");
        printf("-n:ָ���������ݰ�����\n");
        return 0;
    }
    if (argc != 4 && argc != 6 && argc != 2)
    {
        printf("����ȷ���������ʽ\n");
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
                printf("ָ�����ݰ�����ӦΪ1-65500�ֽ�\n");
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
                printf("ָ�����ݰ�����ӦΪ1-65500�ֽ�\n");
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
        // ����ICMP���(��������)
        ECHOREQUEST echoReq;
        // ��дICMP�������
        echoReq.icmphdr.icmp_type = 8;	// ����һ��ICMP����
        echoReq.icmphdr.icmp_code = 0;
        echoReq.icmphdr.icmp_id = (USHORT)GetCurrentProcessId();
        echoReq.icmphdr.icmp_checksum = 0;
        echoReq.icmphdr.icmp_sequence = 0;
        // ������ݲ��֣�����Ϊ����
        memset(&echoReq.cData, 'E', dataSize);
        //����icmp��
        while (TRUE) {
            static int nCount = 0;   int nRet;
            if (nCount++ == delivNum)   break;
            echoReq.icmphdr.icmp_checksum = 0;
            // GetTickCount() ϵͳ��ʼ���Ѿ������ĺ�����
            echoReq.icmphdr.icmp_timestamp = GetTickCount();
            echoReq.icmphdr.icmp_sequence = nSeq++;
            echoReq.icmphdr.icmp_checksum = checksum((USHORT*)&echoReq, sizeof(echoReq));
            //Ŀ�ĵ�ַ
            nRet = sendto(sRaw, (char*)&echoReq, sizeof(echoReq), 0, (SOCKADDR*)&dest, sizeof(dest));
            if (nRet == SOCKET_ERROR) {
                printf(" sendto() failed: %d \n", WSAGetLastError());
                return -1;
            }

            //����Ӧ���
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
            //����
            if (nRet < sizeof(ECHOREPLAY)) {
                printf("Ŀ������Ӧ\n");
            }
            // ���յ��������а���IPͷ��IPͷ��СΪ20���ֽ�
            if (echoReply.echoRequest.icmphdr.icmp_type != 0) { // ����
                //printf(" nonecho type %d recvd \n", echoReply.echoRequest.icmphdr.icmp_type);
                return -1;
            }
            if (echoReply.echoRequest.icmphdr.icmp_id != GetCurrentProcessId()) {
                printf(" someone else's packet! \n");
                return -1;
            }

            //��ʾ��Ϣ
            printf("��%d�����ݰ���", echoReply.echoRequest.icmphdr.icmp_sequence);
            printf("���� %s �Ļظ��� ", inet_ntoa(from.sin_addr));
            printf("���������ֽ�=%d ", strlen(echoReq.cData));
            printf("�����ֽ�=%d ", nRet);
            int nTick = GetTickCount();
            printf("����ʱ��=%dms ", nTick - echoReply.echoRequest.icmphdr.icmp_timestamp);
            printf("TTL=%d ", echoReply.iphdr.ipTTL);
            printf("����IP���ܳ���=%d", echoReply.iphdr.ipLength);
            printf("\n");
            Sleep(1000);
        }
    }
    else
        printf("��ַ�������\n");
}

