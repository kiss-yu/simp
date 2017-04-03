#include "reference.h"
#include "util.h"
#define ETHERTYPE_IP 0x08 //��̫֡Я��ipЭ��
#define ETHERTYPR_PPPOE_FIND 0x6388 //pppoe���ֽ׶�
#define ETHERTYPR_PPPOE_SESSION 0x6488 //pppoe�Ự�׶�
#define MAX_PACK_LEN 65535      //���յ����IP����
#define MAX_HTTP_LEN 10240 //http���ݲ������ֵ
#define MAX_PROTO_TEXT_LEN 16  //��Э�����ƣ���"TCP"����󳤶� 
#define MAX_PROTO_NUM 12   //��Э������
#define MAX_HOSTNAME_LAN 255  //�������������
typedef struct _protomap    //������Э��ӳ��� 
{
	int ProtoNum;
	char ProtoText[MAX_PROTO_TEXT_LEN];
}PROTOMAP;

typedef struct eth_header
{
	unsigned char d_mac[6];//��̫֡Ŀ��mac��ַ
	unsigned char s_mac[6];//��̫֡Դmac��ַ
	unsigned short type;//�ϲ�Э������
}ETH_HEADER;

typedef struct _iphdr    //����IPͷ�� 
{
	ETH_HEADER eth_header;//��̫֡ͷ
	unsigned char h_lenver;  //4λ�ײ�����+4λIP�汾��  
	unsigned char tos;    //8λ��������TOS  
	unsigned short total_len;  //16λ�ܳ��ȣ��ֽڣ� 
	unsigned short ident;   //16λ��ʶ  
	unsigned short frag_and_flags;  //3λ��־λ  
	unsigned char ttl;     //8λ����ʱ��TTL  
	unsigned char proto;    //8λЭ��(TCP,UDP��������  
	unsigned short checksum;   //16λIP�ײ�У���  
	unsigned int sourceIP;    //32λԴIP��ַ  
	unsigned int destIP;    //32λĿ��IP��ַ

}IP_HEADER;

typedef struct _pppoe    //����pppoe֡ͷ��ͷ�� 
{
	ETH_HEADER eth_header;//��̫֡ͷ
	unsigned char h_lenver;  //4λ�ײ�����+4λIP�汾��  //0x11
	unsigned char code;//pppoeЭ��codeֵ //0x09 PADI      0X07 PADO      0X19 PADR      0X65 PADS    0XA7 PADT
	unsigned short session;//Э�鸽��sessionֵ
	unsigned short length;//��ʾ���س��ȣ���������̫ͷ��PPPOEͷ
	unsigned char tags[200];//tag����  ռ��
}PPPOE_HEADER;
PROTOMAP pppType[5]{ //pppoe���׶ΰ���
	{ 0x09,"PADI" },
	{ 0X07,"PADO" },
	{ 0X19,"PADR" },
	{ 0X65,"PADS" },
	{ 0XA7,"PADT" }
};
typedef struct _tcphdr     //����TCP�ײ� 
{
	USHORT th_sport;     //16λԴ�˿�  
	USHORT th_dport;     //16λĿ�Ķ˿�  
	unsigned int th_seq;    //32λ���к�  
	unsigned int th_ack;    //32λȷ�Ϻ�  
	unsigned char th_lenres;   //4λ�ײ�����/6λ������ 
	unsigned char th_flag;    //6λ��־λ  
	USHORT th_win;      //16λ���ڴ�С  
	USHORT th_sum;      //16λУ���  
	USHORT th_urp;      //16λ��������ƫ����
	char http_content[MAX_HTTP_LEN];//httpȫ������
	IP_HEADER ip_header; //ip֡ͷ
}TCP_HEADER;
typedef struct _httphdr
{
	u_char http_content[MAX_HTTP_LEN];//httpȫ������
	TCP_HEADER tcp_header; //tcp֡ͷ
	string getHost()
	{
		string str;
		strcpy((char*)str.c_str(), (char*)http_content);
		if (str.find("Host",0) == string::npos)
		{
			return "host������";
		}
		return split(str, "Host: ", "\r\n");
	}
	string getHttpMethod()
	{
		string str;
		strcpy((char*)str.c_str(), (char*)http_content);
		if (str.find("HTTP",0) == string::npos)
		{
			return "����http����";
		}
		return split(str,"" ," ");
	}
	string getUrl()
	{
		string str;
		strcpy((char*)str.c_str(), (char*)http_content);
		if (getHttpMethod() == "����http����")
		{
			return "url������";
		}
		return split(str, getHttpMethod()+" ", " ");
	}
	string getMessageMap()
	{
		//string str;
		//strcpy((char*)str.c_str(), (char*)http_content);
		string method = getHttpMethod();
		//if (method == "GET")
		//{
		//	return getGeturlMessageMap(getUrl());
		//}
		//else if (method == "POST")
		//{
		//	if (str.find("\r\n\r\n",0) == string::npos)
		//	{
		//		return "post������";
		//	}
		//	return split(str, "\r\n\r\n", "");
		//}else
		//{
			return string("{Method:\"" + method + "\",message:\"��ʱ��֧�ֽ���������\"}");
		//}
	}
	string toString()
	{
		return "method��" + getHttpMethod() + "\n" +
		"url��http:\\" + getHost() + getUrl() + "\n" +
		"���������" + getMessageMap(); +"\n";
	}
}HTTP_HEADER;
typedef struct _udphdr     //����UDP�ײ� 
{
	unsigned short uh_sport;   //16λԴ�˿�  
	unsigned short uh_dport;  //16λĿ�Ķ˿�  
	unsigned short uh_len;    //16λ����  
	unsigned short un_sum;    //16λУ���
}UDP_HEADER;
typedef struct _icmphdr    //����ICMP��
{
	BYTE i_type;      //8λ����  
	BYTE i_code;      //8λ����  
	USHORT i_cksum;      //16λУ���  
	USHORT i_id;      //ʶ��ţ�һ���ý��̺���Ϊʶ��ţ�  
	USHORT i_seq;      //�������к�  
	ULONG timestamp;     //ʱ��� 
}ICMP_HEADER;
PROTOMAP ProtoMap[MAX_PROTO_NUM] = {  //Ϊ��Э��ӳ���ֵ   
	{ IPPROTO_IP,"IP" },
	{ IPPROTO_ICMP,"ICMP" },
	{ IPPROTO_IGMP,"IGMP" },
	{ IPPROTO_GGP,"GGP" },
	{ IPPROTO_TCP,"TCP" },
	{ IPPROTO_PUP,"PUP" },
	{ IPPROTO_UDP,"UDP" },
	{ IPPROTO_IDP,"IDP" },
	{ IPPROTO_ND,"NP" },
	{ IPPROTO_RAW,"RAW" },
	{ IPPROTO_MAX,"MAX" },
	{ NULL,"" }
};