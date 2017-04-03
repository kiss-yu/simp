#include "reference.h"
#include "util.h"
#define ETHERTYPE_IP 0x08 //以太帧携带ip协议
#define ETHERTYPR_PPPOE_FIND 0x6388 //pppoe发现阶段
#define ETHERTYPR_PPPOE_SESSION 0x6488 //pppoe会话阶段
#define MAX_PACK_LEN 65535      //接收的最大IP报文
#define MAX_HTTP_LEN 10240 //http数据部分最大值
#define MAX_PROTO_TEXT_LEN 16  //子协议名称（如"TCP"）最大长度 
#define MAX_PROTO_NUM 12   //子协议数量
#define MAX_HOSTNAME_LAN 255  //最大主机名长度
typedef struct _protomap    //定义子协议映射表 
{
	int ProtoNum;
	char ProtoText[MAX_PROTO_TEXT_LEN];
}PROTOMAP;

typedef struct eth_header
{
	unsigned char d_mac[6];//以太帧目的mac地址
	unsigned char s_mac[6];//以太帧源mac地址
	unsigned short type;//上层协议类型
}ETH_HEADER;

typedef struct _iphdr    //定义IP头部 
{
	ETH_HEADER eth_header;//以太帧头
	unsigned char h_lenver;  //4位首部长度+4位IP版本号  
	unsigned char tos;    //8位服务类型TOS  
	unsigned short total_len;  //16位总长度（字节） 
	unsigned short ident;   //16位标识  
	unsigned short frag_and_flags;  //3位标志位  
	unsigned char ttl;     //8位生存时间TTL  
	unsigned char proto;    //8位协议(TCP,UDP或其他）  
	unsigned short checksum;   //16位IP首部校验和  
	unsigned int sourceIP;    //32位源IP地址  
	unsigned int destIP;    //32位目的IP地址

}IP_HEADER;

typedef struct _pppoe    //定义pppoe帧头部头部 
{
	ETH_HEADER eth_header;//以太帧头
	unsigned char h_lenver;  //4位首部长度+4位IP版本号  //0x11
	unsigned char code;//pppoe协议code值 //0x09 PADI      0X07 PADO      0X19 PADR      0X65 PADS    0XA7 PADT
	unsigned short session;//协议附带session值
	unsigned short length;//表示负载长度，不包括以太头和PPPOE头
	unsigned char tags[200];//tag内容  占留
}PPPOE_HEADER;
PROTOMAP pppType[5]{ //pppoe各阶段包名
	{ 0x09,"PADI" },
	{ 0X07,"PADO" },
	{ 0X19,"PADR" },
	{ 0X65,"PADS" },
	{ 0XA7,"PADT" }
};
typedef struct _tcphdr     //定义TCP首部 
{
	USHORT th_sport;     //16位源端口  
	USHORT th_dport;     //16位目的端口  
	unsigned int th_seq;    //32位序列号  
	unsigned int th_ack;    //32位确认号  
	unsigned char th_lenres;   //4位首部长度/6位保留字 
	unsigned char th_flag;    //6位标志位  
	USHORT th_win;      //16位窗口大小  
	USHORT th_sum;      //16位校验和  
	USHORT th_urp;      //16位紧急数据偏移量
	char http_content[MAX_HTTP_LEN];//http全部数据
	IP_HEADER ip_header; //ip帧头
}TCP_HEADER;
typedef struct _httphdr
{
	u_char http_content[MAX_HTTP_LEN];//http全部数据
	TCP_HEADER tcp_header; //tcp帧头
	string getHost()
	{
		string str;
		strcpy((char*)str.c_str(), (char*)http_content);
		if (str.find("Host",0) == string::npos)
		{
			return "host不存在";
		}
		return split(str, "Host: ", "\r\n");
	}
	string getHttpMethod()
	{
		string str;
		strcpy((char*)str.c_str(), (char*)http_content);
		if (str.find("HTTP",0) == string::npos)
		{
			return "错误http数据";
		}
		return split(str,"" ," ");
	}
	string getUrl()
	{
		string str;
		strcpy((char*)str.c_str(), (char*)http_content);
		if (getHttpMethod() == "错误http数据")
		{
			return "url不存在";
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
		//		return "post无内容";
		//	}
		//	return split(str, "\r\n\r\n", "");
		//}else
		//{
			return string("{Method:\"" + method + "\",message:\"暂时不支持解析！！！\"}");
		//}
	}
	string toString()
	{
		return "method：" + getHttpMethod() + "\n" +
		"url：http:\\" + getHost() + getUrl() + "\n" +
		"请求参数：" + getMessageMap(); +"\n";
	}
}HTTP_HEADER;
typedef struct _udphdr     //定义UDP首部 
{
	unsigned short uh_sport;   //16位源端口  
	unsigned short uh_dport;  //16位目的端口  
	unsigned short uh_len;    //16位长度  
	unsigned short un_sum;    //16位校验和
}UDP_HEADER;
typedef struct _icmphdr    //定义ICMP首
{
	BYTE i_type;      //8位类型  
	BYTE i_code;      //8位代码  
	USHORT i_cksum;      //16位校验和  
	USHORT i_id;      //识别号（一般用进程号作为识别号）  
	USHORT i_seq;      //报文序列号  
	ULONG timestamp;     //时间戳 
}ICMP_HEADER;
PROTOMAP ProtoMap[MAX_PROTO_NUM] = {  //为子协议映射表赋值   
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