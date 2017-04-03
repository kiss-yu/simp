#include "Protocol.h"
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib") 
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char*packet);
int caught();
void sendEthernet();
void parsingIPData(const u_char * pack);
void parsingTcpData(const u_char * pack, IP_HEADER  ip_header);
void parsingHttpData(const u_char * pack, TCP_HEADER tcp_header);
void test(const u_char * pack);
typedef struct t
{
	u_char a[10000];
}t;
void main()
{
	caught();
	//u_char k[8] = { 0xc0,0xa8,0x00,0x64,0xc0,0xa8,0x00,0x64 };
	u_int k[2] = { 1677764800,1677764800 };
	printf("%x", k[1]);
	t * a = (t*)k;
	getchar();
}
int caught()
{
	pcap_t * handle;
	const unsigned char * packet;
	struct pcap_pkthdr header;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "port 23";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	pcap_if_t *it;
	char  error[PCAP_ERRBUF_SIZE];
	pcap_findalldevs(&it, error);
	char * dev = it->name;
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask fordevice %s\n", dev);
		net = 0;
		mask = 0;
	}
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s:%s\n", dev, errbuf);
		return(2);
	}
	packet = pcap_next(handle, &header);
	//异步调用got_packet函数
	pcap_loop(handle, 0, got_packet, NULL);
	printf("close");
	pcap_close(handle);
}
int k = 0;
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char*packet)
{
	ETH_HEADER * e_header = (ETH_HEADER*)(packet);
	//printf("抓到了%4d个数据包  目的mac：", k++);
	//int i = 0;
	//for (i = 0; i < 6; i++)
	//{
	//	printf("%0*x：", 2, e_header->d_mac[i]);
	//}
	//printf("     源mac：");
	//for (i = 0; i < 6; i++)
	//{
	//	printf("%0*x：", 2, e_header->s_mac[i]);
	//}
	//printf("     链路层协议类型：");
	//printf("%x", e_header->type);
	//putchar('\n');
	//ETH_HEADER * e_header = (ETH_HEADER*)packet;
	switch (e_header->type)
	{
	case ETHERTYPE_IP:
		parsingIPData(packet);
		break;
	case ETHERTYPR_PPPOE_FIND:
	case ETHERTYPR_PPPOE_SESSION:
	default:
		break;
	}
}
const u_char * rootpack;
void parsingIPData(const u_char * pack)
{
	rootpack = pack;
	IP_HEADER * i_header = (IP_HEADER*)pack;
	switch (i_header->proto)
	{
	case IPPROTO_TCP:parsingTcpData(pack+ 4 * (i_header->h_lenver & 0x0f) + 14,*i_header); break;
	default:
		break;
	}
}
void parsingTcpData(const u_char * pack, IP_HEADER  ip_header)
{
	TCP_HEADER * tcp_header = (TCP_HEADER*)pack;
	tcp_header->ip_header = ip_header;
	//printf("一个tcp数据包:%0*x\n", 4, tcp_header->th_dport);
	int a = 4 * (int)((tcp_header->th_lenres & 0xf0) >> 4);
	switch (tcp_header->th_dport)
	{
	case 0x5000:parsingHttpData(pack + a, *tcp_header); break;
	default:
		break;
	}
}
void parsingHttpData(const u_char * pack, TCP_HEADER tcp_header)
{
	HTTP_HEADER * h_header = (HTTP_HEADER*)pack;
	h_header->tcp_header = tcp_header;
	printf("\n%d--->%d\n",  h_header->tcp_header.ip_header.sourceIP,h_header->tcp_header.ip_header.destIP);
	//cout<< h_header->toString();
}




void sendEthernet()
{
	////拷贝数据到发送字符中  
	//memcpy(SendBuffer, &m_ethHeader, sizeof(m_ethHeader));
	//index = sizeof(m_ethHeader);
	//memcpy(&SendBuffer[index], strMessage, sizeof(strMessage));
	//index += sizeof(strMessage);
	//if (pcap_sendpacket(fp, // Adapter
	//SendBuffer,             // buffer with the packet
	//index                   // size
	//) != 0)
}