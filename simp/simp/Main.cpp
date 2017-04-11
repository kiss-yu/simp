#include "Protocol.h"
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib") 
/*打印网卡信息函数*/
void ifprint(pcap_if_t *d);
char *iptos(u_long in);
u_char * rootpacket;
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char*packet);
int caught();
void sendEthernet();
void parsingEthernetData(const u_char * pack);
void parsingIPData(const u_char * pack, ETH_HEADER * eth);
void parsingTcpData(const u_char * pack, IP_HEADER  *ip_header);
boolean isRepeatTcpData(TCP_HEADER * tcp_data);
boolean isRepeatHttpData(HTTP_HEADER * h_header);
void init_tcp_checksum();
void parsingHttpData(const u_char * pack, TCP_HEADER *  tcp_header, IP_HEADER * ip_header);
void mycaught();
int cw = 0;
int k = 0;
u_int tcp_seq[1000] = { 0 };
int tcp_tcp_seq_count = 0;
char repactHttpData[5][1500] = {0};
void main()
{
	mycaught();
	getchar();
}
void mycaught()
{
	pcap_if * alldevs;//存储网卡信息
	char error[PCAP_ERRBUF_SIZE];//错误信息
	pcap_t * handle;//
	bpf_program  bpf;//
	const u_char * pack_data = { 0 }; //获取的数据包
	pcap_pkthdr * pkthdr;//
	char * dev_name;//需要抓包网卡的句柄
	
	u_int net, mask, res=0;
	if (pcap_findalldevs(&alldevs, error) == -1)//获取网卡列表  存储在alldevs里
	{
		cout << "获取网卡设备失败--错误信息：" << error << endl;
		exit(0);
	}
	dev_name = alldevs->name;//网卡列表获取成功后把需要抓包的网卡句柄赋值给dev_name
							 //打开网卡数据抓包 dev_name网卡句柄 65536抓取数据包时的包最大长度  1  大于0设置为混杂模式 2000设置超时毫秒数  error接收错误信息
	if ((handle = pcap_open_live(dev_name, MAX_PACK_LEN, 1, 0, error)) == NULL)
	{
		cout << "open_live错误--错误信息：" << error << endl;
		pcap_freealldevs(alldevs);//出现错误后释放资源
		exit(3);
	}
	//编译过滤规则
	if (pcap_compile(handle, &bpf, "src or dst port 80", 1, ((struct sockaddr_in *)alldevs->addresses->netmask)->sin_addr.S_un.S_addr) < 0)
	{
		cout << "编译过滤规则失败！！！" << endl;
		exit(1);
	}
	//设置过滤规则
	if (pcap_setfilter(handle, &bpf) < 0)
	{
		cout << "过滤规则设置失败！！！";
		exit(2);
	}

	//用循环抓取数据包
	//pcap_loop(handle, 0, got_packet, NULL);
	while (res = pcap_next_ex(handle, &pkthdr, (&pack_data))>=0 && cw < 10)
	{  
		//pack_data = pcap_next(handle, pkthdr);
		got_packet(NULL,NULL,pack_data);
		k++;
		//got_packet_two(&pack_data, pack_data);
		//memset((char*)pack_data, 0, 1);  //强制RecvBuf缓冲区数据为0   //获取数据包，开始接收缓冲区数据 
	}
	cout << "\n =================stop======================" << endl;
	cout << "\n =================stop======================" << endl;
	pcap_freealldevs(alldevs);//最后设备
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
	handle = pcap_open_live(dev, 65536, 1, 0, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s:%s\n", dev, errbuf);
		return(2);
	}
	//异步调用got_packet函数
	pcap_loop(handle, 0, got_packet, NULL);
	cout << "\n =================stop======================" << endl;
	cout << "\n =================stop======================" << endl;
	pcap_freealldevs(it);
}
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char*packet)
{
	//cout << "\n =================start======================" << endl;
	u_char * pack = (u_char*)packet;
	//*(pack + MAX_PACK_LEN - 1) = 0;
	//*(pack + MAX_PACK_LEN - 2) = 0;
	//*(pack + MAX_PACK_LEN - 3) = 0;
	parsingEthernetData(pack);
}
void got_packet_two(const u_char ** packet, const u_char * packet1)
{
	//u_char * a = (u_char*)(*packet);
	//u_char * b = (u_char*)((*packet)+1);
	//parsingEthernetData(a);
	//parsingEthernetData(b);
	//for (size_t i = 0; ((*packet) + i) != NULL; i++)
	//{
	//	u_char * b = (u_char*)((*packet) + i);
	//	parsingEthernetData(b);
	//}
	u_char * pack = (u_char*)packet1;
	//*(pack + MAX_PACK_LEN-1) = 0xaa;
	//*(pack + MAX_PACK_LEN-2) = 0xaa;
	//*(pack + MAX_PACK_LEN-3) = 0xaa;
	parsingEthernetData(pack);
}
void parsingEthernetData(const u_char * pack)
{
	//for (;;pack++)
	//{
	//	if (*(pack) == 0x45 && *(pack + 1) == 0x00)
	//	{
	//		pack -= 14;
	//		break;
	//	}
	//	if (*(pack) == 0xaa && *(pack+1) == 0xaa && * (pack+2) == 0xaa)
	//	{
	//		return;
	//	}
	//}
	ETH_HEADER * e_header = (ETH_HEADER*)(pack);
	//printf("\n=======================抓到了%4d个数据包  目的mac：===============================\n", k);
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
	switch (e_header->type)
	{
	case ETHERTYPE_IP:
		parsingIPData(pack + 14, e_header);
		break;
	case ETHERTYPR_PPPOE_FIND:
	case ETHERTYPR_PPPOE_SESSION:
	default:
		break;
	}
	//parsingEthernetData(pack+50);
}
u_char * rootpack;
void parsingIPData(const u_char * pack, ETH_HEADER * eth)
{
	IP_HEADER * i_header = (IP_HEADER*)pack;
	i_header->eth_header = eth;
	switch (i_header->proto)
	{
	case IPPROTO_TCP: 
	{
		//for (size_t i = 0; i < 3; i++)
		//{
		//	printf("%u.", (i_header->sourceIP[i]));
		//}
		//printf("%u", (i_header->sourceIP[3]));
		//printf("------->");
		//for (size_t i = 0; i < 3; i++)
		//{
		//	printf("%u.", (i_header->destIP[i]));
		//}
		//printf("%u", (i_header->destIP[3]));
		parsingTcpData(pack + 4 * (i_header->h_lenver & 0x0f), i_header);
	}; break;
	default:
		break;
	}
}
void parsingTcpData(const  u_char * pack, IP_HEADER * ip_header)
{
	TCP_HEADER * tcp_header = (TCP_HEADER*)pack;
	if (isRepeatTcpData(tcp_header))
	{
		return;
	}
	//tcp_header->ip_header = ip_header;
	//printf("一个tcp数据包:%0*x\n", 4, tcp_header->th_dport);
	int a = 4 * (int)((tcp_header->th_lenres & 0xf0) >> 4);
	switch (tcp_header->th_dport)
	{
	case 0x5000:
	{
		parsingHttpData(pack + a, tcp_header, ip_header);
	}
		break;
	default:
		break;
	}
}
void init_tcp_checksum()
{
	for(int i = 0;i < 1000;i ++)
	{
		tcp_seq[i] = 0;
	}
}
boolean isRepeatTcpData(TCP_HEADER * tcp_data)
{
	if (tcp_tcp_seq_count == 999)
	{
		init_tcp_checksum();
		tcp_tcp_seq_count = 0;
		return false;
	}
	size_t i = 0;
	for (; i < 1000 && tcp_seq[i] != 0; i++)
	{
		if (tcp_seq[i] == tcp_data->th_seq)
		{
			return true;
		}
	}
	tcp_seq[i] = tcp_data->th_seq;
	tcp_tcp_seq_count++;
	return false;
}
void parsingHttpData(const u_char * pack, TCP_HEADER *  tcp_header, IP_HEADER * ip_header)
{
	HTTP_HEADER * h_header = (HTTP_HEADER*)pack;
	//h_header->tcp_header = tcp_header;
	if (!h_header->isNeedHttpData())
	{
		return;
	}
	if (isRepeatHttpData(h_header))
	{
		return;
	}
	cw++;
	putchar('\n');
	putchar('\n');
	putchar('\n');
	for (size_t i = 0; i < 3; i++)
	{
		printf("%u.", (ip_header->sourceIP[i]));
	}
	printf("%u",(ip_header->sourceIP[3]));
	printf("------->");
	for (size_t i = 0; i < 3; i++)
	{
		printf("%u.", (ip_header->destIP[i]));
	}
	printf("%u\n", (ip_header->destIP[3]));
	cout<< h_header->toString();
	//parsingEthernetData(pack + h_header->contentLen());
}
boolean isRepeatHttpData(HTTP_HEADER * h_header)
{
	if (repactHttpData[0][0] == 0)
	{
		  strcat(repactHttpData[0],h_header->toString().c_str());
		  return false;
	}
	size_t i = 0;
	for (; i < 5 && repactHttpData[i][0] != 0; i++)
	{
		if (string(repactHttpData[i]) == h_header->toString())
		{
			return true;
		}
	}
	if (i == 5)
	{
		strcat(repactHttpData[0], h_header->toString().c_str());
		repactHttpData[1][0] = 0;
		return false;
	}
	strcat(repactHttpData[i], h_header->toString().c_str());
	return false;
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


char *iptos(u_long in)
{
	static char output[12][3 * 4 + 3 + 1];
	static short which; u_char *p;  p = (u_char *)&in;
	which = (which + 1 == 12 ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}
void ifprint(pcap_if_t *d) {
	pcap_addr_t *a; /* Name */
	printf("%s\n", d->name);  /* Description */ if (d->description)
		printf("\tDescription: %s\n", d->description);  /* Loopback Address*/
	printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no"); /* IP addresses */
	for (a = d->addresses; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family); /*关于 sockaddr_in 结构请参考其他的网络编程书*/
		switch (a->addr->sa_family) {
		case AF_INET:  printf("\tAddress Family Name: AF_INET\n");//打印网络地址类型 
			if (a->addr)//打印IP地址
				printf("\tAddress: %s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
			if (a->netmask)//打印掩码
				printf("\tNetmask: %s\n", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
			if (a->broadaddr)//打印广播地址 
				printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
			if (a->dstaddr)//目的地址 
				printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr)); break;
		default:  printf("\tAddress Family Name: Unknown\n"); break;
		}
	}  printf("\n");
}