#pragma once
#include "Protocol.h"
class tcpModel
{
public:
	tcpModel();
	TCP_HEADER getTcpModel()
	{
		return tcp_model;
	}
	void setTcpModel(TCP_HEADER model)
	{
		tcp_model =model;
	}
private:
	TCP_HEADER  tcp_model;
};