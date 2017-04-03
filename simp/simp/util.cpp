#include"util.h"
using namespace std;
/*获取str字符串中第一次出现start字符串和end_str字符串之间的字符串
start为""时表示截取str开头到end_str字符串之间的字符串
end_str为""时表示重start到字符串结尾的字符串
*/
string split(string str, string start, string end_str)
{
	int index = start == "" ? 0 : str.find(start, 0);
	int strart_len = start == "" ? 0 : start.length();
	int end = end_str == "" ? str.length(): str.find(end_str, (index + strart_len));
	string data = string(str, index + strart_len, end - index - strart_len);
	return string(str, index + strart_len, end - index - strart_len);
}
//递归运算用end字符串替换replace字符串
string  replaceAll(string str, string replace,string end)
{
	if (str.find(replace,0) == string::npos)
	{
		return str;
	}
	return replaceAll(str.replace(str.find(replace,0),replace.length(),end),replace,end);
}
//获取http get求情方法的参数列表  返回map类型字符串
string getGeturlMessageMap(string url)
{
	string map = "{messge_count:";
	if (url.find("?",0)==string::npos)
	{
		map += "\"该url没有参数内容！！！\"}";
		return map;
	}
	map = "{";
	return map + replaceAll(string(url, url.find("?", 0) + 1, url.length() - url.find("?", 0)),"&",",")+"}";
}
/*
Base64编码
*/
void Base64Encode(const unsigned char *in_str, int in_len, unsigned char *out_str)
{
	static unsigned char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int curr_out_len = 0;
	int i = 0;
	unsigned char a, b, c;
	out_str[0] = '\0';
	if (in_len > 0)
	{
		while (i < in_len)
		{
			a = in_str[i];
			b = (i + 1 <= in_len) ? 0 : in_str[i + 1];
			c = (i + 2 <= in_len) ? 0 : in_str[i + 2];
			if (i + 2 <  in_len)
			{
				out_str[curr_out_len++] = (base64[(a << 2) & 0x3F]);
				out_str[curr_out_len++] = (base64[((a << 4) & 0xf)]);
				out_str[curr_out_len++] = (base64[((b << 6) & 0x3)]);
				out_str[curr_out_len++] = (base64[c & 0x3F]);
			}
			else if (i + 1 < in_len)
			{
				out_str[curr_out_len++] = (base64[(a << 2) & 0x3F]);
				out_str[curr_out_len++] = (base64[((a << 4) & 0xf)]);
				out_str[curr_out_len++] = (base64[((b << 6) & 0x3)]);
				out_str[curr_out_len++] = '=';
			}
			else
			{
				out_str[curr_out_len++] = (base64[(a << 2) & 0x3F]);
				out_str[curr_out_len++] = (base64[((a << 4) & 0xf)]);
				out_str[curr_out_len++] = '=';
				out_str[curr_out_len++] = '=';
			}
			i += 3;
		}
		out_str[curr_out_len] = '\0';
	}
	return;
}
const char * base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char * base64_encode(const unsigned char * bindata, char * base64, int binlength)
{
	int i, j;
	unsigned char current;

	for (i = 0, j = 0; i < binlength; i += 3)
	{
		current = (bindata[i] >> 2);
		current &= (unsigned char)0x3F;
		base64[j++] = base64char[(int)current];

		current = ((unsigned char)(bindata[i] << 4)) & ((unsigned char)0x30);
		if (i + 1 >= binlength)
		{
			base64[j++] = base64char[(int)current];
			base64[j++] = '=';
			base64[j++] = '=';
			break;
		}
		current |= ((unsigned char)(bindata[i + 1] >> 4)) & ((unsigned char)0x0F);
		base64[j++] = base64char[(int)current];

		current = ((unsigned char)(bindata[i + 1] << 2)) & ((unsigned char)0x3C);
		if (i + 2 >= binlength)
		{
			base64[j++] = base64char[(int)current];
			base64[j++] = '=';
			break;
		}
		current |= ((unsigned char)(bindata[i + 2] >> 6)) & ((unsigned char)0x03);
		base64[j++] = base64char[(int)current];

		current = ((unsigned char)bindata[i + 2]) & ((unsigned char)0x3F);
		base64[j++] = base64char[(int)current];
	}
	base64[j] = '\0';
	return base64;
}