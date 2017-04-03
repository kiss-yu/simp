#pragma once
#include "reference.h"
string split(string str, string start, string end);
string getGeturlMessageMap(string url);
void Base64Encode(const unsigned char *in_str, int in_len, unsigned char *out_str);
char * base64_encode(const unsigned char * bindata, char * base64, int binlength);