#include <iostream>
#include "ecdsa.h"
#include <cstring>
using namespace std;

int main()
{
	Ecdsa ec;
	
    unsigned char priv_bytes[32] = {
        0x16, 0x26, 0x07, 0x83, 0xe4, 0x0b, 0x16, 0x73,
        0x16, 0x73, 0x62, 0x2a, 0xc8, 0xa5, 0xb0, 0x45,
        0xfc, 0x3e, 0xa4, 0xaf, 0x70, 0xf7, 0x27, 0xf3,
        0xf9, 0xe9, 0x2b, 0xdd, 0x3a, 0x1d, 0xdc, 0x42
    };
	
    ec.newPair(priv_bytes);
	//ec.print();
	unsigned char digest[32];
	const char message[] = "This is a very confidential message.\n";
	
	int res;
	unsigned char *der;
	unsigned int der_len;
	ec.sign(&der, &der_len, message, strlen(message));
	/** 1:verified 0:not verified **/
	res = ec.verify(der, der_len, message, strlen(message));

    return 0;
}