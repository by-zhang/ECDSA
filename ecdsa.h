#ifndef _EC_H
#define _EC_H

#include <iostream>
#include <iomanip>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>

using namespace std;

class Ecdsa 
{
    private:
        EC_KEY *key;
        EC_KEY *p_key;
        const unsigned char *priv_b;
        unsigned int priv_b_length;
        unsigned char *pub_uncom;
        unsigned int pub_uncom_length;
        unsigned char *pub_com;
        unsigned int pub_com_length;
        
        int setPriv(const unsigned char*);
        int setPub();
        int sha256(unsigned char *, const char *, unsigned int);
    public:
	    int newPair(const unsigned char*);
        int sign(unsigned char**, unsigned int*, const char*, unsigned int);
        int verify(const unsigned char*, unsigned int, const char*, unsigned int);
        int print();
        
};
#endif