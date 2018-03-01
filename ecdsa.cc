#include "ecdsa.h"

int Ecdsa::newPair(const unsigned char* priv_b)
{
    EC_KEY *key;
    BIGNUM *priv;
    BN_CTX *ctx;
    const EC_GROUP *group;
    EC_POINT *pub;
    
	this->setPriv(priv_b);
    
    /** create a ec keypair **/
    key = EC_KEY_new_by_curve_name(NID_secp256k1);

    /** convert priv_b to a 32-byte BIGNUM **/
    priv = BN_new();
    BN_bin2bn(this->priv_b, 32, priv);
    
    /** insert private key to key pair **/
    EC_KEY_set_private_key(key, priv);
        
    /** derive public key, and insert public key to key pair **/
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    
    group = EC_KEY_get0_group(key);
    pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, priv, NULL, NULL, ctx);
    EC_KEY_set_public_key(key, pub);
    this->key = key;
    this->setPub();
   
    /** release resources **/
    EC_POINT_free(pub);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    BN_clear_free(priv);
    
   
    return 0;
}

int Ecdsa::sign(unsigned char **der, unsigned int*dlen, const char *message, unsigned int len)
{
    ECDSA_SIG *signature;
    unsigned int der_len;
    unsigned char digest[32];
    unsigned char *der_copy;
    
    this->sha256(digest, message, len);
    signature = ECDSA_do_sign(digest, sizeof(digest), this->key);
    //cout << "r: " << BN_bn2hex(signature->r) << endl;
    //cout << "s: " << BN_bn2hex(signature->s) << endl;
    *dlen = ECDSA_size(this->key);
    *der = (unsigned char*)calloc(*dlen, sizeof(unsigned char));
    der_copy = *der;
    i2d_ECDSA_SIG(signature, &der_copy);
    ECDSA_SIG_free(signature);
    
    return 0;
}

int Ecdsa::verify(const unsigned char* der, unsigned int der_len, const char* message, unsigned int len)
{
    const unsigned char* der_copy;
    ECDSA_SIG *signature;
    unsigned char digest[32];
    int res;
    
    der_copy = der;
    signature = d2i_ECDSA_SIG(NULL, &der_copy, der_len);
    this->sha256(digest, message, len);
    /** 1:verified. 2:not verified. 3:library error. **/
    res = ECDSA_do_verify(digest, sizeof(digest), signature, this->p_key);

    return res;
}

int Ecdsa::print()
{   
    cout << "priv (" << this->priv_b_length << "bytes) #:" << endl;
    for(int t=0; t<this->priv_b_length; t++)
    {
        cout << hex << setw(2) << setfill('0') << (unsigned int)this->priv_b[t];
    }
    cout << endl << endl;
    cout << dec << "pub uncompressed (" << this->pub_uncom_length << "bytes) #:" << endl;
    for(int t=0; t<this->pub_uncom_length; t++)
    {
        cout << hex << setw(2) << setfill('0') << (unsigned int)this->pub_uncom[t];
    }
    cout << endl << endl;
    cout << dec << "pub compressed (" << this->pub_com_length << "bytes) #:" << endl;
    for(int t=0; t<this->pub_com_length; t++)
    {
        cout << hex << setw(2) << setfill('0') << (unsigned int)this->pub_com[t];
    }
    cout << endl;
    return 0;
}

int Ecdsa::setPriv(const unsigned char* priv_b) 
{
    this->priv_b = priv_b;
    this->priv_b_length = 32;
    return 0;
}

int Ecdsa::setPub()
{
    unsigned char *pub_copy;
    const unsigned char *pub_bytes_copy;
    /** uncompressed form **/
    EC_KEY_set_conv_form(this->key, POINT_CONVERSION_UNCOMPRESSED);
    this->pub_uncom_length = i2o_ECPublicKey(this->key, NULL);
    this->pub_uncom = (unsigned char*)calloc(this->pub_uncom_length, sizeof(unsigned char));
    pub_copy = this->pub_uncom;
    if (i2o_ECPublicKey(this->key, &pub_copy) != this->pub_uncom_length) {
        cout << "error:Unable to decode public key(uncompressed)" << endl;
        return -1;
    }
    /** compressed form **/
    EC_KEY_set_conv_form(this->key, POINT_CONVERSION_COMPRESSED);
    this->pub_com_length = i2o_ECPublicKey(this->key, NULL);
    this->pub_com = (unsigned char*)calloc(this->pub_com_length, sizeof(unsigned char));
    pub_copy = this->pub_com;
    if (i2o_ECPublicKey(this->key, &pub_copy) != this->pub_com_length) {
        cout << "error:Unable to decode public key(compressed)" << endl;
        return -1;
    }
    /** store EC_KEY formed public key **/
    this->p_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    pub_bytes_copy = this->pub_com;
    o2i_ECPublicKey(&this->p_key, &pub_bytes_copy, this->pub_com_length);
    return 0;
}

int Ecdsa::sha256(unsigned char *digest, const char *message, unsigned int len) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, message, len);
    SHA256_Final(digest, &ctx);
    return 0;
}

