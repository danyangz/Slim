#pragma once

#include <iostream>
#include <string>
#include <vector>

extern "C" {
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
}

class AESgcm {
public:
    AESgcm(const unsigned char *key, const unsigned char *iv, int type, int iv_size);
    
    std::vector<unsigned char> encrypt(const unsigned char *plaintext, size_t len);

    std::vector<unsigned char> decrypt(const unsigned char *ciphertext, size_t len);


protected:
    int block_size_;
    int iv_size_;
    unsigned char *key_;
    unsigned char *iv_;
    EVP_CIPHER_CTX *get_ctx(bool is_decrypt=true);
};
