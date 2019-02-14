#include "crypto.hpp"
#include <cassert>
#include <cstring>

AESgcm::AESgcm(const unsigned char *key, const unsigned char *iv, int type, int iv_size) {
    assert(type == 128 || type == 256);
    block_size_ = type / 8;
    key_ = new unsigned char[block_size_];
    memcpy(key_, key, block_size_);
    iv_ = new unsigned char[iv_size];
    iv_size_ = iv_size;
    memcpy(iv_, iv, iv_size);
}

EVP_CIPHER_CTX *AESgcm::get_ctx(bool is_decrypt) {
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    switch (block_size_ * 8) {
    case 128:
	cipher = EVP_aes_128_gcm();
	break;
    case 192:
	cipher = EVP_aes_192_gcm();
	break;
    case 256:
	cipher = EVP_aes_256_gcm();
	break;
    default:
	break;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (is_decrypt) {
	EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL);
	EVP_DecryptInit_ex(ctx, NULL, NULL, key_, iv_);
    } else {
	EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL);
	EVP_EncryptInit_ex(ctx, NULL, NULL, key_, iv_);
    }
    return ctx;
}

std::vector<unsigned char> AESgcm::encrypt(const unsigned char *plaintext, size_t len) {
    int outlen = 0;
    unsigned char *outbuf = new unsigned char[len + 1024];
    auto ctx = this->get_ctx(false);
    EVP_EncryptUpdate(ctx, outbuf, &outlen, plaintext, len);
    std::vector<unsigned char> ciphertext(outbuf, outbuf + len);
    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    delete[] outbuf;
    return ciphertext;
}

std::vector<unsigned char> AESgcm::decrypt(const unsigned char *ciphertext, size_t len) {
    int outlen = 0;
    unsigned char *outbuf = new unsigned char[len + 1024];
    auto ctx = this->get_ctx(false);
    EVP_DecryptUpdate(ctx, outbuf, &outlen, ciphertext, len);
    std::vector<unsigned char> plaintext(outbuf, outbuf + len);
    EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
    delete[] outbuf;
    return plaintext;
}
