#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <iostream>
#include <string>
#include <cassert>
#include <iomanip>
#include <sstream>

class CryptoManager {
private:
    RSA* privateKey = nullptr;
    RSA* publicKey = nullptr;
    static const int KEY_LENGTH = 2048;

    void handleErrors() {
        char err_buf[256];
        ERR_error_string(ERR_get_error(), err_buf);
        throw std::runtime_error(err_buf);
    }

    static std::string toHex(const unsigned char* data, int len) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for(int i = 0; i < len; i++) {
            ss << std::setw(2) << static_cast<int>(data[i]);
        }
        return ss.str();
    }
    
    static std::vector<unsigned char> fromHex(const std::string& hex) {
        std::vector<unsigned char> bytes;
        for(size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

public:
    CryptoManager() {
        OpenSSL_add_all_algorithms();
    }

    ~CryptoManager() {
        if (privateKey) RSA_free(privateKey);
        if (publicKey) RSA_free(publicKey);
        EVP_cleanup();
    }

    bool generateKeyPair() {
        BIGNUM* bne = BN_new();
        BN_set_word(bne, RSA_F4);

        privateKey = RSA_new();
        if (RSA_generate_key_ex(privateKey, KEY_LENGTH, bne, nullptr) != 1) {
            BN_free(bne);
            handleErrors();
            return false;
        }
        
        publicKey = RSAPublicKey_dup(privateKey);
        if (!publicKey) {
            BN_free(bne);
            handleErrors();
            return false;
        }

        BN_free(bne);
        return true;
    }

    
    std::string encrypt(const std::string& plaintext) {
        if (!publicKey) {
            throw std::runtime_error("Public key not loaded");
        }

        std::vector<unsigned char> encrypted(RSA_size(publicKey));
        int encryptedLength = RSA_public_encrypt(
            plaintext.length(),
            reinterpret_cast<const unsigned char*>(plaintext.c_str()),
            encrypted.data(),
            publicKey,
            RSA_PKCS1_OAEP_PADDING
        );

        if (encryptedLength == -1) {
            handleErrors();
        }

        return toHex(encrypted.data(), encryptedLength);
    }

    std::string decrypt(const std::string& encryptedHex) {
        if (!privateKey) {
            throw std::runtime_error("Private key not loaded");
        }

        std::vector<unsigned char> encrypted = fromHex(encryptedHex);
        std::vector<unsigned char> decrypted(RSA_size(privateKey));
        
        int decryptedLength = RSA_private_decrypt(
            encrypted.size(),
            encrypted.data(),
            decrypted.data(),
            privateKey,
            RSA_PKCS1_OAEP_PADDING
        );

        if (decryptedLength == -1) {
            handleErrors();
        }

        return std::string(reinterpret_cast<char*>(decrypted.data()), decryptedLength);
    }

    std::string getPublicKey() const {
        if (!publicKey) {
            throw std::runtime_error("Public key not loaded");
        }

        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPublicKey(bio, publicKey);

        char* keyData = nullptr;
        long keyLength = BIO_get_mem_data(bio, &keyData);

        std::string publicKeyStr(keyData, keyLength);
        BIO_free(bio);

        return publicKeyStr;
    }

    std::string sign(const std::string& message) {
        if (!privateKey) {
            throw std::runtime_error("Private key not loaded");
        }

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, message.c_str(), message.length());
        SHA256_Final(hash, &sha256);

        std::vector<unsigned char> signature(RSA_size(privateKey));
        unsigned int signatureLength;

        if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, 
                     signature.data(), &signatureLength, privateKey) != 1) {
            handleErrors();
        }

        return toHex(signature.data(), signatureLength);
    }

    bool verifySignature(const std::string& message, const std::string& signatureHex,
                    const std::string& signerPublicKey) {
        BIO* bio = BIO_new_mem_buf(signerPublicKey.c_str(), -1);
        if (!bio) {
            throw std::runtime_error("Failed to create BIO");
        }

        RSA* verifyKey = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!verifyKey) {
            throw std::runtime_error("Failed to load verification key");
        }

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, message.c_str(), message.length());
        SHA256_Final(hash, &sha256);

        std::vector<unsigned char> signature = fromHex(signatureHex);

        int result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH,
                              signature.data(), signature.size(), verifyKey);

        RSA_free(verifyKey);
        return result == 1;
    }
};
