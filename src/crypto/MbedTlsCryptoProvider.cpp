#include "uwb/crypto/MbedTlsCryptoProvider.hpp"
#include <mbedtls/aes.h>
#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>

namespace uwb::crypto {

core::Result<void> MbedTlsCryptoProvider::aes128EcbEncrypt(
    std::span<const std::byte, 16> key,
    std::span<const std::byte, 16> plaintext,
    std::span<std::byte, 16> ciphertext) {

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int ret = mbedtls_aes_setkey_enc(
        &ctx,
        reinterpret_cast<const unsigned char*>(key.data()),
        128
    );

    if (ret != 0) {
        mbedtls_aes_free(&ctx);
        return std::unexpected(core::StatusCode::CryptoOperationFailed);
    }

    ret = mbedtls_aes_crypt_ecb(
        &ctx,
        MBEDTLS_AES_ENCRYPT,
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        reinterpret_cast<unsigned char*>(ciphertext.data())
    );

    mbedtls_aes_free(&ctx);

    if (ret != 0) {
        return std::unexpected(core::StatusCode::CryptoOperationFailed);
    }

    return {};
}

core::Result<void> MbedTlsCryptoProvider::aes256EcbEncrypt(
    std::span<const std::byte, 32> key,
    std::span<const std::byte, 16> plaintext,
    std::span<std::byte, 16> ciphertext) {

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    int ret = mbedtls_aes_setkey_enc(
        &ctx,
        reinterpret_cast<const unsigned char*>(key.data()),
        256
    );

    if (ret != 0) {
        mbedtls_aes_free(&ctx);
        return std::unexpected(core::StatusCode::CryptoOperationFailed);
    }

    ret = mbedtls_aes_crypt_ecb(
        &ctx,
        MBEDTLS_AES_ENCRYPT,
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        reinterpret_cast<unsigned char*>(ciphertext.data())
    );

    mbedtls_aes_free(&ctx);

    if (ret != 0) {
        return std::unexpected(core::StatusCode::CryptoOperationFailed);
    }

    return {};
}

core::Result<void> MbedTlsCryptoProvider::aesCmac(
    std::span<const std::byte> key,
    std::span<const std::byte> message,
    std::span<std::byte, 16> outTag) {

    mbedtls_cipher_type_t cipherType;
    if (key.size() == 16) {
        cipherType = MBEDTLS_CIPHER_AES_128_ECB;
    } else if (key.size() == 32) {
        cipherType = MBEDTLS_CIPHER_AES_256_ECB;
    } else {
        return std::unexpected(core::StatusCode::InvalidParameter);
    }

    const mbedtls_cipher_info_t* cipherInfo = mbedtls_cipher_info_from_type(cipherType);
    if (cipherInfo == nullptr) {
        return std::unexpected(core::StatusCode::CryptoOperationFailed);
    }

    static const unsigned char emptyByte = 0;
    const unsigned char* inData = message.empty()
        ? &emptyByte
        : reinterpret_cast<const unsigned char*>(message.data());

    int ret = mbedtls_cipher_cmac(
        cipherInfo,
        reinterpret_cast<const unsigned char*>(key.data()),
        key.size() * 8,
        inData,
        message.size(),
        reinterpret_cast<unsigned char*>(outTag.data())
    );

    if (ret != 0) {
        return std::unexpected(core::StatusCode::CryptoOperationFailed);
    }

    return {};
}

} // namespace uwb::crypto