#pragma once

#include "uwb/crypto/ICryptoProvider.hpp"

namespace uwb::crypto {

	class MbedTlsCryptoProvider final : public ICryptoProvider {
	public:
		MbedTlsCryptoProvider() = default;
		~MbedTlsCryptoProvider() override = default;

		MbedTlsCryptoProvider(const MbedTlsCryptoProvider&) = delete;
		MbedTlsCryptoProvider& operator=(const MbedTlsCryptoProvider&) = delete;
		MbedTlsCryptoProvider(MbedTlsCryptoProvider&&) = delete;
		MbedTlsCryptoProvider& operator=(MbedTlsCryptoProvider&&) = delete;

		[[nodiscard]] core::Result<void> aes128EcbEncrypt(
				std::span<const std::byte, 16> key,
				std::span<const std::byte, 16> plaintext,
				std::span<std::byte, 16> ciphertext) override;

		[[nodiscard]] core::Result<void> aes256EcbEncrypt(
				std::span<const std::byte, 32> key,
				std::span<const std::byte, 16> plaintext,
				std::span<std::byte, 16> ciphertext) override;

		[[nodiscard]] core::Result<void> aesCmac(
				std::span<const std::byte> key,
				std::span<const std::byte> message,
				std::span<std::byte, 16> outTag) override;
	};

} // namespace uwb::crypto