#pragma once
#include <cstdint>
#include <string>
#include <openssl/evp.h>
#include <memory>

class RsaTest final
{
// 对外暴露
public:
	RsaTest() = default;
	~RsaTest() {}
	void Init(std::string plantText);
	void DoTest();

// 定义函数
private:
	uint32_t CreatRsaKeyPair(const std::string fileName);

	std::string GetPubKeyPath(const std::string& fileName);
	std::string GetPriKeyPath(const std::string& fileName);
	EVP_PKEY* ReadRsaPrivateKey(const std::string fileName);
	EVP_PKEY* ReadRsaPublicKey(const std::string fileName);
	uint32_t GetDerKey(EVP_PKEY* evpKey, std::unique_ptr<uint8_t[]>& buffer, uint32_t& bufferSize, bool isPrivate);
	EVP_PKEY* GetEvpKeyFromDer(const std::unique_ptr<uint8_t[]>& buffer, const uint32_t& bufferSize, bool isPrivate);
	uint32_t GetPemFromEvpKey(EVP_PKEY* evpKey, std::unique_ptr<char[]>& buffer, uint32_t& buffersize, bool isPrivateKey);
	uint32_t WriteToFile(const std::string& filePath, const char* buffer, const uint32_t& bufferSize);
// 定义成员
private:
	std::string m_plantText;
};

