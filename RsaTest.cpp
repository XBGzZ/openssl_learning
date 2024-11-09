#include "RsaTest.h"
#include <iostream>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <windows.h>
#include <fstream>

constexpr char RSA_KEY_PATH[] = "C:\\Users\\Rog\\Desktop\\cpp\\openssl\\file\\rsa\\";

constexpr char RSA_PUB_EXT[] = ".pub";
constexpr char RSA_PRI_EXT[] = ".key";
enum ErrorCode : uint32_t {
	SUCCESS = 0,
	FAILED,
	MAX
};
// 初始化成员
void RsaTest::Init(std::string plantText) {
	m_plantText = plantText;
}

// 代码核心入口
void RsaTest::DoTest() {
	constexpr char rsaNewCreate[] = "rsa_2048"; // 原始密钥对名称
	constexpr char rsa1[] = "rsa_pem_evp_pem_2048"; // 被转换一次后的名称
	constexpr char rsa2[] = "rsa_pem_evp_der_evp_pem_2048"; // 被转换一次后的名称
	
	//CreatRsaKeyPair(RSA_KEY_NAME);
	// 读取PEM，转换为EVP_PKEY
	auto priKey = ReadRsaPrivateKey(rsaNewCreate);
	auto pubKey = ReadRsaPublicKey(rsaNewCreate);

	// 用EVP_PKEY转DER格式
	std::unique_ptr<uint8_t[]> derPriBuffer;
	uint32_t derPriBufferLen = 0;
	uint32_t ret = SUCCESS;
	ret = GetDerKey(priKey, derPriBuffer, derPriBufferLen,true);
	std::cout << "Get private Der Key ret = " << ret << std::endl;
	

	std::unique_ptr<uint8_t[]> derPubBuffer;
	uint32_t derPubBufferLen = 0;
	ret = GetDerKey(pubKey, derPubBuffer, derPubBufferLen, false);
	std::cout << "Get public Der Key ret = " << ret << std::endl;

	// DER格式转换EVP_PKEY格式
	EVP_PKEY* derPriKey = GetEvpKeyFromDer(derPriBuffer, derPriBufferLen, true);
	EVP_PKEY* derPubKey = GetEvpKeyFromDer(derPubBuffer, derPubBufferLen, false);

	// EVP_PKEY格式转换为PEM格式
	std::unique_ptr<char[]> pemBuffer;
	uint32_t pemBufferLen = 0;
	if (GetPemFromEvpKey(priKey, pemBuffer, pemBufferLen, true) == SUCCESS) {
		WriteToFile(GetPriKeyPath(rsa1), pemBuffer.get(), pemBufferLen);
	}
	
	if (GetPemFromEvpKey(pubKey, pemBuffer, pemBufferLen, false) == SUCCESS) {
		WriteToFile(GetPubKeyPath(rsa1), pemBuffer.get(), pemBufferLen);
	}

	if (GetPemFromEvpKey(derPriKey, pemBuffer, pemBufferLen, true) == SUCCESS) {
		WriteToFile(GetPriKeyPath(rsa2), pemBuffer.get(), pemBufferLen);
	}

	if (GetPemFromEvpKey(derPubKey, pemBuffer, pemBufferLen, false) == SUCCESS) {
		WriteToFile(GetPubKeyPath(rsa2), pemBuffer.get(), pemBufferLen);
	}
}

// 公钥路径
std::string RsaTest::GetPubKeyPath(const std::string& fileName) {
	return std::string(RSA_KEY_PATH) + fileName + RSA_PUB_EXT;
}

// 私钥路径
std::string RsaTest::GetPriKeyPath(const std::string& fileName){
	return std::string(RSA_KEY_PATH) + fileName + RSA_PRI_EXT;
}

// 生成PKCS#8密钥，并且以PEM格式保存到文件中
uint32_t RsaTest::CreatRsaKeyPair(const std::string fileName) {
	EVP_PKEY* pKey = nullptr;
	EVP_PKEY_CTX* ctx = nullptr;
	auto ret = FAILED;
	do {
		ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
		// 上下文
		if (ctx == nullptr) break;
		// 密钥初始化
		if (EVP_PKEY_keygen_init(ctx) < 0) break;
		// 设置密钥长度
		if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) break;
		// 生成密钥
		if (EVP_PKEY_keygen(ctx, &pKey) <= 0) break;
		// 私钥的写入
		BIO* priBio = BIO_new_file(GetPriKeyPath(fileName).c_str(), "w");
		if (PEM_write_bio_PrivateKey(priBio, pKey, nullptr, nullptr, 0, nullptr, nullptr) != 1) break;
		if (priBio != nullptr) {
			BIO_free(priBio);
		}
		// 公钥的写入
		BIO* pubBio = BIO_new_file(GetPubKeyPath(fileName).c_str(), "w");
		if (PEM_write_bio_PUBKEY(pubBio, pKey) != 1) break;
		if (pubBio != nullptr) {
			BIO_free(pubBio);
		}
    } while (0);
	if (pKey != nullptr) {
		EVP_PKEY_free(pKey);
	}
	if (ctx != nullptr) {
		EVP_PKEY_CTX_free(ctx);
	}
	return ret;
}

// 将PEM格式的密钥读取，转换为EVP_PKEY格式的内存对象
EVP_PKEY* RsaTest::ReadRsaPrivateKey(const std::string fileName) {
	BIO* priBio = nullptr;
	EVP_PKEY* evpKey = nullptr;
	do {
		priBio  = BIO_new_file(GetPriKeyPath(fileName).c_str(), "r");
		if (priBio == nullptr) {
			break;
		}
		evpKey = PEM_read_bio_PrivateKey(priBio, nullptr, nullptr, nullptr);
	} while (0);
	if (priBio != nullptr) {
		BIO_free(priBio);
	}
	return evpKey;
}

// 公钥读取
EVP_PKEY* RsaTest::ReadRsaPublicKey(const std::string fileName) {
	BIO* priBio = nullptr;
	EVP_PKEY* evpKey = nullptr;
	do {
		priBio = BIO_new_file(GetPubKeyPath(fileName).c_str(), "r");
		if (priBio == nullptr) {
			break;
		}
		
		evpKey = PEM_read_bio_PUBKEY(priBio, nullptr, nullptr, nullptr);
	} while (0);
	if (priBio != nullptr) {
		BIO_free(priBio);
	}
	return evpKey;
}

// 再将EVP_PKEY格式的内存对象转换为DER格式
uint32_t RsaTest::GetDerKey(EVP_PKEY* evpKey, std::unique_ptr<uint8_t[]>& buffer, uint32_t& bufferSize, bool isPrivate) {
	BIO* bio = nullptr;
	uint32_t ret = FAILED;
	if (evpKey == nullptr) return ret;
	do {
		bio = BIO_new(BIO_s_mem());
		
		if (isPrivate) {
			i2d_PrivateKey_bio(bio, evpKey);
		}
		else {
			i2d_PUBKEY_bio(bio, evpKey);
		}
		int32_t length = BIO_get_mem_data(bio, nullptr);
		if (length <= 0) break;
		if (buffer != nullptr) {
			buffer.reset();
		}
		// 生成缓冲区长度
		buffer = std::make_unique<uint8_t[]>(length);
		memset(buffer.get(), 0, length);
		if (buffer == nullptr) break;
		length = BIO_read(bio, buffer.get(), length);
		if (length <= 0) break;
		bufferSize = length < 0 ? 0 : length;
		ret = SUCCESS;
	} while (0);
	if (bio != nullptr) {
		BIO_free(bio);
	}
	return ret;
}

// DER转EVP_PKEY格式
EVP_PKEY* RsaTest::GetEvpKeyFromDer(const std::unique_ptr<uint8_t[]>& buffer, const uint32_t& bufferSize, bool isPrivate) {
	BIO* bio = nullptr;
	EVP_PKEY* evpKey = nullptr;
	if (buffer == nullptr) return nullptr;
	do {
		bio = BIO_new(BIO_s_mem());
		BIO_write(bio, buffer.get(), bufferSize);
		int32_t length = BIO_get_mem_data(bio, nullptr);
		if (length <= 0) break;
		if (isPrivate) {
			evpKey = d2i_PrivateKey_bio(bio, nullptr);
		}
		else {
			evpKey = d2i_PUBKEY_bio(bio, nullptr);
		}
	} while (0);
	if (bio != nullptr) {
		BIO_free(bio);
	}
	return evpKey;
}

// EVP_PKEY转PEM
uint32_t RsaTest::GetPemFromEvpKey(EVP_PKEY* evpKey, std::unique_ptr<char[]>& buffer, uint32_t& buffersize, bool isPrivate) {
	BIO* bio = nullptr;
	uint32_t ret = FAILED;
	do {
		bio = BIO_new(BIO_s_mem());
		if (bio == nullptr) break;
		if (isPrivate) {
			PEM_write_bio_PrivateKey(bio, evpKey, nullptr, nullptr, 0, nullptr, nullptr);
		}
		else {
			PEM_write_bio_PUBKEY(bio, evpKey);
		}
		int32_t length = BIO_get_mem_data(bio, nullptr);
		if (length < 0) break;
		// 缓冲区清理
		if (buffer != nullptr) buffer.reset();
		buffersize = 0;

		// 重新构造buffer缓冲区
		uint32_t size = length + 1;
		buffer = std::make_unique<char[]>(size);
		memset(buffer.get(), 0, size);
		
		// BIO缓冲区数据写入buffer中
		length = BIO_read(bio, buffer.get(), length);
		if (length < 0) break;
		buffersize = size;
		ret = SUCCESS;
	} while (0);
	if (bio != nullptr) {
		BIO_free(bio);
	}
	if (ret != SUCCESS && buffer != nullptr) {
		buffer.reset();
	}
	return ret;
}

uint32_t RsaTest::WriteToFile(const std::string &filePath,const char* buffer,const uint32_t &bufferSize) {
	std::fstream f;
	f.open(filePath.c_str(), std::ios::out);
	if (!f.good()) {
		return FAILED;
	}
	// 写入数据到文件  
	f << buffer << '\0';
	// 关闭文件  
	f.close();
	return SUCCESS;
}