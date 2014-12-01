#include <cstring>
#include <memory>
#include "csr_handle.hpp"
#include <ca.pb.h>

#include <openssl/x509.h>

csr_handle::~csr_handle()
{
}

csr_handle::csr_handle(boost::asio::io_service& io)
	: m_io_service(io)
{
}

// 在这里处理 csr 推送. avrouter 将 CSR 文件推送过来, CA 呢, 就是要处理后返回 CERT
bool csr_handle::process_csr_push(google::protobuf::Message* msg, avkernel& avcore, boost::asio::yield_context yield_context)
{
	bool csr_integrity_pass = false;
	auto csr_push_msg = dynamic_cast<proto::ca::csr_push*>(msg);

	// CSR 完整性检查
	// TODO 检查 CSR 证书是否有伪造.
	auto in = (const unsigned char *)csr_push_msg->csr().data();

	std::shared_ptr<X509_REQ> csr(d2i_X509_REQ(NULL, &in, static_cast<long>(csr_push_msg->csr().length())), X509_REQ_free);

	if (csr)
	{
		std::shared_ptr<EVP_PKEY> evp_pubkey;
		evp_pubkey.reset(X509_REQ_get_pubkey(csr.get()), EVP_PKEY_free);

		if (evp_pubkey && (X509_REQ_verify(csr.get(), evp_pubkey.get()) > 0))
		{
			// integrity pass
			std::shared_ptr<RSA> rsa(EVP_PKEY_get1_RSA(evp_pubkey.get()), RSA_free);
			if (rsa)
			{
				unsigned char * out = nullptr;
				auto l = i2d_RSA_PUBKEY(rsa.get(), &out);

				if ( l > 1)
				{
					std::string rsa_pk12((char*)out, l);
					unsigned char sha1[20];
					SHA1(out, l, sha1);

					csr_integrity_pass = (0 == memcmp(sha1, csr_push_msg->fingerprint().c_str(), 20));
				}

				CRYPTO_free(out);
			}
			// 获取公钥 RSA 指纹
		}
	}

	if (!csr_integrity_pass)
	{
		// 不鸟烂货
		return false;
	}

	// 立即回复 push ok

	proto::ca::push_ok push_ok;
	push_ok.add_fingerprints()->assign(csr_push_msg->fingerprint());


	// 开始签出证书!



	return true;
}
