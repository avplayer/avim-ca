#include <cstring>
#include <memory>
#include "csr_handle.hpp"
#include <ca.pb.h>

#include <openssl/x509.h>
#include "easyssl.hpp"
#include "serialization.hpp"

csr_handle::~csr_handle()
{
}

csr_handle::csr_handle(boost::asio::io_service& io, const boost::filesystem::path& dbpath,
	const std::shared_ptr<EVP_PKEY>& pkey, const std::shared_ptr<X509>& cert)
	: m_io_service(io)
	, m_rootca_pkey(pkey)
	, m_rootca_cert(cert)
	, m_dbpath(dbpath)
{
}

// 在这里处理 csr 推送. avrouter 将 CSR 文件推送过来, CA 呢, 就是要处理后返回 CERT
bool csr_handle::process_csr_request(google::protobuf::Message* msg, boost::asio::ip::tcp::socket& socket, boost::asio::yield_context yield_context)
{
	bool csr_integrity_pass = false;
	auto csr_request_msg = dynamic_cast<proto::ca::csr_request*>(msg);

	// CSR 完整性检查
	// TODO 检查 CSR 证书是否有伪造.
	auto in = (const unsigned char *)csr_request_msg->csr().data();

	std::shared_ptr<X509_REQ> csr(d2i_X509_REQ(NULL, &in, static_cast<long>(csr_request_msg->csr().length())), X509_REQ_free);

	std::shared_ptr<EVP_PKEY> evp_pubkey;

	if (csr)
	{
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

					csr_integrity_pass = (0 == memcmp(sha1, csr_request_msg->fingerprint().c_str(), 20));
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

	// 开始签出证书!
	auto signed_cert = csr_sign(csr, evp_pubkey);

	// TODO 向 avrouter 返回 cert !

	proto::ca::csr_result csr_result;

	csr_result.set_cert(X509_to_string(signed_cert.get()));


	boost::asio::async_write(socket, boost::asio::buffer(av_proto::encode(csr_result)), yield_context);
	return true;
}

static inline int X509_NAME_add_entry_by_NID(X509_NAME *subj, int nid, std::string value)
{
	return X509_NAME_add_entry_by_NID(subj, nid, MBSTRING_UTF8, (unsigned char*) value.data(), -1, -1 , 0);
}

static std::string bytes_to_hex(unsigned char bytes[], int length)
{
	char hex_table[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	std::string ret;
	std::for_each(bytes, bytes + length, [hex_table, &ret](unsigned char b)
	{
		ret.append(1, hex_table[(b& 0xF0)>>4]);
		ret.append(1, hex_table[(b& 0xF)]);
	});
	return ret;
}

std::shared_ptr<X509> csr_handle::csr_sign(std::shared_ptr<X509_REQ> csr, std::shared_ptr<EVP_PKEY> user_pkey)
{
	std::string common_name;
	common_name.resize(1024);

	auto csr_x509_name = X509_REQ_get_subject_name(csr.get());

	auto common_name_len = X509_NAME_get_text_by_NID(csr_x509_name, NID_commonName, &common_name[0], common_name.capacity());
	if (common_name_len >0 && common_name_len<1024)
		common_name.resize(common_name_len);
	else
		return false;

	// 计算 av地址 sha256 校验
	unsigned char md[32];
	SHA256((const unsigned char*)common_name.data(), common_name.length(), md);
	std::string certfilename = bytes_to_hex(md, sizeof(md));

	// 然后到 db 里找找看有没有重复
	if (boost::filesystem::exists((m_dbpath / certfilename.substr(4) / certfilename).string().c_str()))
	{
		// FIXME, 最好查看下文件日期, 过期的可以重签
		return false;
	}

	// 来, 把 CERT 签出来
	std::shared_ptr<X509> x509(X509_new(), X509_free);

	ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), advance_to_next_serialNumber());

	X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
	X509_gmtime_adj(X509_get_notAfter(x509.get()), 31536000L);

	X509_set_pubkey(x509.get(), user_pkey.get());

	auto cert_x509_name = X509_get_subject_name(x509.get());

	X509_NAME_add_entry_by_NID(cert_x509_name, NID_commonName, common_name);

	auto ca_name = X509_NAME_dup(X509_get_issuer_name(m_rootca_cert.get()));
	X509_set_issuer_name(x509.get(), ca_name);
	X509_sign(x509.get(), m_rootca_pkey.get(), EVP_sha256());

	// CERT 签出来了, 写入文件
	std::string	x509_cert = X509_to_string(x509.get());

	if (!boost::filesystem::exists(m_dbpath / certfilename.substr(4)))
	{
		boost::filesystem::create_directories(m_dbpath / certfilename.substr(4));
	}

	std::shared_ptr<BIO> certfile(
		BIO_new_file((m_dbpath / certfilename.substr(4) / certfilename).string().c_str(), "w"),
		BIO_free
	);

	PEM_write_bio_X509(certfile.get(), x509.get());
	return x509;
}

long int csr_handle::advance_to_next_serialNumber()
{
	// TODO 从 db 找记录然后返回
	static long int s = 1;
	return s++;
}


