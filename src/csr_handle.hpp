#pragma once
#include <boost/filesystem.hpp>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include <avproto.hpp>

class csr_handle
{
public:
	csr_handle(boost::asio::io_service&, const boost::filesystem::path&, const std::shared_ptr<EVP_PKEY>&, const std::shared_ptr<X509>&);
	~csr_handle();

public:
	bool process_csr_request(google::protobuf::Message*, avkernel&, boost::asio::yield_context);
	void set_root_pkey(const std::shared_ptr<EVP_PKEY>& rootca_privatekey)
	{
		m_rootca_pkey = rootca_privatekey;
	}

	std::shared_ptr< X509 > csr_sign(std::shared_ptr< X509_REQ > csr, std::shared_ptr< EVP_PKEY > user_pkey);

private:
	boost::asio::io_service& m_io_service;
	boost::filesystem::path m_dbpath;
	std::shared_ptr<EVP_PKEY> m_rootca_pkey;
	std::shared_ptr<X509> m_rootca_cert;
protected:
	long int advance_to_next_serialNumber();
};
