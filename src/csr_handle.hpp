#pragma once

#include <avproto.hpp>

class csr_handle
{
public:
	csr_handle(boost::asio::io_service&);
	~csr_handle();

public:
	bool process_csr_push(google::protobuf::Message*, avkernel&, boost::asio::yield_context);

private:
	boost::asio::io_service& m_io_service;
};
