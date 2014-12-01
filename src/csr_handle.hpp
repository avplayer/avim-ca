#pragma once
#include "ca_service.hpp"
#include "serialization.hpp"

class csr_handle
{
public:
	csr_handle(io_service_pool&);
	~csr_handle();

public:
	void connection_notify(int type, connection_ptr, connection_manager&);
	bool process_csr_push(google::protobuf::Message*, connection_ptr, connection_manager&);

private:
	io_service_pool& m_io_service_poll;
};
