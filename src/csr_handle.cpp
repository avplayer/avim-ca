#include "csr_handle.hpp"

csr_handle::~csr_handle()
{
}

csr_handle::csr_handle(io_service_pool& ios)
	: m_io_service_poll(ios)
{
}

// 在这里处理 csr 推送. avrouter 将 CSR 文件推送过来, CA 呢, 就是要处理后返回 CERT
bool csr_handle::process_csr_push(google::protobuf::Message*, connection_ptr, connection_manager&)
{

}
