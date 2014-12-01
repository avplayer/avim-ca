#pragma once

#include <boost/asio/io_service.hpp>

#include "ca.pb.h"

class ca_service
{
public:
	ca_service();
	boost::asio::io_service& get_io_service(){return m_io_service;}

private:
	boost::asio::io_service& m_io_service;
};
