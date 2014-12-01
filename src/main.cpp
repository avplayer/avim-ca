
#include <iostream>
#include <boost/program_options.hpp>
#include <boost/asio.hpp>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "ca_service.hpp"

namespace po = boost::program_options;
namespace asio = boost::asio;

static void terminator(boost::asio::io_service& ios)
{
	ios.stop();
}

/*
 * avCA - 管理 CSR 和 CERT 的简单程序.
 */
int main(int argc, char **argv)
{
	OpenSSL_add_all_algorithms();
	try{
		po::options_description desc("options");
		desc.add_options()
			("help,h", "help message")
			("version", "current avrouter version")
			("certpath",  "path to cert")
			;

		po::variables_map vm;
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);

		if (vm.count("help"))
		{
			std::cout << desc << "\n";
			return 0;
		}
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
	}
	return 0;
}
