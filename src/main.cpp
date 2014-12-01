
#include <iostream>
#include <functional>
#include <thread>
#include <boost/program_options.hpp>
#include <boost/asio.hpp>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "ca_service.hpp"
#include "csr_handle.hpp"

namespace po = boost::program_options;
namespace asio = boost::asio;

static void terminator(io_service_pool& ios, ca_service& serv)
{
	serv.stop();
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

		auto num_threads = std::thread::hardware_concurrency();

		io_service_pool io_pool(num_threads);

		ca_service serv(io_pool, 8086);

		// Ctrl+c异步处理退出.
		boost::asio::signal_set terminator_signal(io_pool.get_io_service());
		terminator_signal.add(SIGINT);
		terminator_signal.add(SIGTERM);
#if defined(SIGQUIT)
		terminator_signal.add(SIGQUIT);
#endif // defined(SIGQUIT)
		terminator_signal.async_wait(std::bind(&terminator, boost::ref(io_pool), boost::ref(serv)));

		csr_handle csr_handler(io_pool);

		serv.add_message_process_moudle("proto.ca.csr_push",
			boost::bind(&csr_handle::process_csr_push, &csr_handler, _1, _2, _3));

		serv.start();

		io_pool.run();
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << std::endl;
	}
	return 0;
}
