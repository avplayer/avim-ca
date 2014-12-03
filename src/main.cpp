
#include <iostream>
#include <functional>
#include <thread>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>
#include <exception>
#include <system_error>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "ca.pb.h"
#include "csr_handle.hpp"
#include "serialization.hpp"

namespace po = boost::program_options;
namespace asio = boost::asio;
namespace fs = boost::filesystem;

static void load_keys(fs::path pem_cert, fs::path pem_key);

// 这个才是 ROOT CA 签发证书所用到的私钥
std::shared_ptr<EVP_PKEY> rootca_privatekey;
std::shared_ptr<X509> rootca_selfcert;

boost::asio::io_service io_service;

template<typename AsyncStream>
static inline google::protobuf::Message*
async_read_protobuf_message(AsyncStream &_sock, boost::asio::yield_context yield_context)
{
	std::uint32_t l;
	boost::asio::async_read(_sock, boost::asio::buffer(&l, sizeof(l)), boost::asio::transfer_exactly(4), yield_context);
	auto hostl = htonl(l);
	std::string  buf;

	buf.resize(hostl + 4);
	memcpy(&buf[0], &l, 4);
	hostl = boost::asio::async_read(_sock, boost::asio::buffer(&buf[4], hostl),
		boost::asio::transfer_exactly(hostl), yield_context);

	return av_proto::decode(buf);
}

static void ca_main(std::string avrouter_host, std::string avrouter_port, csr_handle& csr_handler, boost::asio::yield_context yield_context)
{
	try
	{
		boost::asio::ip::tcp::socket socket(io_service);
		// 首先连接到 avrouter
		boost::asio::ip::tcp::resolver resolver(io_service);
		boost::asio::ip::tcp::resolver::query query(avrouter_host, avrouter_port);

		auto endpointit = resolver.async_resolve(query, yield_context);

		boost::asio::async_connect(socket, endpointit, yield_context);

		// TODO 发送 ca_announce

		{
			proto::ca::ca_announce ca_announce;
			ca_announce.set_ca_name("avplayer ROOT ca");
			boost::asio::async_write(socket, boost::asio::buffer(av_proto::encode(ca_announce)), yield_context);
		}

		for(;;) // 主循环
		{
			std::unique_ptr<google::protobuf::Message> msg;
			msg.reset(async_read_protobuf_message(socket, yield_context));

			// TODO 读取 csr_request 消息
			if (msg)
				csr_handler.process_csr_request(msg.get(), socket, yield_context);
			else throw std::system_error();
		}

	}catch(const std::exception&)
	{
		// 链接错误, 重试 ...
		boost::system::error_code ec;
		boost::asio::deadline_timer timer(io_service);
		timer.expires_from_now(boost::posix_time::seconds(20));
		timer.async_wait(yield_context[ec]);
		boost::asio::spawn(io_service, std::bind(ca_main, avrouter_host, avrouter_port, std::ref(csr_handler), std::placeholders::_1));
	}
}

/*
 * avCA - 管理 CSR 和 CERT 的简单程序.
 */
int main(int argc, char **argv)
{
	fs::path dbpath;
	fs::path pem_key, pem_cert;


	OpenSSL_add_all_algorithms();

	po::options_description desc("options");
	desc.add_options()
		("help,h", "help message")
		("version", "current avrouter version")
		("ca_root_key", po::value<fs::path>(&pem_key)->default_value("/etc/avimca/root.key"), "path to private key")
		("ca_root_cert", po::value<fs::path>(&pem_cert)->default_value("/etc/avimca/root.cert"), "path to root cert")
		("certdb", po::value<fs::path>(&dbpath)->default_value("/var/lib/avimca"), "path to crt and csr store")
		;

	po::variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);

	if (vm.count("help"))
	{
		std::cout << desc << std::endl;
		return 0;
	}

	// 载入密钥
	load_keys(pem_key, pem_cert);

	// TODO 打开配置文件, 读取需要连入的 router 列表

	csr_handle csr_handler(io_service, dbpath, rootca_privatekey, rootca_selfcert);

	csr_handler.set_root_pkey(rootca_privatekey);

	std::string avrouter_host = "avim.avplayer.org";
	std::string avrouter_port = "24950";

	// 主程序开始
	boost::asio::spawn(io_service, std::bind(ca_main, avrouter_host, avrouter_port, std::ref(csr_handler), std::placeholders::_1));


	// Ctrl+c异步处理退出.
	boost::asio::signal_set terminator_signal(io_service);
	terminator_signal.add(SIGINT);
	terminator_signal.add(SIGTERM);
#if defined(SIGQUIT)
	terminator_signal.add(SIGQUIT);
#endif // defined(SIGQUIT)
	terminator_signal.async_wait([](const boost::system::error_code& error, int){io_service.stop();});

	io_service.run();
	return 0;
}

void load_keys(boost::filesystem::path pem_cert, boost::filesystem::path pem_key)
{
	std::shared_ptr<BIO> bio_root_cert_key {BIO_new_file(pem_cert.string().c_str(), "r") , BIO_free};
	if (!bio_root_cert_key)
	{
		std::cerr << "无法打开 " << pem_cert << std::endl;
		exit(1);
	}

	std::shared_ptr<BIO> bio_root_cert_file {BIO_new_file(pem_key.string().c_str(), "r") , BIO_free};
	if (!bio_root_cert_file)
	{
		std::cerr << "无法打开" << pem_key << std::endl;
		exit(1);
	}

	if (bio_root_cert_key && bio_root_cert_file)
	{
		auto _c_root_key = PEM_read_bio_PrivateKey(bio_root_cert_key.get(), nullptr, [](char * buf, int size, int rwflag, void * parent)->int
		{
			// 提示用户输入密码
			auto text = getpass("输入密码解锁 ca 密钥: ");
			if (text && strlen(text))
			{
				strncpy(buf, text, strlen(text));
				return strlen(text);
			}
			return -1;
		}, (void*) 0);

		rootca_privatekey.reset(_c_root_key, EVP_PKEY_free);
		rootca_selfcert.reset(PEM_read_bio_X509(bio_root_cert_file.get(), NULL, NULL, NULL), X509_free);
	}
}
