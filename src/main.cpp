
#include <iostream>
#include <functional>
#include <thread>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "avproto.hpp"
#include "csr_handle.hpp"

#include <avproto/serialization.hpp>

namespace po = boost::program_options;
namespace asio = boost::asio;
namespace fs = boost::filesystem;

static void load_keys(fs::path dir);

// 这个才是 ROOT CA 签发证书所用到的私钥
std::shared_ptr<EVP_PKEY> rootca_privatekey;
std::shared_ptr<X509> rootca_selfcert;

// 这个是 ca 作为 avim 客户端和 avrouter 沟通的时候所用的 key 和 cert
// av地址必须是 ca@avplayer.org
// 利用 avim 网络和 avrouter 沟通, 因此需要一个 av 地址, 这个 key 是 av地址的 key
std::shared_ptr<RSA> ca_avkey;
std::shared_ptr<X509> ca_avcert;

boost::asio::io_service io_service;
avkernel avcore(io_service);

std::shared_ptr<avjackif> avconnect;

static void avrouter_connect_routine(boost::asio::yield_context yield_context)
{
	avconnect.reset(new avjackif(io_service));
	avconnect->set_pki(ca_avkey, ca_avcert);
	auto _debug_host = getenv("AVIM_HOST");

	bool ret = avconnect->async_connect(_debug_host?_debug_host:"avim.avplayer.org", "24950", yield_context);

	avconnect->async_handshake(yield_context);
	avconnect->signal_notify_remove.connect([]()
	{
		boost::asio::spawn(io_service, avrouter_connect_routine);
	});
	avcore.add_interface(avconnect);
	avcore.add_route("router@avplayer.org", "ca@avplayer.org", avconnect->get_ifname(), 100);
}
/*
 * avCA - 管理 CSR 和 CERT 的简单程序.
 */
int main(int argc, char **argv)
{
	fs::path dbpath;
	fs::path certpath;


	OpenSSL_add_all_algorithms();

	po::options_description desc("options");
	desc.add_options()
		("help,h", "help message")
		("version", "current avrouter version")
		("configpath", po::value<fs::path>(&certpath)->default_value("/etc/avimca"), "path to private key and configs")
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

	if (!fs::exists(certpath / "routers.txt"))
	{
		std::cerr << "no " << (certpath / "routers.txt") << " exites."   << std::endl;
		return 1;
	}

	if (!fs::exists(certpath / "routers.txt"))
	{
		std::cerr << "no " << (certpath / "routers.txt") << " exites."   << std::endl;
		return 1;
	}

	// 载入密钥
	load_keys(certpath);

	// TODO 打开配置文件, 读取需要连入的 router 列表

	csr_handle csr_handler(io_service, dbpath, rootca_privatekey, rootca_selfcert);

	csr_handler.set_root_pkey(rootca_privatekey);

	// 现在只是链接到 一个, 就是 router@avplayer.org
	boost::asio::spawn(io_service, avrouter_connect_routine);

	// 主循环开始
	boost::asio::spawn(io_service,[&csr_handler](boost::asio::yield_context yield_context)
	{
		for(;;)
		{
			std::string sender, data;
			avcore.async_recvfrom(sender, data, yield_context);

			if (sender != "router@avplayer.org" || sender != "test-route@avplayer.org" )
				continue;

			if (!is_control_message(data))
				continue;

			// 接到一个 csr 了
			// 尝试解码为 protobuf
			std::shared_ptr<google::protobuf::Message> av_control_message(av_proto::decode(data.substr(1)));
			if (!av_control_message)
				continue;

			if (av_control_message->GetTypeName() == "proto.ca.csr_request")
			{
				csr_handler.process_csr_request(sender, av_control_message.get(), avcore, yield_context);
			}
		}

	});
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

void load_keys(fs::path dir)
{
	std::shared_ptr<BIO> bio_key {BIO_new_file((dir / "avim.key").string().c_str(), "r") , BIO_free};

	if (!bio_key)
	{
		std::cerr << "无法打开 avim.key" << std::endl;
		exit(1);
	}

	std::shared_ptr<BIO> bio_cert {BIO_new_file((dir / "avim.crt").string().c_str(), "r") , BIO_free};
	if (!bio_cert)
	{
		std::cerr << "无法打开 avim.crt" << std::endl;
		exit(1);
	}
	std::shared_ptr<BIO> bio_root_cert_key {BIO_new_file((dir / "root.key").string().c_str(), "r") , BIO_free};
	if (!bio_root_cert_key)
	{
		std::cerr << "无法打开 root.key" << std::endl;
		exit(1);
	}

	std::shared_ptr<BIO> bio_root_cert_file {BIO_new_file((dir / "root.crt").string().c_str(), "r") , BIO_free};
	if (!bio_root_cert_file)
	{
		std::cerr << "无法打开 root.crt" << std::endl;
		exit(1);
	}
	if (bio_cert && bio_key)
	{
		auto _c_rsa_key = PEM_read_bio_RSAPrivateKey(bio_key.get(), nullptr, [](char * buf, int size, int rwflag, void * parent)->int
		{
			// 提示用户输入密码
			auto text = getpass("输入密码解锁 avim 密钥: ");
			if (text && strlen(text))
			{
				strncpy(buf, text, strlen(text));
				return strlen(text);
			}
			return -1;
		}, (void*) 0);

		ca_avkey.reset(_c_rsa_key, RSA_free);
		ca_avcert.reset(PEM_read_bio_X509(bio_cert.get(), NULL, NULL, NULL), X509_free);
	}

	if (bio_root_cert_key && bio_root_cert_file)
	{
		auto _c_root_key = PEM_read_bio_PrivateKey(bio_root_cert_key.get(), nullptr, [](char * buf, int size, int rwflag, void * parent)->int
		{
			// 提示用户输入密码
			auto text = getpass("再次输入密码解锁 root 密钥: ");
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
