#include "VRDriver.hpp"
#include <Driver/ControllerDevice.hpp>
#include <Driver/HMDDevice.hpp>
#include <Driver/TrackerDevice.hpp>
#include <Driver/TrackingReferenceDevice.hpp>

// -----------------------
#include <algorithm>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/coroutine.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/thread.hpp>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <iostream>
#include <string>
#include <sstream>
#include <bitset>

#include <chrono>
#include <thread>

namespace net = boost::asio;            // from <boost/asio.hpp>

// -----------------------
#include <nlohmann/json.hpp>
using json = nlohmann::json;
// -----------------------

// Report a failure
void fail(boost::system::error_code ec, char const* what) {
	std::cerr << what << ": " << ec.message() << "\n";
}

//------------------------------------------------------------------------------

#include <windows.h>
#include <string>
#include <iostream>

std::string GetExeFileName()
{
	char buffer[MAX_PATH];
	GetModuleFileName(NULL, buffer, MAX_PATH);
	return std::string(buffer);
}

std::string GetExePath()
{
	std::string f = GetExeFileName();
	return f.substr(0, f.find_last_of("\\/"));
}

//------------------------------------------------------------------------------
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cassert>

std::string readFileIntoString(std::string& path) {
    std::ifstream input_file(path);
    if (!input_file.is_open()) {
		return std::string("");
    }
    return std::string((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());
}




//------------------------------------------------------------------------------



#include <mutex>

static std::mutex globalVariableProtector;
std::string raw_data = "";

std::string __fastcall get_data() // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector);
	return (raw_data);
}

void __fastcall unlock_data() // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> unlock(globalVariableProtector);
}

void __fastcall set_data(std::string set) // sets the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector);
	raw_data = set;
}

static std::mutex globalVariableProtector_send;
std::string raw_data_send = "";

std::string __fastcall get_data_send() // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_send);
	return (raw_data_send);
}

void __fastcall unlock_data_send() // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> unlock(globalVariableProtector_send);
}

void __fastcall set_data_send(
	std::string set) // sets the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_send);
	raw_data_send = set;
}

static std::mutex globalVariableProtector_echo;
std::string raw_data_echo = "";

std::string __fastcall get_data_echo() // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_echo);
	return (raw_data_echo);
}

void __fastcall unlock_data_echo() // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> unlock(globalVariableProtector_echo);
}

void __fastcall set_data_echo(
	std::string set) // sets the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_echo);
	raw_data_echo = set;
}

static std::mutex globalVariableProtector_localip;
std::string local_ip_echo = "";

std::string __fastcall get_ip_echo() // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_localip);
	return (local_ip_echo);
}

void __fastcall unlock_ip_echo() // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> unlock(globalVariableProtector_localip);
}

void __fastcall set_ip_echo(
	std::string set) // sets the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_localip);
	local_ip_echo = set;
}


static std::mutex globalVariableProtector_ssl_transmit;
std::string ssl_transmit = "";

std::string __fastcall get_ssl_transmit() // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_ssl_transmit);
	return (ssl_transmit);
}

void __fastcall unlock_ssl_transmit() // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> unlock(globalVariableProtector_ssl_transmit);
}

void __fastcall set_ssl_transmit(
	std::string set) // sets the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_ssl_transmit);
	ssl_transmit = set;
}

static std::mutex globalVariableProtector_ssl_sendmessage;
std::string ssl_sendmessage = "";

std::string __fastcall get_ssl_sendmessage() // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_ssl_sendmessage);
	return (ssl_sendmessage);
}

void __fastcall unlock_ssl_sendmessage() // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> unlock(globalVariableProtector_ssl_sendmessage);
}

void __fastcall set_ssl_sendmessage(
	std::string set) // sets the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_ssl_sendmessage);
	ssl_sendmessage = set;
}

static std::mutex globalVariableProtector_ssl_current_character;
std::string ssl_current_character = "";

std::string __fastcall get_ssl_current_character() // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_ssl_current_character);
	return (ssl_current_character);
}

void __fastcall unlock_ssl_current_character() // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> unlock(globalVariableProtector_ssl_current_character);
}

void __fastcall set_ssl_current_character(
	std::string set) // sets the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_ssl_current_character);
	ssl_current_character = set;
}

static std::mutex globalVariableProtector_ssl_next_confirm;
std::string ssl_next_confirm = "";

std::string __fastcall get_ssl_next_confirm() // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_ssl_next_confirm);
	return (ssl_next_confirm);
}

void __fastcall unlock_ssl_next_confirm() // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> unlock(globalVariableProtector_ssl_next_confirm);
}

void __fastcall set_ssl_next_confirm(
	std::string set) // sets the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_ssl_next_confirm);
	ssl_next_confirm = set;
}



//------------------------------------------------------------------------------



std::string ReplaceAll(std::string str, const std::string& from,
	const std::string& to) {
	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos +=
			to.length(); // Handles case where 'to' is a substring of 'from'
	}
	return str;
}



// -------------
// SSL code
// -------------
// start

/**/
#include <boost/asio/buffer.hpp>
#include <boost/asio/ssl/context.hpp>
#include <cstddef>
#include <memory>

void load_server_certificate(boost::asio::ssl::context& ctx)
{
    //    The certificate was generated from CMD.EXE on Windows 10 using:

    //    openssl dhparam -out dh.txt 2048
    //    openssl req -newkey rsa:2048 -nodes -keyout key.txt -x509 -days 10000 -out cert.txt -subj "//C=US\ST=CA\L=Los Angeles\O=Beast\CN=www.example.com"
	

	auto directory = GetExePath();
	auto doc_pre = std::string("\\..\\..\\drivers\\");
	auto driver_name = std::string("websocket_trackers");
	auto doc_post = std::string("\\resources\\ssl\\");
	auto combined_string = directory + doc_pre + driver_name + doc_post;

	std::filesystem::path cert_path(combined_string + "cert.txt");
	std::filesystem::path dh_path(combined_string + "dh.txt");
	std::filesystem::path key_path(combined_string + "key.txt");

	auto cert_path_string = std::string(cert_path.lexically_normal().string());	
	auto dh_path_string = std::string(dh_path.lexically_normal().string());	
	auto key_path_string = std::string(key_path.lexically_normal().string());	
	
	

	std::string cert = readFileIntoString(cert_path_string);

	std::string key = readFileIntoString(key_path_string);

	std::string dh = readFileIntoString(dh_path_string);
    
    ctx.set_password_callback(
        [](std::size_t,
            boost::asio::ssl::context_base::password_purpose)
        {
            return "test";
        });

    ctx.set_options(
        boost::asio::ssl::context::default_workarounds |
        boost::asio::ssl::context::no_sslv2 |
        boost::asio::ssl::context::single_dh_use);

    ctx.use_certificate_chain(
        boost::asio::buffer(cert.data(), cert.size()));

    ctx.use_private_key(
        boost::asio::buffer(key.data(), key.size()),
        boost::asio::ssl::context::file_format::pem);

    ctx.use_tmp_dh(
        boost::asio::buffer(dh.data(), dh.size()));
}

/**/

// -------------
// SSL code
// -------------
// end


// -------------
// WEB SERVER CODE
// -------------
// start
// https://www.boost.org/doc/libs/1_69_0/libs/beast/example/http/server/async/http_server_async.cpp
// listener => listererweb
// session => sessionweb

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
namespace http = boost::beast::http;    // from <boost/beast/http.hpp>

// Return a reasonable mime type based on the extension of a file.
boost::beast::string_view
mime_type(boost::beast::string_view path)
{
	using boost::beast::iequals;
	auto const ext = [&path]
	{
		auto const pos = path.rfind(".");
		if (pos == boost::beast::string_view::npos)
			return boost::beast::string_view{};
		return path.substr(pos);
	}();
	if (iequals(ext, ".htm"))  return "text/html";
	if (iequals(ext, ".html")) return "text/html";
	if (iequals(ext, ".php"))  return "text/html";
	if (iequals(ext, ".css"))  return "text/css";
	if (iequals(ext, ".txt"))  return "text/plain";
	if (iequals(ext, ".js"))   return "application/javascript";
	if (iequals(ext, ".json")) return "application/json";
	if (iequals(ext, ".xml"))  return "application/xml";
	if (iequals(ext, ".swf"))  return "application/x-shockwave-flash";
	if (iequals(ext, ".flv"))  return "video/x-flv";
	if (iequals(ext, ".png"))  return "image/png";
	if (iequals(ext, ".jpe"))  return "image/jpeg";
	if (iequals(ext, ".jpeg")) return "image/jpeg";
	if (iequals(ext, ".jpg"))  return "image/jpeg";
	if (iequals(ext, ".gif"))  return "image/gif";
	if (iequals(ext, ".bmp"))  return "image/bmp";
	if (iequals(ext, ".ico"))  return "image/vnd.microsoft.icon";
	if (iequals(ext, ".tiff")) return "image/tiff";
	if (iequals(ext, ".tif"))  return "image/tiff";
	if (iequals(ext, ".svg"))  return "image/svg+xml";
	if (iequals(ext, ".svgz")) return "image/svg+xml";
	return "application/text";
}

// Append an HTTP rel-path to a local filesystem path.
// The returned path is normalized for the platform.
std::string
path_cat(
	boost::beast::string_view base,
	boost::beast::string_view path)
{
	if (base.empty())
		return path.to_string();
	std::string result = base.to_string();
#if BOOST_MSVC
	char constexpr path_separator = '\\';
	if (result.back() == path_separator)
		result.resize(result.size() - 1);
	result.append(path.data(), path.size());
	for (auto& c : result)
		if (c == '/')
			c = path_separator;
#else
	char constexpr path_separator = '/';
	if (result.back() == path_separator)
		result.resize(result.size() - 1);
	result.append(path.data(), path.size());
#endif
	return result;
}

// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template<
	class Body, class Allocator,
	class Send>
	void
	handle_request(
		boost::beast::string_view doc_root,
		http::request<Body, http::basic_fields<Allocator>>&& req,
		Send&& send)
{
	// Returns a bad request response
	auto const bad_request =
		[&req](boost::beast::string_view why)
	{
		http::response<http::string_body> res{ http::status::bad_request, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = why.to_string();
		res.prepare_payload();
		return res;
	};

	// Returns a not found response
	auto const not_found =
		[&req](boost::beast::string_view target)
	{
		http::response<http::string_body> res{ http::status::not_found, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "The resource '" + target.to_string() + "' was not found.";
		res.prepare_payload();
		return res;
	};

	// Returns a server error response
	auto const server_error =
		[&req](boost::beast::string_view what)
	{
		http::response<http::string_body> res{ http::status::internal_server_error, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "An error occurred: '" + what.to_string() + "'";
		res.prepare_payload();
		return res;
	};

	// Make sure we can handle the method
	if (req.method() != http::verb::get &&
		req.method() != http::verb::head)
		return send(bad_request("Unknown HTTP-method"));

	// Request path must be absolute and not contain "..".
	if (req.target().empty() ||
		req.target()[0] != '/' ||
		req.target().find("..") != boost::beast::string_view::npos)
		return send(bad_request("Illegal request-target"));

	// Build the path to the requested file
	std::string path = path_cat(doc_root, req.target());
	if (req.target().back() == '/')
		path.append("index.html");

	// Attempt to open the file
	boost::beast::error_code ec;
	http::file_body::value_type body;
	body.open(path.c_str(), boost::beast::file_mode::scan, ec);

	// Handle the case where the file doesn't exist
	if (ec == boost::system::errc::no_such_file_or_directory)
		return send(not_found(req.target()));

	// Handle an unknown error
	if (ec)
		return send(server_error(ec.message()));

	// Cache the size since we need it after the move
	auto const size = body.size();

	// Respond to HEAD request
	if (req.method() == http::verb::head)
	{
		http::response<http::empty_body> res{ http::status::ok, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, mime_type(path));
		res.content_length(size);
		res.keep_alive(req.keep_alive());
		return send(std::move(res));
	}

	// Respond to GET request
	http::response<http::file_body> res{
		std::piecewise_construct,
		std::make_tuple(std::move(body)),
		std::make_tuple(http::status::ok, req.version()) };
	res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
	res.set(http::field::content_type, mime_type(path));
	res.content_length(size);
	res.keep_alive(req.keep_alive());
	return send(std::move(res));
}

//------------------------------------------------------------------------------

// Handles an HTTP server connection
class sessionweb : public std::enable_shared_from_this<sessionweb>
{
	// This is the C++11 equivalent of a generic lambda.
	// The function object is used to send an HTTP message.
	struct send_lambda
	{
		sessionweb& self_;

		explicit
			send_lambda(sessionweb& self)
			: self_(self)
		{
		}

		template<bool isRequest, class Body, class Fields>
		void
			operator()(http::message<isRequest, Body, Fields>&& msg) const
		{
			// The lifetime of the message has to extend
			// for the duration of the async operation so
			// we use a shared_ptr to manage it.
			auto sp = std::make_shared<
				http::message<isRequest, Body, Fields>>(std::move(msg));

			// Store a type-erased version of the shared
			// pointer in the class to keep it alive.
			self_.res_ = sp;

			// Write the response
			http::async_write(
				self_.socket_,
				*sp,
				boost::asio::bind_executor(
					self_.strand_,
					std::bind(
						&sessionweb::on_write,
						self_.shared_from_this(),
						std::placeholders::_1,
						std::placeholders::_2,
						sp->need_eof())));
		}
	};

	tcp::socket socket_;
	boost::asio::strand<
		boost::asio::io_context::executor_type> strand_;
	boost::beast::flat_buffer buffer_;
	std::shared_ptr<std::string const> doc_root_;
	http::request<http::string_body> req_;
	std::shared_ptr<void> res_;
	send_lambda lambda_;

public:
	// Take ownership of the socket
	explicit
		sessionweb(
			tcp::socket socket,
			std::shared_ptr<std::string const> const& doc_root)
		: socket_(std::move(socket))
		, strand_(socket_.get_executor())
		, doc_root_(doc_root)
		, lambda_(*this)
	{
	}

	// Start the asynchronous operation
	void
		run()
	{
		do_read();
	}

	void
		do_read()
	{
		// Make the request empty before reading,
		// otherwise the operation behavior is undefined.
		req_ = {};

		// Read a request
		http::async_read(socket_, buffer_, req_,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&sessionweb::on_read,
					shared_from_this(),
					std::placeholders::_1,
					std::placeholders::_2)));
	}

	void
		on_read(
			boost::system::error_code ec,
			std::size_t bytes_transferred)
	{
		boost::ignore_unused(bytes_transferred);

		// This means they closed the connection
		if (ec == http::error::end_of_stream)
			return do_close();

		if (ec)
			return fail(ec, "read");

		// Send the response
		handle_request(*doc_root_, std::move(req_), lambda_);
	}

	void
		on_write(
			boost::system::error_code ec,
			std::size_t bytes_transferred,
			bool close)
	{
		boost::ignore_unused(bytes_transferred);

		if (ec)
			return fail(ec, "write");

		if (close)
		{
			// This means we should close the connection, usually because
			// the response indicated the "Connection: close" semantic.
			return do_close();
		}

		// We're done with the response so delete it
		res_ = nullptr;

		// Read another request
		do_read();
	}

	void
		do_close()
	{
		// Send a TCP shutdown
		boost::system::error_code ec;
		socket_.shutdown(tcp::socket::shutdown_send, ec);

		// At this point the connection is closed gracefully
	}
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the sessionwebs
class listenerweb : public std::enable_shared_from_this<listenerweb>
{
	tcp::acceptor acceptor_;
	tcp::socket socket_;
	std::shared_ptr<std::string const> doc_root_;

public:
	listenerweb(
		boost::asio::io_context& ioc,
		tcp::endpoint endpoint,
		std::shared_ptr<std::string const> const& doc_root)
		: acceptor_(ioc)
		, socket_(ioc)
		, doc_root_(doc_root)
	{
		boost::system::error_code ec;

		// Open the acceptor
		acceptor_.open(endpoint.protocol(), ec);
		if (ec)
		{
			fail(ec, "open");
			return;
		}

		// Allow address reuse
		acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
		if (ec)
		{
			fail(ec, "set_option");
			return;
		}

		// Bind to the server address
		acceptor_.bind(endpoint, ec);
		if (ec)
		{
			fail(ec, "bind");
			return;
		}

		// Start listening for connections
		acceptor_.listen(
			boost::asio::socket_base::max_listen_connections, ec);
		if (ec)
		{
			fail(ec, "listen");
			return;
		}
	}

	// Start accepting incoming connections
	void
		run()
	{
		if (!acceptor_.is_open())
			return;
		do_accept();
	}

	void
		do_accept()
	{
		acceptor_.async_accept(
			socket_,
			std::bind(
				&listenerweb::on_accept,
				shared_from_this(),
				std::placeholders::_1));
	}

	void
		on_accept(boost::system::error_code ec)
	{
		if (ec)
		{
			fail(ec, "accept");
		}
		else
		{
			// Create the sessionweb and run it
			std::make_shared<sessionweb>(
				std::move(socket_),
				doc_root_)->run();
		}

		// Accept another connection
		do_accept();
	}
};

// -------------
// WEB SERVER CODE
// -------------
// end

// -------------
// WEB SERVER CODE ssl0
// -------------
// start
// https://www.boost.org/doc/libs/1_69_0/libs/beast/example/http/server/async-ssl/http_server_async_ssl.cpp

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http;    // from <boost/beast/http.hpp>


// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template<
	class Body, class Allocator,
	class Send>
	void
	handle_request_ssl0(
		boost::beast::string_view doc_root,
		http::request<Body, http::basic_fields<Allocator>>&& req,
		Send&& send)
{
	// Returns a bad request response
	auto const bad_request =
		[&req](boost::beast::string_view why)
	{
		http::response<http::string_body> res{ http::status::bad_request, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = why.to_string();
		res.prepare_payload();
		return res;
	};

	// Returns a not found response
	auto const not_found =
		[&req](boost::beast::string_view target)
	{
		http::response<http::string_body> res{ http::status::not_found, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "The resource '" + target.to_string() + "' was not found.";
		res.prepare_payload();
		return res;
	};

	// Returns a server error response
	auto const server_error =
		[&req](boost::beast::string_view what)
	{
		http::response<http::string_body> res{ http::status::internal_server_error, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "An error occurred: '" + what.to_string() + "'";
		res.prepare_payload();
		return res;
	};

	// Make sure we can handle the method
	if (req.method() != http::verb::get &&
		req.method() != http::verb::head)
		return send(bad_request("Unknown HTTP-method"));

	// Request path must be absolute and not contain "..".
	if (req.target().empty() ||
		req.target()[0] != '/' ||
		req.target().find("..") != boost::beast::string_view::npos)
		return send(bad_request("Illegal request-target"));

	// Build the path to the requested file
	std::string path = path_cat(doc_root, req.target());
	if (req.target().back() == '/')
		path.append("index.html");

	// Attempt to open the file
	boost::beast::error_code ec;
	http::file_body::value_type body;
	body.open(path.c_str(), boost::beast::file_mode::scan, ec);

	// Handle the case where the file doesn't exist
	if (ec == boost::system::errc::no_such_file_or_directory)
		return send(not_found(req.target()));

	// Handle an unknown error
	if (ec)
		return send(server_error(ec.message()));

	// Cache the size since we need it after the move
	auto const size = body.size();

	// Respond to HEAD request
	if (req.method() == http::verb::head)
	{
		http::response<http::empty_body> res{ http::status::ok, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, mime_type(path));
		res.content_length(size);
		res.keep_alive(req.keep_alive());
		return send(std::move(res));
	}

	// Respond to GET request
	http::response<http::file_body> res{
		std::piecewise_construct,
		std::make_tuple(std::move(body)),
		std::make_tuple(http::status::ok, req.version()) };
	res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
	res.set(http::field::content_type, mime_type(path));
	res.content_length(size);
	res.keep_alive(req.keep_alive());
	return send(std::move(res));
}

// Handles an HTTP server connection
class session_ssl0 : public std::enable_shared_from_this<session_ssl0>
{
	// This is the C++11 equivalent of a generic lambda.
	// The function object is used to send an HTTP message.
	struct send_lambda
	{
		session_ssl0& self_;

		explicit
			send_lambda(session_ssl0& self)
			: self_(self)
		{
		}

		template<bool isRequest, class Body, class Fields>
		void
			operator()(http::message<isRequest, Body, Fields>&& msg) const
		{
			// The lifetime of the message has to extend
			// for the duration of the async operation so
			// we use a shared_ptr to manage it.
			auto sp = std::make_shared<
				http::message<isRequest, Body, Fields>>(std::move(msg));

			// Store a type-erased version of the shared
			// pointer in the class to keep it alive.
			self_.res_ = sp;

			// Write the response
			http::async_write(
				self_.stream_,
				*sp,
				boost::asio::bind_executor(
					self_.strand_,
					std::bind(
						&session_ssl0::on_write,
						self_.shared_from_this(),
						std::placeholders::_1,
						std::placeholders::_2,
						sp->need_eof())));
		}
	};

	tcp::socket socket_;
	ssl::stream<tcp::socket&> stream_;
	boost::asio::strand<
		boost::asio::io_context::executor_type> strand_;
	boost::beast::flat_buffer buffer_;
	std::shared_ptr<std::string const> doc_root_;
	http::request<http::string_body> req_;
	std::shared_ptr<void> res_;
	send_lambda lambda_;

public:
	// Take ownership of the socket
	explicit
		session_ssl0(
			tcp::socket socket,
			ssl::context& ctx,
			std::shared_ptr<std::string const> const& doc_root)
		: socket_(std::move(socket))
		, stream_(socket_, ctx)
		, strand_(socket_.get_executor())
		, doc_root_(doc_root)
		, lambda_(*this)
	{
	}

	// Start the asynchronous operation
	void
		run()
	{
		std::string current_data = get_ssl_transmit();
		std::string new_data = current_data + "0";

		unlock_ssl_transmit();
		set_ssl_transmit(new_data);
		unlock_ssl_transmit();

		// Perform the SSL handshake
		stream_.async_handshake(
			ssl::stream_base::server,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_ssl0::on_handshake,
					shared_from_this(),
					std::placeholders::_1)));
	}

	void
		on_handshake(boost::system::error_code ec)
	{
		if (ec)
			return fail(ec, "handshake");

		do_read();
	}

	void
		do_read()
	{
		// Make the request empty before reading,
		// otherwise the operation behavior is undefined.
		req_ = {};

		// Read a request
		http::async_read(stream_, buffer_, req_,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_ssl0::on_read,
					shared_from_this(),
					std::placeholders::_1,
					std::placeholders::_2)));
	}

	void
		on_read(
			boost::system::error_code ec,
			std::size_t bytes_transferred)
	{
		boost::ignore_unused(bytes_transferred);

		// This means they closed the connection
		if (ec == http::error::end_of_stream)
			return do_close();

		if (ec)
			return fail(ec, "read");

		// Send the response
		handle_request_ssl0(*doc_root_, std::move(req_), lambda_);
	}

	void
		on_write(
			boost::system::error_code ec,
			std::size_t bytes_transferred,
			bool close)
	{
		boost::ignore_unused(bytes_transferred);

		if (ec)
			return fail(ec, "write");

		if (close)
		{
			// This means we should close the connection, usually because
			// the response indicated the "Connection: close" semantic.
			return do_close();
		}

		// We're done with the response so delete it
		res_ = nullptr;

		// Read another request
		do_read();
	}

	void
		do_close()
	{
		// Perform the SSL shutdown
		stream_.async_shutdown(
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_ssl0::on_shutdown,
					shared_from_this(),
					std::placeholders::_1)));
	}

	void
		on_shutdown(boost::system::error_code ec)
	{
		if (ec)
			return fail(ec, "shutdown");

		// At this point the connection is closed gracefully
	}
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the session_ssl0s
class listener_ssl0 : public std::enable_shared_from_this<listener_ssl0>
{
	ssl::context& ctx_;
	tcp::acceptor acceptor_;
	tcp::socket socket_;
	std::shared_ptr<std::string const> doc_root_;

public:
	listener_ssl0(
		boost::asio::io_context& ioc,
		ssl::context& ctx,
		tcp::endpoint endpoint,
		std::shared_ptr<std::string const> const& doc_root)
		: ctx_(ctx)
		, acceptor_(ioc)
		, socket_(ioc)
		, doc_root_(doc_root)
	{
		boost::system::error_code ec;

		// Open the acceptor
		acceptor_.open(endpoint.protocol(), ec);
		if (ec)
		{
			fail(ec, "open");
			return;
		}

		// Allow address reuse
		acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
		if (ec)
		{
			fail(ec, "set_option");
			return;
		}

		// Bind to the server address
		acceptor_.bind(endpoint, ec);
		if (ec)
		{
			fail(ec, "bind");
			return;
		}

		// Start listening for connections
		acceptor_.listen(
			boost::asio::socket_base::max_listen_connections, ec);
		if (ec)
		{
			fail(ec, "listen");
			return;
		}
	}

	// Start accepting incoming connections
	void
		run()
	{
		if (!acceptor_.is_open())
			return;
		do_accept();
	}

	void
		do_accept()
	{
		acceptor_.async_accept(
			socket_,
			std::bind(
				&listener_ssl0::on_accept,
				shared_from_this(),
				std::placeholders::_1));
	}

	void
		on_accept(boost::system::error_code ec)
	{
		if (ec)
		{
			fail(ec, "accept");
		}
		else
		{
			// Create the session_ssl0 and run it
			std::make_shared<session_ssl0>(
				std::move(socket_),
				ctx_,
				doc_root_)->run();
		}

		// Accept another connection
		do_accept();
	}
};


// -------------
// WEB SERVER CODE ssl0
// -------------
// end


// -------------
// WEB SERVER CODE ssl1
// -------------
// start
// https://www.boost.org/doc/libs/1_69_0/libs/beast/example/http/server/async-ssl/http_server_async_ssl.cpp

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http;    // from <boost/beast/http.hpp>


// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template<
	class Body, class Allocator,
	class Send>
	void
	handle_request_ssl1(
		boost::beast::string_view doc_root,
		http::request<Body, http::basic_fields<Allocator>>&& req,
		Send&& send)
{
	// Returns a bad request response
	auto const bad_request =
		[&req](boost::beast::string_view why)
	{
		http::response<http::string_body> res{ http::status::bad_request, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = why.to_string();
		res.prepare_payload();
		return res;
	};

	// Returns a not found response
	auto const not_found =
		[&req](boost::beast::string_view target)
	{
		http::response<http::string_body> res{ http::status::not_found, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "The resource '" + target.to_string() + "' was not found.";
		res.prepare_payload();
		return res;
	};

	// Returns a server error response
	auto const server_error =
		[&req](boost::beast::string_view what)
	{
		http::response<http::string_body> res{ http::status::internal_server_error, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "An error occurred: '" + what.to_string() + "'";
		res.prepare_payload();
		return res;
	};

	// Make sure we can handle the method
	if (req.method() != http::verb::get &&
		req.method() != http::verb::head)
		return send(bad_request("Unknown HTTP-method"));

	// Request path must be absolute and not contain "..".
	if (req.target().empty() ||
		req.target()[0] != '/' ||
		req.target().find("..") != boost::beast::string_view::npos)
		return send(bad_request("Illegal request-target"));

	// Build the path to the requested file
	std::string path = path_cat(doc_root, req.target());
	if (req.target().back() == '/')
		path.append("index.html");

	// Attempt to open the file
	boost::beast::error_code ec;
	http::file_body::value_type body;
	body.open(path.c_str(), boost::beast::file_mode::scan, ec);

	// Handle the case where the file doesn't exist
	if (ec == boost::system::errc::no_such_file_or_directory)
		return send(not_found(req.target()));

	// Handle an unknown error
	if (ec)
		return send(server_error(ec.message()));

	// Cache the size since we need it after the move
	auto const size = body.size();

	// Respond to HEAD request
	if (req.method() == http::verb::head)
	{
		http::response<http::empty_body> res{ http::status::ok, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, mime_type(path));
		res.content_length(size);
		res.keep_alive(req.keep_alive());
		return send(std::move(res));
	}

	// Respond to GET request
	http::response<http::file_body> res{
		std::piecewise_construct,
		std::make_tuple(std::move(body)),
		std::make_tuple(http::status::ok, req.version()) };
	res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
	res.set(http::field::content_type, mime_type(path));
	res.content_length(size);
	res.keep_alive(req.keep_alive());
	return send(std::move(res));
}

// Handles an HTTP server connection
class session_ssl1 : public std::enable_shared_from_this<session_ssl1>
{
	// This is the C++11 equivalent of a generic lambda.
	// The function object is used to send an HTTP message.
	struct send_lambda
	{
		session_ssl1& self_;

		explicit
			send_lambda(session_ssl1& self)
			: self_(self)
		{
		}

		template<bool isRequest, class Body, class Fields>
		void
			operator()(http::message<isRequest, Body, Fields>&& msg) const
		{
			// The lifetime of the message has to extend
			// for the duration of the async operation so
			// we use a shared_ptr to manage it.
			auto sp = std::make_shared<
				http::message<isRequest, Body, Fields>>(std::move(msg));

			// Store a type-erased version of the shared
			// pointer in the class to keep it alive.
			self_.res_ = sp;

			// Write the response
			http::async_write(
				self_.stream_,
				*sp,
				boost::asio::bind_executor(
					self_.strand_,
					std::bind(
						&session_ssl1::on_write,
						self_.shared_from_this(),
						std::placeholders::_1,
						std::placeholders::_2,
						sp->need_eof())));
		}
	};

	tcp::socket socket_;
	ssl::stream<tcp::socket&> stream_;
	boost::asio::strand<
		boost::asio::io_context::executor_type> strand_;
	boost::beast::flat_buffer buffer_;
	std::shared_ptr<std::string const> doc_root_;
	http::request<http::string_body> req_;
	std::shared_ptr<void> res_;
	send_lambda lambda_;

public:
	// Take ownership of the socket
	explicit
		session_ssl1(
			tcp::socket socket,
			ssl::context& ctx,
			std::shared_ptr<std::string const> const& doc_root)
		: socket_(std::move(socket))
		, stream_(socket_, ctx)
		, strand_(socket_.get_executor())
		, doc_root_(doc_root)
		, lambda_(*this)
	{
	}

	// Start the asynchronous operation
	void
		run()
	{
		std::string current_data = get_ssl_transmit();
		std::string new_data = current_data + "1";

		unlock_ssl_transmit();
		set_ssl_transmit(new_data);
		unlock_ssl_transmit();

		// Perform the SSL handshake
		stream_.async_handshake(
			ssl::stream_base::server,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_ssl1::on_handshake,
					shared_from_this(),
					std::placeholders::_1)));
	}

	void
		on_handshake(boost::system::error_code ec)
	{
		if (ec)
			return fail(ec, "handshake");

		do_read();
	}

	void
		do_read()
	{
		// Make the request empty before reading,
		// otherwise the operation behavior is undefined.
		req_ = {};

		// Read a request
		http::async_read(stream_, buffer_, req_,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_ssl1::on_read,
					shared_from_this(),
					std::placeholders::_1,
					std::placeholders::_2)));
	}

	void
		on_read(
			boost::system::error_code ec,
			std::size_t bytes_transferred)
	{
		boost::ignore_unused(bytes_transferred);

		// This means they closed the connection
		if (ec == http::error::end_of_stream)
			return do_close();

		if (ec)
			return fail(ec, "read");

		// Send the response
		handle_request_ssl1(*doc_root_, std::move(req_), lambda_);
	}

	void
		on_write(
			boost::system::error_code ec,
			std::size_t bytes_transferred,
			bool close)
	{
		boost::ignore_unused(bytes_transferred);

		if (ec)
			return fail(ec, "write");

		if (close)
		{
			// This means we should close the connection, usually because
			// the response indicated the "Connection: close" semantic.
			return do_close();
		}

		// We're done with the response so delete it
		res_ = nullptr;

		// Read another request
		do_read();
	}

	void
		do_close()
	{
		// Perform the SSL shutdown
		stream_.async_shutdown(
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_ssl1::on_shutdown,
					shared_from_this(),
					std::placeholders::_1)));
	}

	void
		on_shutdown(boost::system::error_code ec)
	{
		if (ec)
			return fail(ec, "shutdown");

		// At this point the connection is closed gracefully
	}
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the session_ssl1s
class listener_ssl1 : public std::enable_shared_from_this<listener_ssl1>
{
	ssl::context& ctx_;
	tcp::acceptor acceptor_;
	tcp::socket socket_;
	std::shared_ptr<std::string const> doc_root_;

public:
	listener_ssl1(
		boost::asio::io_context& ioc,
		ssl::context& ctx,
		tcp::endpoint endpoint,
		std::shared_ptr<std::string const> const& doc_root)
		: ctx_(ctx)
		, acceptor_(ioc)
		, socket_(ioc)
		, doc_root_(doc_root)
	{
		boost::system::error_code ec;

		// Open the acceptor
		acceptor_.open(endpoint.protocol(), ec);
		if (ec)
		{
			fail(ec, "open");
			return;
		}

		// Allow address reuse
		acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
		if (ec)
		{
			fail(ec, "set_option");
			return;
		}

		// Bind to the server address
		acceptor_.bind(endpoint, ec);
		if (ec)
		{
			fail(ec, "bind");
			return;
		}

		// Start listening for connections
		acceptor_.listen(
			boost::asio::socket_base::max_listen_connections, ec);
		if (ec)
		{
			fail(ec, "listen");
			return;
		}
	}

	// Start accepting incoming connections
	void
		run()
	{
		if (!acceptor_.is_open())
			return;
		do_accept();
	}

	void
		do_accept()
	{
		acceptor_.async_accept(
			socket_,
			std::bind(
				&listener_ssl1::on_accept,
				shared_from_this(),
				std::placeholders::_1));
	}

	void
		on_accept(boost::system::error_code ec)
	{
		if (ec)
		{
			fail(ec, "accept");
		}
		else
		{
			// Create the session_ssl1 and run it
			std::make_shared<session_ssl1>(
				std::move(socket_),
				ctx_,
				doc_root_)->run();
		}

		// Accept another connection
		do_accept();
	}
};


// -------------
// WEB SERVER CODE ssl1
// -------------
// end


// -------------
// WEB SERVER CODE sslconfirm
// -------------
// start
// https://www.boost.org/doc/libs/1_69_0/libs/beast/example/http/server/async-ssl/http_server_async_ssl.cpp

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http;    // from <boost/beast/http.hpp>


// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template<
	class Body, class Allocator,
	class Send>
	void
	handle_request_sslconfirm(
		boost::beast::string_view doc_root,
		http::request<Body, http::basic_fields<Allocator>>&& req,
		Send&& send)
{
	// Returns a bad request response
	auto const bad_request =
		[&req](boost::beast::string_view why)
	{
		http::response<http::string_body> res{ http::status::bad_request, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = why.to_string();
		res.prepare_payload();
		return res;
	};

	// Returns a not found response
	auto const not_found =
		[&req](boost::beast::string_view target)
	{
		http::response<http::string_body> res{ http::status::not_found, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "The resource '" + target.to_string() + "' was not found.";
		res.prepare_payload();
		return res;
	};

	// Returns a server error response
	auto const server_error =
		[&req](boost::beast::string_view what)
	{
		http::response<http::string_body> res{ http::status::internal_server_error, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "An error occurred: '" + what.to_string() + "'";
		res.prepare_payload();
		return res;
	};

	// Make sure we can handle the method
	if (req.method() != http::verb::get &&
		req.method() != http::verb::head)
		return send(bad_request("Unknown HTTP-method"));

	// Request path must be absolute and not contain "..".
	if (req.target().empty() ||
		req.target()[0] != '/' ||
		req.target().find("..") != boost::beast::string_view::npos)
		return send(bad_request("Illegal request-target"));

	// Build the path to the requested file
	std::string path = path_cat(doc_root, req.target());
	if (req.target().back() == '/')
		path.append("index.html");

	// Attempt to open the file
	boost::beast::error_code ec;
	http::file_body::value_type body;
	body.open(path.c_str(), boost::beast::file_mode::scan, ec);

	// Handle the case where the file doesn't exist
	if (ec == boost::system::errc::no_such_file_or_directory)
		return send(not_found(req.target()));

	// Handle an unknown error
	if (ec)
		return send(server_error(ec.message()));

	// Cache the size since we need it after the move
	auto const size = body.size();

	// Respond to HEAD request
	if (req.method() == http::verb::head)
	{
		http::response<http::empty_body> res{ http::status::ok, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, mime_type(path));
		res.content_length(size);
		res.keep_alive(req.keep_alive());
		return send(std::move(res));
	}

	// Respond to GET request
	http::response<http::file_body> res{
		std::piecewise_construct,
		std::make_tuple(std::move(body)),
		std::make_tuple(http::status::ok, req.version()) };
	res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
	res.set(http::field::content_type, mime_type(path));
	res.content_length(size);
	res.keep_alive(req.keep_alive());
	return send(std::move(res));
}

// Handles an HTTP server connection
class session_sslconfirm : public std::enable_shared_from_this<session_sslconfirm>
{
	// This is the C++11 equivalent of a generic lambda.
	// The function object is used to send an HTTP message.
	struct send_lambda
	{
		session_sslconfirm& self_;

		explicit
			send_lambda(session_sslconfirm& self)
			: self_(self)
		{
		}

		template<bool isRequest, class Body, class Fields>
		void
			operator()(http::message<isRequest, Body, Fields>&& msg) const
		{
			// The lifetime of the message has to extend
			// for the duration of the async operation so
			// we use a shared_ptr to manage it.
			auto sp = std::make_shared<
				http::message<isRequest, Body, Fields>>(std::move(msg));

			// Store a type-erased version of the shared
			// pointer in the class to keep it alive.
			self_.res_ = sp;

			// Write the response
			http::async_write(
				self_.stream_,
				*sp,
				boost::asio::bind_executor(
					self_.strand_,
					std::bind(
						&session_sslconfirm::on_write,
						self_.shared_from_this(),
						std::placeholders::_1,
						std::placeholders::_2,
						sp->need_eof())));
		}
	};

	tcp::socket socket_;
	ssl::stream<tcp::socket&> stream_;
	boost::asio::strand<
		boost::asio::io_context::executor_type> strand_;
	boost::beast::flat_buffer buffer_;
	std::shared_ptr<std::string const> doc_root_;
	http::request<http::string_body> req_;
	std::shared_ptr<void> res_;
	send_lambda lambda_;

public:
	// Take ownership of the socket
	explicit
		session_sslconfirm(
			tcp::socket socket,
			ssl::context& ctx,
			std::shared_ptr<std::string const> const& doc_root)
		: socket_(std::move(socket))
		, stream_(socket_, ctx)
		, strand_(socket_.get_executor())
		, doc_root_(doc_root)
		, lambda_(*this)
	{
	}

	// Start the asynchronous operation
	void
		run()
	{
		//std::string current_data = get_ssl_transmit();
		//set_data_echo(current_data);
		//unlock_data_echo();


		//unlock_ssl_transmit();
		//set_ssl_transmit("");
		//unlock_ssl_transmit();

		std::string current_data = get_ssl_transmit();
		std::string new_data = current_data;

		unlock_ssl_transmit();

		if (new_data.length() > 8) {
			std::stringstream sstream(new_data);
			std::string output = "";
			while (sstream.good())
			{
				std::bitset<8> bits;
				sstream >> bits;
				auto char_code = bits.to_ulong();
				if (char_code > 0 && char_code < 128) {
					char c = char(char_code);
					output += c;
				}
			}

			output = ReplaceAll(output, "\\", "\\\\");
			output = ReplaceAll(output, "\"", "\\\"");

			set_data_echo(output);
			unlock_data_echo();
		}

		set_ssl_transmit("");
		unlock_ssl_transmit();

		// Perform the SSL handshake
		stream_.async_handshake(
			ssl::stream_base::server,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_sslconfirm::on_handshake,
					shared_from_this(),
					std::placeholders::_1)));
	}

	void
		on_handshake(boost::system::error_code ec)
	{
		if (ec)
			return fail(ec, "handshake");

		do_read();
	}

	void
		do_read()
	{
		// Make the request empty before reading,
		// otherwise the operation behavior is undefined.
		req_ = {};

		// Read a request
		http::async_read(stream_, buffer_, req_,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_sslconfirm::on_read,
					shared_from_this(),
					std::placeholders::_1,
					std::placeholders::_2)));
	}

	void
		on_read(
			boost::system::error_code ec,
			std::size_t bytes_transferred)
	{
		boost::ignore_unused(bytes_transferred);

		// This means they closed the connection
		if (ec == http::error::end_of_stream)
			return do_close();

		if (ec)
			return fail(ec, "read");

		// Send the response
		handle_request_sslconfirm(*doc_root_, std::move(req_), lambda_);
	}

	void
		on_write(
			boost::system::error_code ec,
			std::size_t bytes_transferred,
			bool close)
	{
		boost::ignore_unused(bytes_transferred);

		if (ec)
			return fail(ec, "write");

		if (close)
		{
			// This means we should close the connection, usually because
			// the response indicated the "Connection: close" semantic.
			return do_close();
		}

		// We're done with the response so delete it
		res_ = nullptr;

		// Read another request
		do_read();
	}

	void
		do_close()
	{
		// Perform the SSL shutdown
		stream_.async_shutdown(
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_sslconfirm::on_shutdown,
					shared_from_this(),
					std::placeholders::_1)));
	}

	void
		on_shutdown(boost::system::error_code ec)
	{
		if (ec)
			return fail(ec, "shutdown");

		// At this point the connection is closed gracefully
	}
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the session_sslconfirms
class listener_sslconfirm : public std::enable_shared_from_this<listener_sslconfirm>
{
	ssl::context& ctx_;
	tcp::acceptor acceptor_;
	tcp::socket socket_;
	std::shared_ptr<std::string const> doc_root_;

public:
	listener_sslconfirm(
		boost::asio::io_context& ioc,
		ssl::context& ctx,
		tcp::endpoint endpoint,
		std::shared_ptr<std::string const> const& doc_root)
		: ctx_(ctx)
		, acceptor_(ioc)
		, socket_(ioc)
		, doc_root_(doc_root)
	{
		boost::system::error_code ec;

		// Open the acceptor
		acceptor_.open(endpoint.protocol(), ec);
		if (ec)
		{
			fail(ec, "open");
			return;
		}

		// Allow address reuse
		acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
		if (ec)
		{
			fail(ec, "set_option");
			return;
		}

		// Bind to the server address
		acceptor_.bind(endpoint, ec);
		if (ec)
		{
			fail(ec, "bind");
			return;
		}

		// Start listening for connections
		acceptor_.listen(
			boost::asio::socket_base::max_listen_connections, ec);
		if (ec)
		{
			fail(ec, "listen");
			return;
		}
	}

	// Start accepting incoming connections
	void
		run()
	{
		if (!acceptor_.is_open())
			return;
		do_accept();
	}

	void
		do_accept()
	{
		acceptor_.async_accept(
			socket_,
			std::bind(
				&listener_sslconfirm::on_accept,
				shared_from_this(),
				std::placeholders::_1));
	}

	void
		on_accept(boost::system::error_code ec)
	{
		if (ec)
		{
			fail(ec, "accept");
		}
		else
		{
			// Create the session_sslconfirm and run it
			std::make_shared<session_sslconfirm>(
				std::move(socket_),
				ctx_,
				doc_root_)->run();
		}

		// Accept another connection
		do_accept();
	}
};


// -------------
// WEB SERVER CODE sslconfirm
// -------------
// end


// -------------
// WEB SERVER CODE ssldetect
// -------------
// start
// https://www.boost.org/doc/libs/1_69_0/libs/beast/example/http/server/async-ssl/http_server_async_ssl.cpp

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http;    // from <boost/beast/http.hpp>


// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template<
	class Body, class Allocator,
	class Send>
	void
	handle_request_ssldetect(
		boost::beast::string_view doc_root,
		http::request<Body, http::basic_fields<Allocator>>&& req,
		Send&& send)
{
	// Returns a bad request response
	auto const bad_request =
		[&req](boost::beast::string_view why)
	{
		http::response<http::string_body> res{ http::status::bad_request, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = why.to_string();
		res.prepare_payload();
		return res;
	};

	// Returns a not found response
	auto const not_found =
		[&req](boost::beast::string_view target)
	{
		http::response<http::string_body> res{ http::status::not_found, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "The resource '" + target.to_string() + "' was not found.";
		res.prepare_payload();
		return res;
	};

	// Returns a server error response
	auto const server_error =
		[&req](boost::beast::string_view what)
	{
		http::response<http::string_body> res{ http::status::internal_server_error, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "An error occurred: '" + what.to_string() + "'";
		res.prepare_payload();
		return res;
	};

	// Make sure we can handle the method
	if (req.method() != http::verb::get &&
		req.method() != http::verb::head)
		return send(bad_request("Unknown HTTP-method"));

	// Request path must be absolute and not contain "..".
	if (req.target().empty() ||
		req.target()[0] != '/' ||
		req.target().find("..") != boost::beast::string_view::npos)
		return send(bad_request("Illegal request-target"));

	// Build the path to the requested file
	std::string path = path_cat(doc_root, req.target());
	if (req.target().back() == '/')
		path.append("index.html");

	// Attempt to open the file
	boost::beast::error_code ec;
	http::file_body::value_type body;
	body.open(path.c_str(), boost::beast::file_mode::scan, ec);

	// Handle the case where the file doesn't exist
	if (ec == boost::system::errc::no_such_file_or_directory)
		return send(not_found(req.target()));

	// Handle an unknown error
	if (ec)
		return send(server_error(ec.message()));

	// Cache the size since we need it after the move
	auto const size = body.size();

	// Respond to HEAD request
	if (req.method() == http::verb::head)
	{
		http::response<http::empty_body> res{ http::status::ok, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, mime_type(path));
		res.content_length(size);
		res.keep_alive(req.keep_alive());
		return send(std::move(res));
	}

	// Respond to GET request
	http::response<http::file_body> res{
		std::piecewise_construct,
		std::make_tuple(std::move(body)),
		std::make_tuple(http::status::ok, req.version()) };
	res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
	res.set(http::field::content_type, mime_type(path));
	res.content_length(size);
	res.keep_alive(req.keep_alive());
	return send(std::move(res));
}

// Handles an HTTP server connection
class session_ssldetect : public std::enable_shared_from_this<session_ssldetect>
{
	// This is the C++11 equivalent of a generic lambda.
	// The function object is used to send an HTTP message.
	struct send_lambda
	{
		session_ssldetect& self_;

		explicit
			send_lambda(session_ssldetect& self)
			: self_(self)
		{
		}

		template<bool isRequest, class Body, class Fields>
		void
			operator()(http::message<isRequest, Body, Fields>&& msg) const
		{
			// The lifetime of the message has to extend
			// for the duration of the async operation so
			// we use a shared_ptr to manage it.
			auto sp = std::make_shared<
				http::message<isRequest, Body, Fields>>(std::move(msg));

			// Store a type-erased version of the shared
			// pointer in the class to keep it alive.
			self_.res_ = sp;

			// Write the response
			http::async_write(
				self_.stream_,
				*sp,
				boost::asio::bind_executor(
					self_.strand_,
					std::bind(
						&session_ssldetect::on_write,
						self_.shared_from_this(),
						std::placeholders::_1,
						std::placeholders::_2,
						sp->need_eof())));
		}
	};

	tcp::socket socket_;
	ssl::stream<tcp::socket&> stream_;
	boost::asio::strand<
		boost::asio::io_context::executor_type> strand_;
	boost::beast::flat_buffer buffer_;
	std::shared_ptr<std::string const> doc_root_;
	http::request<http::string_body> req_;
	std::shared_ptr<void> res_;
	send_lambda lambda_;

public:
	// Take ownership of the socket
	explicit
		session_ssldetect(
			tcp::socket socket,
			ssl::context& ctx,
			std::shared_ptr<std::string const> const& doc_root)
		: socket_(std::move(socket))
		, stream_(socket_, ctx)
		, strand_(socket_.get_executor())
		, doc_root_(doc_root)
		, lambda_(*this)
	{
	}

	// Start the asynchronous operation
	void
		run()
	{
		//INSERT CODE HERE

		// Perform the SSL handshake
		stream_.async_handshake(
			ssl::stream_base::server,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_ssldetect::on_handshake,
					shared_from_this(),
					std::placeholders::_1)));
	}

	void
		on_handshake(boost::system::error_code ec)
	{
		if (ec)
			return fail(ec, "handshake");

		do_read();
	}

	void
		do_read()
	{
		// Make the request empty before reading,
		// otherwise the operation behavior is undefined.
		req_ = {};

		// Read a request
		http::async_read(stream_, buffer_, req_,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_ssldetect::on_read,
					shared_from_this(),
					std::placeholders::_1,
					std::placeholders::_2)));
	}

	void
		on_read(
			boost::system::error_code ec,
			std::size_t bytes_transferred)
	{
		boost::ignore_unused(bytes_transferred);

		// This means they closed the connection
		if (ec == http::error::end_of_stream)
			return do_close();

		if (ec)
			return fail(ec, "read");

		// Send the response
		handle_request_ssldetect(*doc_root_, std::move(req_), lambda_);
	}

	void
		on_write(
			boost::system::error_code ec,
			std::size_t bytes_transferred,
			bool close)
	{
		boost::ignore_unused(bytes_transferred);

		if (ec)
			return fail(ec, "write");

		if (close)
		{
			// This means we should close the connection, usually because
			// the response indicated the "Connection: close" semantic.
			return do_close();
		}

		// We're done with the response so delete it
		res_ = nullptr;

		// Read another request
		do_read();
	}

	void
		do_close()
	{
		// Perform the SSL shutdown
		stream_.async_shutdown(
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_ssldetect::on_shutdown,
					shared_from_this(),
					std::placeholders::_1)));
	}

	void
		on_shutdown(boost::system::error_code ec)
	{
		if (ec)
			return fail(ec, "shutdown");

		// At this point the connection is closed gracefully
	}
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the session_ssldetects
class listener_ssldetect : public std::enable_shared_from_this<listener_ssldetect>
{
	ssl::context& ctx_;
	tcp::acceptor acceptor_;
	tcp::socket socket_;
	std::shared_ptr<std::string const> doc_root_;

public:
	listener_ssldetect(
		boost::asio::io_context& ioc,
		ssl::context& ctx,
		tcp::endpoint endpoint,
		std::shared_ptr<std::string const> const& doc_root)
		: ctx_(ctx)
		, acceptor_(ioc)
		, socket_(ioc)
		, doc_root_(doc_root)
	{
		boost::system::error_code ec;

		// Open the acceptor
		acceptor_.open(endpoint.protocol(), ec);
		if (ec)
		{
			fail(ec, "open");
			return;
		}

		// Allow address reuse
		acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
		if (ec)
		{
			fail(ec, "set_option");
			return;
		}

		// Bind to the server address
		acceptor_.bind(endpoint, ec);
		if (ec)
		{
			fail(ec, "bind");
			return;
		}

		// Start listening for connections
		acceptor_.listen(
			boost::asio::socket_base::max_listen_connections, ec);
		if (ec)
		{
			fail(ec, "listen");
			return;
		}
	}

	// Start accepting incoming connections
	void
		run()
	{
		if (!acceptor_.is_open())
			return;
		do_accept();
	}

	void
		do_accept()
	{
		acceptor_.async_accept(
			socket_,
			std::bind(
				&listener_ssldetect::on_accept,
				shared_from_this(),
				std::placeholders::_1));
	}

	void
		on_accept(boost::system::error_code ec)
	{
		if (ec)
		{
			fail(ec, "accept");
		}
		else
		{
			// Create the session_ssldetect and run it
			std::make_shared<session_ssldetect>(
				std::move(socket_),
				ctx_,
				doc_root_)->run();
		}

		// Accept another connection
		do_accept();
	}
};


// -------------
// WEB SERVER CODE ssldetect
// -------------
// end



// -------------
// WEB SERVER CODE sslsend0
// -------------
// start
// https://www.boost.org/doc/libs/1_69_0/libs/beast/example/http/server/async-ssl/http_server_async_ssl.cpp

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http;    // from <boost/beast/http.hpp>


// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template<
	class Body, class Allocator,
	class Send>
	void
	handle_request_sslsend0(
		boost::beast::string_view doc_root,
		http::request<Body, http::basic_fields<Allocator>>&& req,
		Send&& send)
{
	// Returns a bad request response
	auto const bad_request =
		[&req](boost::beast::string_view why)
	{
		http::response<http::string_body> res{ http::status::bad_request, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = why.to_string();
		res.prepare_payload();
		return res;
	};

	// Returns a not found response
	auto const not_found =
		[&req](boost::beast::string_view target)
	{
		http::response<http::string_body> res{ http::status::not_found, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "The resource '" + target.to_string() + "' was not found.";
		res.prepare_payload();
		return res;
	};

	// Returns a server error response
	auto const server_error =
		[&req](boost::beast::string_view what)
	{
		http::response<http::string_body> res{ http::status::internal_server_error, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "An error occurred: '" + what.to_string() + "'";
		res.prepare_payload();
		return res;
	};

	// Make sure we can handle the method
	if (req.method() != http::verb::get &&
		req.method() != http::verb::head)
		return send(bad_request("Unknown HTTP-method"));

	// Request path must be absolute and not contain "..".
	if (req.target().empty() ||
		req.target()[0] != '/' ||
		req.target().find("..") != boost::beast::string_view::npos)
		return send(bad_request("Illegal request-target"));

	// Build the path to the requested file
	std::string path = path_cat(doc_root, req.target());
	if (req.target().back() == '/')
		path.append("index.html");

	// Attempt to open the file
	boost::beast::error_code ec;
	http::file_body::value_type body;
	body.open(path.c_str(), boost::beast::file_mode::scan, ec);

	// Handle the case where the file doesn't exist
	if (ec == boost::system::errc::no_such_file_or_directory)
		return send(not_found(req.target()));

	// Handle an unknown error
	if (ec)
		return send(server_error(ec.message()));

	// Cache the size since we need it after the move
	auto const size = body.size();

	// Respond to HEAD request
	if (req.method() == http::verb::head)
	{
		http::response<http::empty_body> res{ http::status::ok, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, mime_type(path));
		res.content_length(size);
		res.keep_alive(req.keep_alive());
		return send(std::move(res));
	}

	// Respond to GET request
	http::response<http::file_body> res{
		std::piecewise_construct,
		std::make_tuple(std::move(body)),
		std::make_tuple(http::status::ok, req.version()) };
	res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
	res.set(http::field::content_type, mime_type(path));
	res.content_length(size);
	res.keep_alive(req.keep_alive());
	return send(std::move(res));
}

// Handles an HTTP server connection
class session_sslsend0 : public std::enable_shared_from_this<session_sslsend0>
{
	// This is the C++11 equivalent of a generic lambda.
	// The function object is used to send an HTTP message.
	struct send_lambda
	{
		session_sslsend0& self_;

		explicit
			send_lambda(session_sslsend0& self)
			: self_(self)
		{
		}

		template<bool isRequest, class Body, class Fields>
		void
			operator()(http::message<isRequest, Body, Fields>&& msg) const
		{
			// The lifetime of the message has to extend
			// for the duration of the async operation so
			// we use a shared_ptr to manage it.
			auto sp = std::make_shared<
				http::message<isRequest, Body, Fields>>(std::move(msg));

			// Store a type-erased version of the shared
			// pointer in the class to keep it alive.
			self_.res_ = sp;

			// Write the response
			http::async_write(
				self_.stream_,
				*sp,
				boost::asio::bind_executor(
					self_.strand_,
					std::bind(
						&session_sslsend0::on_write,
						self_.shared_from_this(),
						std::placeholders::_1,
						std::placeholders::_2,
						sp->need_eof())));
		}
	};

	tcp::socket socket_;
	ssl::stream<tcp::socket&> stream_;
	boost::asio::strand<
		boost::asio::io_context::executor_type> strand_;
	boost::beast::flat_buffer buffer_;
	std::shared_ptr<std::string const> doc_root_;
	http::request<http::string_body> req_;
	std::shared_ptr<void> res_;
	send_lambda lambda_;

public:
	// Take ownership of the socket
	explicit
		session_sslsend0(
			tcp::socket socket,
			ssl::context& ctx,
			std::shared_ptr<std::string const> const& doc_root)
		: socket_(std::move(socket))
		, stream_(socket_, ctx)
		, strand_(socket_.get_executor())
		, doc_root_(doc_root)
		, lambda_(*this)
	{
	}

	// Start the asynchronous operation
	void
		run()
	{
		std::string current_data = get_ssl_current_character();
		std::string current_char = current_data;
		unlock_ssl_current_character();
		
		if (current_char == "0") {

		}
		else {
			auto start = std::chrono::system_clock::now();
			while (true) {
				std::string should_next = get_ssl_next_confirm();
				std::string should_next_copy = should_next;
				unlock_ssl_next_confirm();

				auto now = std::chrono::system_clock::now();
				std::chrono::duration<double> elapsed_seconds = now - start;

				if (should_next_copy != "" || elapsed_seconds.count() > 2) {
					break;
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(50));
			}
		}

		//return do_close();

		// Perform the SSL handshake
		stream_.async_handshake(
			ssl::stream_base::server,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_sslsend0::on_handshake,
					shared_from_this(),
					std::placeholders::_1)));
	}

	void
		on_handshake(boost::system::error_code ec)
	{
		if (ec)
			return fail(ec, "handshake");

		do_read();
	}

	void
		do_read()
	{
		// Make the request empty before reading,
		// otherwise the operation behavior is undefined.
		req_ = {};

		// Read a request
		http::async_read(stream_, buffer_, req_,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_sslsend0::on_read,
					shared_from_this(),
					std::placeholders::_1,
					std::placeholders::_2)));
	}

	void
		on_read(
			boost::system::error_code ec,
			std::size_t bytes_transferred)
	{
		boost::ignore_unused(bytes_transferred);

		// This means they closed the connection
		if (ec == http::error::end_of_stream)
			return do_close();

		if (ec)
			return fail(ec, "read");

		// Send the response
		handle_request_sslsend0(*doc_root_, std::move(req_), lambda_);
	}

	void
		on_write(
			boost::system::error_code ec,
			std::size_t bytes_transferred,
			bool close)
	{
		boost::ignore_unused(bytes_transferred);

		if (ec)
			return fail(ec, "write");

		if (close)
		{
			// This means we should close the connection, usually because
			// the response indicated the "Connection: close" semantic.
			return do_close();
		}

		// We're done with the response so delete it
		res_ = nullptr;

		// Read another request
		do_read();
	}

	void
		do_close()
	{
		// Perform the SSL shutdown
		stream_.async_shutdown(
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_sslsend0::on_shutdown,
					shared_from_this(),
					std::placeholders::_1)));
	}

	void
		on_shutdown(boost::system::error_code ec)
	{
		if (ec)
			return fail(ec, "shutdown");

		// At this point the connection is closed gracefully
	}
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the session_sslsend0s
class listener_sslsend0 : public std::enable_shared_from_this<listener_sslsend0>
{
	ssl::context& ctx_;
	tcp::acceptor acceptor_;
	tcp::socket socket_;
	std::shared_ptr<std::string const> doc_root_;

public:
	listener_sslsend0(
		boost::asio::io_context& ioc,
		ssl::context& ctx,
		tcp::endpoint endpoint,
		std::shared_ptr<std::string const> const& doc_root)
		: ctx_(ctx)
		, acceptor_(ioc)
		, socket_(ioc)
		, doc_root_(doc_root)
	{
		boost::system::error_code ec;

		// Open the acceptor
		acceptor_.open(endpoint.protocol(), ec);
		if (ec)
		{
			fail(ec, "open");
			return;
		}

		// Allow address reuse
		acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
		if (ec)
		{
			fail(ec, "set_option");
			return;
		}

		// Bind to the server address
		acceptor_.bind(endpoint, ec);
		if (ec)
		{
			fail(ec, "bind");
			return;
		}

		// Start listening for connections
		acceptor_.listen(
			boost::asio::socket_base::max_listen_connections, ec);
		if (ec)
		{
			fail(ec, "listen");
			return;
		}
	}

	// Start accepting incoming connections
	void
		run()
	{
		if (!acceptor_.is_open())
			return;
		do_accept();
	}

	void
		do_accept()
	{
		acceptor_.async_accept(
			socket_,
			std::bind(
				&listener_sslsend0::on_accept,
				shared_from_this(),
				std::placeholders::_1));
	}

	void
		on_accept(boost::system::error_code ec)
	{
		if (ec)
		{
			fail(ec, "accept");
		}
		else
		{
			// Create the session_sslsend0 and run it
			std::make_shared<session_sslsend0>(
				std::move(socket_),
				ctx_,
				doc_root_)->run();
		}

		// Accept another connection
		do_accept();
	}
};


// -------------
// WEB SERVER CODE sslsend0
// -------------
// end


// -------------
// WEB SERVER CODE sslsend1
// -------------
// start
// https://www.boost.org/doc/libs/1_69_0/libs/beast/example/http/server/async-ssl/http_server_async_ssl.cpp

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http;    // from <boost/beast/http.hpp>


// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template<
	class Body, class Allocator,
	class Send>
	void
	handle_request_sslsend1(
		boost::beast::string_view doc_root,
		http::request<Body, http::basic_fields<Allocator>>&& req,
		Send&& send)
{
	// Returns a bad request response
	auto const bad_request =
		[&req](boost::beast::string_view why)
	{
		http::response<http::string_body> res{ http::status::bad_request, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = why.to_string();
		res.prepare_payload();
		return res;
	};

	// Returns a not found response
	auto const not_found =
		[&req](boost::beast::string_view target)
	{
		http::response<http::string_body> res{ http::status::not_found, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "The resource '" + target.to_string() + "' was not found.";
		res.prepare_payload();
		return res;
	};

	// Returns a server error response
	auto const server_error =
		[&req](boost::beast::string_view what)
	{
		http::response<http::string_body> res{ http::status::internal_server_error, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "An error occurred: '" + what.to_string() + "'";
		res.prepare_payload();
		return res;
	};

	// Make sure we can handle the method
	if (req.method() != http::verb::get &&
		req.method() != http::verb::head)
		return send(bad_request("Unknown HTTP-method"));

	// Request path must be absolute and not contain "..".
	if (req.target().empty() ||
		req.target()[0] != '/' ||
		req.target().find("..") != boost::beast::string_view::npos)
		return send(bad_request("Illegal request-target"));

	// Build the path to the requested file
	std::string path = path_cat(doc_root, req.target());
	if (req.target().back() == '/')
		path.append("index.html");

	// Attempt to open the file
	boost::beast::error_code ec;
	http::file_body::value_type body;
	body.open(path.c_str(), boost::beast::file_mode::scan, ec);

	// Handle the case where the file doesn't exist
	if (ec == boost::system::errc::no_such_file_or_directory)
		return send(not_found(req.target()));

	// Handle an unknown error
	if (ec)
		return send(server_error(ec.message()));

	// Cache the size since we need it after the move
	auto const size = body.size();

	// Respond to HEAD request
	if (req.method() == http::verb::head)
	{
		http::response<http::empty_body> res{ http::status::ok, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, mime_type(path));
		res.content_length(size);
		res.keep_alive(req.keep_alive());
		return send(std::move(res));
	}

	// Respond to GET request
	http::response<http::file_body> res{
		std::piecewise_construct,
		std::make_tuple(std::move(body)),
		std::make_tuple(http::status::ok, req.version()) };
	res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
	res.set(http::field::content_type, mime_type(path));
	res.content_length(size);
	res.keep_alive(req.keep_alive());
	return send(std::move(res));
}

// Handles an HTTP server connection
class session_sslsend1 : public std::enable_shared_from_this<session_sslsend1>
{
	// This is the C++11 equivalent of a generic lambda.
	// The function object is used to send an HTTP message.
	struct send_lambda
	{
		session_sslsend1& self_;

		explicit
			send_lambda(session_sslsend1& self)
			: self_(self)
		{
		}

		template<bool isRequest, class Body, class Fields>
		void
			operator()(http::message<isRequest, Body, Fields>&& msg) const
		{
			// The lifetime of the message has to extend
			// for the duration of the async operation so
			// we use a shared_ptr to manage it.
			auto sp = std::make_shared<
				http::message<isRequest, Body, Fields>>(std::move(msg));

			// Store a type-erased version of the shared
			// pointer in the class to keep it alive.
			self_.res_ = sp;

			// Write the response
			http::async_write(
				self_.stream_,
				*sp,
				boost::asio::bind_executor(
					self_.strand_,
					std::bind(
						&session_sslsend1::on_write,
						self_.shared_from_this(),
						std::placeholders::_1,
						std::placeholders::_2,
						sp->need_eof())));
		}
	};

	tcp::socket socket_;
	ssl::stream<tcp::socket&> stream_;
	boost::asio::strand<
		boost::asio::io_context::executor_type> strand_;
	boost::beast::flat_buffer buffer_;
	std::shared_ptr<std::string const> doc_root_;
	http::request<http::string_body> req_;
	std::shared_ptr<void> res_;
	send_lambda lambda_;

public:
	// Take ownership of the socket
	explicit
		session_sslsend1(
			tcp::socket socket,
			ssl::context& ctx,
			std::shared_ptr<std::string const> const& doc_root)
		: socket_(std::move(socket))
		, stream_(socket_, ctx)
		, strand_(socket_.get_executor())
		, doc_root_(doc_root)
		, lambda_(*this)
	{
	}

	// Start the asynchronous operation
	void
		run()
	{
		std::string current_data = get_ssl_current_character();
		std::string current_char = current_data;
		unlock_ssl_current_character();

		if (current_char == "1") {

		}
		else {
			auto start = std::chrono::system_clock::now();
			while (true) {
				std::string should_next = get_ssl_next_confirm();
				std::string should_next_copy = should_next;
				unlock_ssl_next_confirm();

				auto now = std::chrono::system_clock::now();
				std::chrono::duration<double> elapsed_seconds = now - start;

				if (should_next_copy != "" || elapsed_seconds.count() > 2) {
					break;
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(50));
			}
		}

		//return do_close();

		// Perform the SSL handshake
		stream_.async_handshake(
			ssl::stream_base::server,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_sslsend1::on_handshake,
					shared_from_this(),
					std::placeholders::_1)));
	}

	void
		on_handshake(boost::system::error_code ec)
	{
		if (ec)
			return fail(ec, "handshake");

		do_read();
	}

	void
		do_read()
	{
		// Make the request empty before reading,
		// otherwise the operation behavior is undefined.
		req_ = {};

		// Read a request
		http::async_read(stream_, buffer_, req_,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_sslsend1::on_read,
					shared_from_this(),
					std::placeholders::_1,
					std::placeholders::_2)));
	}

	void
		on_read(
			boost::system::error_code ec,
			std::size_t bytes_transferred)
	{
		boost::ignore_unused(bytes_transferred);

		// This means they closed the connection
		if (ec == http::error::end_of_stream)
			return do_close();

		if (ec)
			return fail(ec, "read");

		// Send the response
		handle_request_sslsend1(*doc_root_, std::move(req_), lambda_);
	}

	void
		on_write(
			boost::system::error_code ec,
			std::size_t bytes_transferred,
			bool close)
	{
		boost::ignore_unused(bytes_transferred);

		if (ec)
			return fail(ec, "write");

		if (close)
		{
			// This means we should close the connection, usually because
			// the response indicated the "Connection: close" semantic.
			return do_close();
		}

		// We're done with the response so delete it
		res_ = nullptr;

		// Read another request
		do_read();
	}

	void
		do_close()
	{
		// Perform the SSL shutdown
		stream_.async_shutdown(
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_sslsend1::on_shutdown,
					shared_from_this(),
					std::placeholders::_1)));
	}

	void
		on_shutdown(boost::system::error_code ec)
	{
		if (ec)
			return fail(ec, "shutdown");

		// At this point the connection is closed gracefully
	}
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the session_sslsend1s
class listener_sslsend1 : public std::enable_shared_from_this<listener_sslsend1>
{
	ssl::context& ctx_;
	tcp::acceptor acceptor_;
	tcp::socket socket_;
	std::shared_ptr<std::string const> doc_root_;

public:
	listener_sslsend1(
		boost::asio::io_context& ioc,
		ssl::context& ctx,
		tcp::endpoint endpoint,
		std::shared_ptr<std::string const> const& doc_root)
		: ctx_(ctx)
		, acceptor_(ioc)
		, socket_(ioc)
		, doc_root_(doc_root)
	{
		boost::system::error_code ec;

		// Open the acceptor
		acceptor_.open(endpoint.protocol(), ec);
		if (ec)
		{
			fail(ec, "open");
			return;
		}

		// Allow address reuse
		acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
		if (ec)
		{
			fail(ec, "set_option");
			return;
		}

		// Bind to the server address
		acceptor_.bind(endpoint, ec);
		if (ec)
		{
			fail(ec, "bind");
			return;
		}

		// Start listening for connections
		acceptor_.listen(
			boost::asio::socket_base::max_listen_connections, ec);
		if (ec)
		{
			fail(ec, "listen");
			return;
		}
	}

	// Start accepting incoming connections
	void
		run()
	{
		if (!acceptor_.is_open())
			return;
		do_accept();
	}

	void
		do_accept()
	{
		acceptor_.async_accept(
			socket_,
			std::bind(
				&listener_sslsend1::on_accept,
				shared_from_this(),
				std::placeholders::_1));
	}

	void
		on_accept(boost::system::error_code ec)
	{
		if (ec)
		{
			fail(ec, "accept");
		}
		else
		{
			// Create the session_sslsend1 and run it
			std::make_shared<session_sslsend1>(
				std::move(socket_),
				ctx_,
				doc_root_)->run();
		}

		// Accept another connection
		do_accept();
	}
};


// -------------
// WEB SERVER CODE sslsend1
// -------------
// end


// -------------
// WEB SERVER CODE sslsendnext
// -------------
// start
// https://www.boost.org/doc/libs/1_69_0/libs/beast/example/http/server/async-ssl/http_server_async_ssl.cpp

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http;    // from <boost/beast/http.hpp>


// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template<
	class Body, class Allocator,
	class Send>
	void
	handle_request_sslsendnext(
		boost::beast::string_view doc_root,
		http::request<Body, http::basic_fields<Allocator>>&& req,
		Send&& send)
{
	// Returns a bad request response
	auto const bad_request =
		[&req](boost::beast::string_view why)
	{
		http::response<http::string_body> res{ http::status::bad_request, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = why.to_string();
		res.prepare_payload();
		return res;
	};

	// Returns a not found response
	auto const not_found =
		[&req](boost::beast::string_view target)
	{
		http::response<http::string_body> res{ http::status::not_found, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "The resource '" + target.to_string() + "' was not found.";
		res.prepare_payload();
		return res;
	};

	// Returns a server error response
	auto const server_error =
		[&req](boost::beast::string_view what)
	{
		http::response<http::string_body> res{ http::status::internal_server_error, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "An error occurred: '" + what.to_string() + "'";
		res.prepare_payload();
		return res;
	};

	// Make sure we can handle the method
	if (req.method() != http::verb::get &&
		req.method() != http::verb::head)
		return send(bad_request("Unknown HTTP-method"));

	// Request path must be absolute and not contain "..".
	if (req.target().empty() ||
		req.target()[0] != '/' ||
		req.target().find("..") != boost::beast::string_view::npos)
		return send(bad_request("Illegal request-target"));

	// Build the path to the requested file
	std::string path = path_cat(doc_root, req.target());
	if (req.target().back() == '/')
		path.append("index.html");

	// Attempt to open the file
	boost::beast::error_code ec;
	http::file_body::value_type body;
	body.open(path.c_str(), boost::beast::file_mode::scan, ec);

	// Handle the case where the file doesn't exist
	if (ec == boost::system::errc::no_such_file_or_directory)
		return send(not_found(req.target()));

	// Handle an unknown error
	if (ec)
		return send(server_error(ec.message()));

	// Cache the size since we need it after the move
	auto const size = body.size();

	// Respond to HEAD request
	if (req.method() == http::verb::head)
	{
		http::response<http::empty_body> res{ http::status::ok, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, mime_type(path));
		res.content_length(size);
		res.keep_alive(req.keep_alive());
		return send(std::move(res));
	}

	// Respond to GET request
	http::response<http::file_body> res{
		std::piecewise_construct,
		std::make_tuple(std::move(body)),
		std::make_tuple(http::status::ok, req.version()) };
	res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
	res.set(http::field::content_type, mime_type(path));
	res.content_length(size);
	res.keep_alive(req.keep_alive());
	return send(std::move(res));
}

// Handles an HTTP server connection
class session_sslsendnext : public std::enable_shared_from_this<session_sslsendnext>
{
	// This is the C++11 equivalent of a generic lambda.
	// The function object is used to send an HTTP message.
	struct send_lambda
	{
		session_sslsendnext& self_;

		explicit
			send_lambda(session_sslsendnext& self)
			: self_(self)
		{
		}

		template<bool isRequest, class Body, class Fields>
		void
			operator()(http::message<isRequest, Body, Fields>&& msg) const
		{
			// The lifetime of the message has to extend
			// for the duration of the async operation so
			// we use a shared_ptr to manage it.
			auto sp = std::make_shared<
				http::message<isRequest, Body, Fields>>(std::move(msg));

			// Store a type-erased version of the shared
			// pointer in the class to keep it alive.
			self_.res_ = sp;

			// Write the response
			http::async_write(
				self_.stream_,
				*sp,
				boost::asio::bind_executor(
					self_.strand_,
					std::bind(
						&session_sslsendnext::on_write,
						self_.shared_from_this(),
						std::placeholders::_1,
						std::placeholders::_2,
						sp->need_eof())));
		}
	};

	tcp::socket socket_;
	ssl::stream<tcp::socket&> stream_;
	boost::asio::strand<
		boost::asio::io_context::executor_type> strand_;
	boost::beast::flat_buffer buffer_;
	std::shared_ptr<std::string const> doc_root_;
	http::request<http::string_body> req_;
	std::shared_ptr<void> res_;
	send_lambda lambda_;

public:
	// Take ownership of the socket
	explicit
		session_sslsendnext(
			tcp::socket socket,
			ssl::context& ctx,
			std::shared_ptr<std::string const> const& doc_root)
		: socket_(std::move(socket))
		, stream_(socket_, ctx)
		, strand_(socket_.get_executor())
		, doc_root_(doc_root)
		, lambda_(*this)
	{
	}

	// Start the asynchronous operation
	void
		run()
	{
		//INSERT CODE HERE
		std::string message_to_send = get_ssl_sendmessage();
		std::string message_to_send_copy = message_to_send;

		if (message_to_send_copy.length() > 0) {
			auto current_char = message_to_send_copy.at(0);
			std::string char_to_string(1, current_char);
			set_ssl_current_character(char_to_string);
			unlock_ssl_current_character();

			message_to_send_copy.erase(0, 1);
			unlock_ssl_sendmessage();
			set_ssl_sendmessage(message_to_send_copy);
		}
		else {
			set_ssl_current_character("0");
			unlock_ssl_current_character();
		}
		unlock_ssl_sendmessage();

		set_ssl_next_confirm("next");
		unlock_ssl_next_confirm();
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		set_ssl_next_confirm("");
		unlock_ssl_next_confirm();

		//return do_close();

		// Perform the SSL handshake
		stream_.async_handshake(
			ssl::stream_base::server,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_sslsendnext::on_handshake,
					shared_from_this(),
					std::placeholders::_1)));
	}

	void
		on_handshake(boost::system::error_code ec)
	{
		if (ec)
			return fail(ec, "handshake");

		do_read();
	}

	void
		do_read()
	{
		// Make the request empty before reading,
		// otherwise the operation behavior is undefined.
		req_ = {};

		// Read a request
		http::async_read(stream_, buffer_, req_,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_sslsendnext::on_read,
					shared_from_this(),
					std::placeholders::_1,
					std::placeholders::_2)));
	}

	void
		on_read(
			boost::system::error_code ec,
			std::size_t bytes_transferred)
	{
		boost::ignore_unused(bytes_transferred);

		// This means they closed the connection
		if (ec == http::error::end_of_stream)
			return do_close();

		if (ec)
			return fail(ec, "read");

		// Send the response
		handle_request_sslsendnext(*doc_root_, std::move(req_), lambda_);
	}

	void
		on_write(
			boost::system::error_code ec,
			std::size_t bytes_transferred,
			bool close)
	{
		boost::ignore_unused(bytes_transferred);

		if (ec)
			return fail(ec, "write");

		if (close)
		{
			// This means we should close the connection, usually because
			// the response indicated the "Connection: close" semantic.
			return do_close();
		}

		// We're done with the response so delete it
		res_ = nullptr;

		// Read another request
		do_read();
	}

	void
		do_close()
	{
		// Perform the SSL shutdown
		stream_.async_shutdown(
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_sslsendnext::on_shutdown,
					shared_from_this(),
					std::placeholders::_1)));
	}

	void
		on_shutdown(boost::system::error_code ec)
	{
		if (ec)
			return fail(ec, "shutdown");

		// At this point the connection is closed gracefully
	}
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the session_sslsendnexts
class listener_sslsendnext : public std::enable_shared_from_this<listener_sslsendnext>
{
	ssl::context& ctx_;
	tcp::acceptor acceptor_;
	tcp::socket socket_;
	std::shared_ptr<std::string const> doc_root_;

public:
	listener_sslsendnext(
		boost::asio::io_context& ioc,
		ssl::context& ctx,
		tcp::endpoint endpoint,
		std::shared_ptr<std::string const> const& doc_root)
		: ctx_(ctx)
		, acceptor_(ioc)
		, socket_(ioc)
		, doc_root_(doc_root)
	{
		boost::system::error_code ec;

		// Open the acceptor
		acceptor_.open(endpoint.protocol(), ec);
		if (ec)
		{
			fail(ec, "open");
			return;
		}

		// Allow address reuse
		acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
		if (ec)
		{
			fail(ec, "set_option");
			return;
		}

		// Bind to the server address
		acceptor_.bind(endpoint, ec);
		if (ec)
		{
			fail(ec, "bind");
			return;
		}

		// Start listening for connections
		acceptor_.listen(
			boost::asio::socket_base::max_listen_connections, ec);
		if (ec)
		{
			fail(ec, "listen");
			return;
		}
	}

	// Start accepting incoming connections
	void
		run()
	{
		if (!acceptor_.is_open())
			return;
		do_accept();
	}

	void
		do_accept()
	{
		acceptor_.async_accept(
			socket_,
			std::bind(
				&listener_sslsendnext::on_accept,
				shared_from_this(),
				std::placeholders::_1));
	}

	void
		on_accept(boost::system::error_code ec)
	{
		if (ec)
		{
			fail(ec, "accept");
		}
		else
		{
			// Create the session_sslsendnext and run it
			std::make_shared<session_sslsendnext>(
				std::move(socket_),
				ctx_,
				doc_root_)->run();
		}

		// Accept another connection
		do_accept();
	}
};


// -------------
// WEB SERVER CODE sslsendnext
// -------------
// end


// -------------
// WEB SERVER CODE sslsendrestart
// -------------
// start
// https://www.boost.org/doc/libs/1_69_0/libs/beast/example/http/server/async-ssl/http_server_async_ssl.cpp

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
namespace http = boost::beast::http;    // from <boost/beast/http.hpp>


// This function produces an HTTP response for the given
// request. The type of the response object depends on the
// contents of the request, so the interface requires the
// caller to pass a generic lambda for receiving the response.
template<
	class Body, class Allocator,
	class Send>
	void
	handle_request_sslsendrestart(
		boost::beast::string_view doc_root,
		http::request<Body, http::basic_fields<Allocator>>&& req,
		Send&& send)
{
	// Returns a bad request response
	auto const bad_request =
		[&req](boost::beast::string_view why)
	{
		http::response<http::string_body> res{ http::status::bad_request, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = why.to_string();
		res.prepare_payload();
		return res;
	};

	// Returns a not found response
	auto const not_found =
		[&req](boost::beast::string_view target)
	{
		http::response<http::string_body> res{ http::status::not_found, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "The resource '" + target.to_string() + "' was not found.";
		res.prepare_payload();
		return res;
	};

	// Returns a server error response
	auto const server_error =
		[&req](boost::beast::string_view what)
	{
		http::response<http::string_body> res{ http::status::internal_server_error, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/html");
		res.keep_alive(req.keep_alive());
		res.body() = "An error occurred: '" + what.to_string() + "'";
		res.prepare_payload();
		return res;
	};

	// Make sure we can handle the method
	if (req.method() != http::verb::get &&
		req.method() != http::verb::head)
		return send(bad_request("Unknown HTTP-method"));

	// Request path must be absolute and not contain "..".
	if (req.target().empty() ||
		req.target()[0] != '/' ||
		req.target().find("..") != boost::beast::string_view::npos)
		return send(bad_request("Illegal request-target"));

	// Build the path to the requested file
	std::string path = path_cat(doc_root, req.target());
	if (req.target().back() == '/')
		path.append("index.html");

	// Attempt to open the file
	boost::beast::error_code ec;
	http::file_body::value_type body;
	body.open(path.c_str(), boost::beast::file_mode::scan, ec);

	// Handle the case where the file doesn't exist
	if (ec == boost::system::errc::no_such_file_or_directory)
		return send(not_found(req.target()));

	// Handle an unknown error
	if (ec)
		return send(server_error(ec.message()));

	// Cache the size since we need it after the move
	auto const size = body.size();

	// Respond to HEAD request
	if (req.method() == http::verb::head)
	{
		http::response<http::empty_body> res{ http::status::ok, req.version() };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, mime_type(path));
		res.content_length(size);
		res.keep_alive(req.keep_alive());
		return send(std::move(res));
	}

	// Respond to GET request
	http::response<http::file_body> res{
		std::piecewise_construct,
		std::make_tuple(std::move(body)),
		std::make_tuple(http::status::ok, req.version()) };
	res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
	res.set(http::field::content_type, mime_type(path));
	res.content_length(size);
	res.keep_alive(req.keep_alive());
	return send(std::move(res));
}

// Handles an HTTP server connection
class session_sslsendrestart : public std::enable_shared_from_this<session_sslsendrestart>
{
	// This is the C++11 equivalent of a generic lambda.
	// The function object is used to send an HTTP message.
	struct send_lambda
	{
		session_sslsendrestart& self_;

		explicit
			send_lambda(session_sslsendrestart& self)
			: self_(self)
		{
		}

		template<bool isRequest, class Body, class Fields>
		void
			operator()(http::message<isRequest, Body, Fields>&& msg) const
		{
			// The lifetime of the message has to extend
			// for the duration of the async operation so
			// we use a shared_ptr to manage it.
			auto sp = std::make_shared<
				http::message<isRequest, Body, Fields>>(std::move(msg));

			// Store a type-erased version of the shared
			// pointer in the class to keep it alive.
			self_.res_ = sp;

			// Write the response
			http::async_write(
				self_.stream_,
				*sp,
				boost::asio::bind_executor(
					self_.strand_,
					std::bind(
						&session_sslsendrestart::on_write,
						self_.shared_from_this(),
						std::placeholders::_1,
						std::placeholders::_2,
						sp->need_eof())));
		}
	};

	tcp::socket socket_;
	ssl::stream<tcp::socket&> stream_;
	boost::asio::strand<
		boost::asio::io_context::executor_type> strand_;
	boost::beast::flat_buffer buffer_;
	std::shared_ptr<std::string const> doc_root_;
	http::request<http::string_body> req_;
	std::shared_ptr<void> res_;
	send_lambda lambda_;

public:
	// Take ownership of the socket
	explicit
		session_sslsendrestart(
			tcp::socket socket,
			ssl::context& ctx,
			std::shared_ptr<std::string const> const& doc_root)
		: socket_(std::move(socket))
		, stream_(socket_, ctx)
		, strand_(socket_.get_executor())
		, doc_root_(doc_root)
		, lambda_(*this)
	{
	}

	// Start the asynchronous operation
	void
		run()
	{
		std::string data_message_to_send = get_data_echo();
		std::string data_message_to_send_copy = data_message_to_send;
		unlock_data_echo();

		//Convert to binary
		std::string output = "";
		for (int i = 0; i < data_message_to_send_copy.length(); ++i) {
			std::bitset<8> binary_char(data_message_to_send_copy[i]);

			output += binary_char.to_string();
		}

		set_ssl_sendmessage(output);
		unlock_ssl_sendmessage();


		//Prime the first character
		std::string message_to_send = get_ssl_sendmessage();
		std::string message_to_send_copy = message_to_send;

		if (message_to_send_copy.length() > 0) {
			auto current_char = message_to_send_copy.at(0);
			std::string char_to_string(1, current_char);
			set_ssl_current_character(char_to_string);
			unlock_ssl_current_character();

			message_to_send_copy.erase(0, 1);
			unlock_ssl_sendmessage();
			set_ssl_sendmessage(message_to_send_copy);
		}
		else {
			set_ssl_current_character("0");
			unlock_ssl_current_character();
		}
		unlock_ssl_sendmessage();

		//return do_close();

		// Perform the SSL handshake
		stream_.async_handshake(
			ssl::stream_base::server,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_sslsendrestart::on_handshake,
					shared_from_this(),
					std::placeholders::_1)));
	}

	void
		on_handshake(boost::system::error_code ec)
	{
		if (ec)
			return fail(ec, "handshake");

		do_read();
	}

	void
		do_read()
	{
		// Make the request empty before reading,
		// otherwise the operation behavior is undefined.
		req_ = {};

		// Read a request
		http::async_read(stream_, buffer_, req_,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_sslsendrestart::on_read,
					shared_from_this(),
					std::placeholders::_1,
					std::placeholders::_2)));
	}

	void
		on_read(
			boost::system::error_code ec,
			std::size_t bytes_transferred)
	{
		boost::ignore_unused(bytes_transferred);

		// This means they closed the connection
		if (ec == http::error::end_of_stream)
			return do_close();

		if (ec)
			return fail(ec, "read");

		// Send the response
		handle_request_sslsendrestart(*doc_root_, std::move(req_), lambda_);
	}

	void
		on_write(
			boost::system::error_code ec,
			std::size_t bytes_transferred,
			bool close)
	{
		boost::ignore_unused(bytes_transferred);

		if (ec)
			return fail(ec, "write");

		if (close)
		{
			// This means we should close the connection, usually because
			// the response indicated the "Connection: close" semantic.
			return do_close();
		}

		// We're done with the response so delete it
		res_ = nullptr;

		// Read another request
		do_read();
	}

	void
		do_close()
	{
		// Perform the SSL shutdown
		stream_.async_shutdown(
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session_sslsendrestart::on_shutdown,
					shared_from_this(),
					std::placeholders::_1)));
	}

	void
		on_shutdown(boost::system::error_code ec)
	{
		if (ec)
			return fail(ec, "shutdown");

		// At this point the connection is closed gracefully
	}
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the session_sslsendrestarts
class listener_sslsendrestart : public std::enable_shared_from_this<listener_sslsendrestart>
{
	ssl::context& ctx_;
	tcp::acceptor acceptor_;
	tcp::socket socket_;
	std::shared_ptr<std::string const> doc_root_;

public:
	listener_sslsendrestart(
		boost::asio::io_context& ioc,
		ssl::context& ctx,
		tcp::endpoint endpoint,
		std::shared_ptr<std::string const> const& doc_root)
		: ctx_(ctx)
		, acceptor_(ioc)
		, socket_(ioc)
		, doc_root_(doc_root)
	{
		boost::system::error_code ec;

		// Open the acceptor
		acceptor_.open(endpoint.protocol(), ec);
		if (ec)
		{
			fail(ec, "open");
			return;
		}

		// Allow address reuse
		acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
		if (ec)
		{
			fail(ec, "set_option");
			return;
		}

		// Bind to the server address
		acceptor_.bind(endpoint, ec);
		if (ec)
		{
			fail(ec, "bind");
			return;
		}

		// Start listening for connections
		acceptor_.listen(
			boost::asio::socket_base::max_listen_connections, ec);
		if (ec)
		{
			fail(ec, "listen");
			return;
		}
	}

	// Start accepting incoming connections
	void
		run()
	{
		if (!acceptor_.is_open())
			return;
		do_accept();
	}

	void
		do_accept()
	{
		acceptor_.async_accept(
			socket_,
			std::bind(
				&listener_sslsendrestart::on_accept,
				shared_from_this(),
				std::placeholders::_1));
	}

	void
		on_accept(boost::system::error_code ec)
	{
		if (ec)
		{
			fail(ec, "accept");
		}
		else
		{
			// Create the session_sslsendrestart and run it
			std::make_shared<session_sslsendrestart>(
				std::move(socket_),
				ctx_,
				doc_root_)->run();
		}

		// Accept another connection
		do_accept();
	}
};


// -------------
// WEB SERVER CODE sslsendrestart
// -------------
// end



























// -------------
// WEB SOCKET CODE
// -------------
// start
// https://www.boost.org/doc/libs/1_69_0/libs/beast/example/websocket/server/async/websocket_server_async.cpp

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>
namespace websocket = boost::beast::websocket;  // from <boost/beast/websocket.hpp>

//------------------------------------------------------------------------------

// Echoes back all received WebSocket messages
class session : public std::enable_shared_from_this<session>
{
	websocket::stream<tcp::socket> ws_;
	boost::asio::strand<
		boost::asio::io_context::executor_type> strand_;
	boost::beast::multi_buffer buffer_;

public:
	// Take ownership of the socket
	explicit
		session(tcp::socket socket)
		: ws_(std::move(socket))
		, strand_(ws_.get_executor())
	{
	}

	// Start the asynchronous operation
	void
		run()
	{
		// Accept the websocket handshake
		ws_.async_accept(
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session::on_accept,
					shared_from_this(),
					std::placeholders::_1)));
	}

	void
		on_accept(boost::system::error_code ec)
	{
		if (ec)
			return fail(ec, "accept");

		// Read a message
		do_read();
	}

	void
		do_read()
	{
		// Read a message into our buffer
		ws_.async_read(
			buffer_,
			boost::asio::bind_executor(
				strand_,
				std::bind(
					&session::on_read,
					shared_from_this(),
					std::placeholders::_1,
					std::placeholders::_2)));
	}

	void
		on_read(
			boost::system::error_code ec,
			std::size_t bytes_transferred)
	{
		boost::ignore_unused(bytes_transferred);

		// This indicates that the session was closed
		if (ec == websocket::error::closed)
			return;

		if (ec)
			fail(ec, "read");

		try {
			std::string current_data = get_data();
			unlock_data();

			// This code updates current_data with the message
			std::string message = boost::beast::buffers_to_string(buffer_.data());

			if (message != "" && (message.at(0) == '[' || message.at(0) == '{')) {
				if (message == "") {
					message = "{}";
				}

				if (message.at(0) == '[') {
					message = message.substr(1, message.length() - 2);
				}

				std::string new_message;
				if (current_data == "") {
					new_message = message;
				}
				else {
					new_message = current_data + "," + message;
				}

				set_data(new_message);
				unlock_data();
			}
			else {
				std::string new_echo = message;
				new_echo = ReplaceAll(new_echo, "\\", "\\\\");
				new_echo = ReplaceAll(new_echo, "\"", "\\\"");

				set_data_echo(new_echo);
				unlock_data_echo();
			}

			std::string reply_data = get_data_send();
			unlock_data_send();

			// Format the reply_echo either as a string with double quotes around or as JSON
			std::string reply_echo = get_data_echo();
			unlock_data_echo();

			std::string reply_echo_copy = reply_echo;
			reply_echo = reply_echo + std::string(" ");
			std::size_t n = reply_echo.length();
			std::string escaped;
			escaped.reserve(n * 2);

			for (std::size_t i = 0; i < n; ++i) {
				if (reply_echo[i] == '\\' && reply_echo[i + 1] == '\"') {

				}
				else {
					escaped += reply_echo[i];
				}
			}
			reply_echo = escaped;
			size_t endpos = reply_echo.find_last_not_of(" \t");
			size_t startpos = reply_echo.find_first_not_of(" \t");
			if (std::string::npos != endpos)
			{
				reply_echo = reply_echo.substr(0, endpos + 1);
				reply_echo = reply_echo.substr(startpos);
			}
			else {
				reply_echo.erase(std::remove(std::begin(reply_echo), std::end(reply_echo), ' '), std::end(reply_echo));
			}

			if (reply_echo.length() > 0 && json::accept(reply_echo)) {
				//If valid JSON we use the modified string we made, otherwise use the original string
			}
			else {
				reply_echo = std::string("\"") + reply_echo_copy + std::string("\"");
			}


			std::string local_ip_str = get_ip_echo();
			unlock_ip_echo();

			std::string reply_message = "{\"vr_trackers\": [" + reply_data + "], \"echo\": " + reply_echo + ", \"ip\": [" + local_ip_str + "]" + "}";

			ws_.text(true);
			ws_.async_write(
				net::buffer(reply_message),
				boost::asio::bind_executor(
					strand_,
					std::bind(
						&session::on_write,
						shared_from_this(),
						std::placeholders::_1,
						std::placeholders::_2)));
		}
		catch (...) {
			unlock_data();
			unlock_data_send();
			unlock_data_echo();
			return fail(ec, "write");
		}
	}

	void
		on_write(
			boost::system::error_code ec,
			std::size_t bytes_transferred)
	{
		boost::ignore_unused(bytes_transferred);

		if (ec)
			return fail(ec, "write");

		// Clear the buffer
		buffer_.consume(buffer_.size());

		// Do another read
		do_read();
	}
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the sessions
class listener : public std::enable_shared_from_this<listener>
{
	tcp::acceptor acceptor_;
	tcp::socket socket_;

public:
	listener(
		boost::asio::io_context& ioc,
		tcp::endpoint endpoint)
		: acceptor_(ioc)
		, socket_(ioc)
	{
		boost::system::error_code ec;

		// Open the acceptor
		acceptor_.open(endpoint.protocol(), ec);
		if (ec)
		{
			fail(ec, "open");
			return;
		}

		// Allow address reuse
		acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
		if (ec)
		{
			fail(ec, "set_option");
			return;
		}

		// Bind to the server address
		acceptor_.bind(endpoint, ec);
		if (ec)
		{
			fail(ec, "bind");
			return;
		}

		// Start listening for connections
		acceptor_.listen(
			boost::asio::socket_base::max_listen_connections, ec);
		if (ec)
		{
			fail(ec, "listen");
			return;
		}
	}

	// Start accepting incoming connections
	void
		run()
	{
		if (!acceptor_.is_open())
			return;
		do_accept();
	}

	void
		do_accept()
	{
		acceptor_.async_accept(
			socket_,
			std::bind(
				&listener::on_accept,
				shared_from_this(),
				std::placeholders::_1));
	}

	void
		on_accept(boost::system::error_code ec)
	{
		if (ec)
		{
			fail(ec, "accept");
		}
		else
		{
			// Create the session and run it
			std::make_shared<session>(std::move(socket_))->run();
		}

		// Accept another connection
		do_accept();
	}
};

// -------------
// WEB SOCKET CODE
// -------------
// end

//------------------------------------------------------------------------------
#include <boost/asio.hpp>
namespace ip = boost::asio::ip;

std::string getLocalIP() {
	boost::asio::io_service ioService;
	ip::tcp::resolver resolver(ioService);

	return resolver.resolve(ip::host_name(), "")
		->endpoint()
		.address()
		.to_string();
}

#include <iostream>
#include <winsock.h>
int SaveLocalIP()
{
	char ac[80];
	if (gethostname(ac, sizeof(ac)) == SOCKET_ERROR) {
		return 1;
	}

	struct hostent* phe = gethostbyname(ac);
	if (phe == 0) {
		return 1;
	}

	auto output_string = std::string("");

	for (int i = 0; phe->h_addr_list[i] != 0; ++i) {
		if (i > 0) {
			output_string = output_string + ",";
		}

		struct in_addr addr;
		memcpy(&addr, phe->h_addr_list[i], sizeof(struct in_addr));


		std::string current_ip(inet_ntoa(addr));
		output_string = output_string + std::string("\"") + current_ip + std::string("\"");
	}

	set_ip_echo(output_string);
	unlock_ip_echo();

	return 0;
}

//------------------------------------------------------------------------------

int multithreadServer_ws() {
	// Code for the websocket server
	auto const address = boost::asio::ip::make_address("0.0.0.0");
	auto const port = static_cast<unsigned short>(12100);
	int const threads = 1;

	// The io_context is required for all I/O
	boost::asio::io_context ioc{ threads };

	// Create and launch a listening port
	std::make_shared<listener>(ioc, tcp::endpoint{ address, port })->run();

	// Run the I/O service on the requested number of threads
	std::vector<std::thread> v;
	v.reserve(threads - 1);
	for (auto i = threads - 1; i > 0; --i)
		v.emplace_back(
			[&ioc]
			{
				ioc.run();
			});
	ioc.run();

	return 0;
}

int multithreadServer_web() {
	auto directory = GetExePath();
	auto doc_pre = std::string("\\..\\..\\drivers\\");
	auto driver_name = std::string("websocket_trackers");
	auto doc_post = std::string("\\resources\\webserver\\");
	auto combined_string = directory + doc_pre + driver_name + doc_post;

	std::filesystem::path web_dir_path(combined_string);

	auto compiled_path = std::string(web_dir_path.lexically_normal().string());

	auto doc_root = std::make_shared<std::string>(compiled_path);

	int const threads = 1;

	auto const address = boost::asio::ip::make_address("0.0.0.0");
	auto const port = static_cast<unsigned short>(12101);


	// The io_context is required for all I/O
	boost::asio::io_context ioc{ threads };

	// Create and launch a listening port
	std::make_shared<listenerweb>(
		ioc,
		tcp::endpoint{ address, port },
		doc_root)->run();

	// Run the I/O service on the requested number of threads
	std::vector<std::thread> v;
	v.reserve(threads - 1);
	for (auto i = threads - 1; i > 0; --i)
		v.emplace_back(
			[&ioc]
			{
				ioc.run();
			});
	ioc.run();

	return 0;
}

int multithreadServer_ssl0() {
	auto directory = GetExePath();
	auto doc_pre = std::string("\\..\\..\\drivers\\");
	auto driver_name = std::string("websocket_trackers");
	auto doc_post = std::string("\\resources\\webserver\\");
	auto combined_string = directory + doc_pre + driver_name + doc_post;

	std::filesystem::path web_dir_path(combined_string);

	auto compiled_path = std::string(web_dir_path.lexically_normal().string());

	auto doc_root = std::make_shared<std::string>(compiled_path);

	int const threads = 5;

	auto const address = boost::asio::ip::make_address("0.0.0.0");
	auto const port = static_cast<unsigned short>(12110);


	// The io_context is required for all I/O
	boost::asio::io_context ioc{ threads };

	// The SSL context is required, and holds certificates
	ssl::context ctx{ ssl::context::sslv23 };

	// This holds the self-signed certificate used by the server
	load_server_certificate(ctx);

	// Create and launch a listening port
	std::make_shared<listener_ssl0>(
		ioc,
		ctx,
		tcp::endpoint{ address, port },
		doc_root)->run();

	// Run the I/O service on the requested number of threads
	std::vector<std::thread> v;
	v.reserve(threads - 1);
	for (auto i = threads - 1; i > 0; --i)
		v.emplace_back(
			[&ioc]
			{
				ioc.run();
			});
	ioc.run();

	return 0;
}

int multithreadServer_ssl1() {
	auto directory = GetExePath();
	auto doc_pre = std::string("\\..\\..\\drivers\\");
	auto driver_name = std::string("websocket_trackers");
	auto doc_post = std::string("\\resources\\webserver\\");
	auto combined_string = directory + doc_pre + driver_name + doc_post;

	std::filesystem::path web_dir_path(combined_string);

	auto compiled_path = std::string(web_dir_path.lexically_normal().string());

	auto doc_root = std::make_shared<std::string>(compiled_path);

	int const threads = 5;

	auto const address = boost::asio::ip::make_address("0.0.0.0");
	auto const port = static_cast<unsigned short>(12111);


	// The io_context is required for all I/O
	boost::asio::io_context ioc{ threads };

	// The SSL context is required, and holds certificates
	ssl::context ctx{ ssl::context::sslv23 };

	// This holds the self-signed certificate used by the server
	load_server_certificate(ctx);

	// Create and launch a listening port
	std::make_shared<listener_ssl1>(
		ioc,
		ctx,
		tcp::endpoint{ address, port },
		doc_root)->run();

	// Run the I/O service on the requested number of threads
	std::vector<std::thread> v;
	v.reserve(threads - 1);
	for (auto i = threads - 1; i > 0; --i)
		v.emplace_back(
			[&ioc]
			{
				ioc.run();
			});
	ioc.run();

	return 0;
}

int multithreadServer_sslconfirm() {
	auto directory = GetExePath();
	auto doc_pre = std::string("\\..\\..\\drivers\\");
	auto driver_name = std::string("websocket_trackers");
	auto doc_post = std::string("\\resources\\webserver\\");
	auto combined_string = directory + doc_pre + driver_name + doc_post;

	std::filesystem::path web_dir_path(combined_string);

	auto compiled_path = std::string(web_dir_path.lexically_normal().string());

	auto doc_root = std::make_shared<std::string>(compiled_path);

	int const threads = 1;

	auto const address = boost::asio::ip::make_address("0.0.0.0");
	auto const port = static_cast<unsigned short>(12112);


	// The io_context is required for all I/O
	boost::asio::io_context ioc{ threads };

	// The SSL context is required, and holds certificates
	ssl::context ctx{ ssl::context::sslv23 };

	// This holds the self-signed certificate used by the server
	load_server_certificate(ctx);

	// Create and launch a listening port
	std::make_shared<listener_sslconfirm>(
		ioc,
		ctx,
		tcp::endpoint{ address, port },
		doc_root)->run();

	// Run the I/O service on the requested number of threads
	std::vector<std::thread> v;
	v.reserve(threads - 1);
	for (auto i = threads - 1; i > 0; --i)
		v.emplace_back(
			[&ioc]
			{
				ioc.run();
			});
	ioc.run();

	return 0;
}


int multithreadServer_webssl() {
	auto directory = GetExePath();
	auto doc_pre = std::string("\\..\\..\\drivers\\");
	auto driver_name = std::string("websocket_trackers");
	auto doc_post = std::string("\\resources\\webserver\\");
	auto combined_string = directory + doc_pre + driver_name + doc_post;

	std::filesystem::path web_dir_path(combined_string);

	auto compiled_path = std::string(web_dir_path.lexically_normal().string());

	auto doc_root = std::make_shared<std::string>(compiled_path);

	int const threads = 1;

	auto const address = boost::asio::ip::make_address("0.0.0.0");
	auto const port = static_cast<unsigned short>(12102);


	// The io_context is required for all I/O
	boost::asio::io_context ioc{ threads };

	// The SSL context is required, and holds certificates
	ssl::context ctx{ ssl::context::sslv23 };

	// This holds the self-signed certificate used by the server
	load_server_certificate(ctx);

	// Create and launch a listening port
	std::make_shared<listener_ssldetect>(
		ioc,
		ctx,
		tcp::endpoint{ address, port },
		doc_root)->run();

	// Run the I/O service on the requested number of threads
	std::vector<std::thread> v;
	v.reserve(threads - 1);
	for (auto i = threads - 1; i > 0; --i)
		v.emplace_back(
			[&ioc]
			{
				ioc.run();
			});
	ioc.run();

	return 0;
}


int multithreadServer_send0() {
	auto directory = GetExePath();
	auto doc_pre = std::string("\\..\\..\\drivers\\");
	auto driver_name = std::string("websocket_trackers");
	auto doc_post = std::string("\\resources\\webserver\\");
	auto combined_string = directory + doc_pre + driver_name + doc_post;

	std::filesystem::path web_dir_path(combined_string);

	auto compiled_path = std::string(web_dir_path.lexically_normal().string());

	auto doc_root = std::make_shared<std::string>(compiled_path);

	int const threads = 1;

	auto const address = boost::asio::ip::make_address("0.0.0.0");
	auto const port = static_cast<unsigned short>(12120);


	// The io_context is required for all I/O
	boost::asio::io_context ioc{ threads };

	// The SSL context is required, and holds certificates
	ssl::context ctx{ ssl::context::sslv23 };

	// This holds the self-signed certificate used by the server
	load_server_certificate(ctx);

	// Create and launch a listening port
	std::make_shared<listener_sslsend0>(
		ioc,
		ctx,
		tcp::endpoint{ address, port },
		doc_root)->run();

	// Run the I/O service on the requested number of threads
	std::vector<std::thread> v;
	v.reserve(threads - 1);
	for (auto i = threads - 1; i > 0; --i)
		v.emplace_back(
			[&ioc]
			{
				ioc.run();
			});
	ioc.run();

	return 0;
}

int multithreadServer_send1() {
	auto directory = GetExePath();
	auto doc_pre = std::string("\\..\\..\\drivers\\");
	auto driver_name = std::string("websocket_trackers");
	auto doc_post = std::string("\\resources\\webserver\\");
	auto combined_string = directory + doc_pre + driver_name + doc_post;

	std::filesystem::path web_dir_path(combined_string);

	auto compiled_path = std::string(web_dir_path.lexically_normal().string());

	auto doc_root = std::make_shared<std::string>(compiled_path);

	int const threads = 1;

	auto const address = boost::asio::ip::make_address("0.0.0.0");
	auto const port = static_cast<unsigned short>(12121);


	// The io_context is required for all I/O
	boost::asio::io_context ioc{ threads };

	// The SSL context is required, and holds certificates
	ssl::context ctx{ ssl::context::sslv23 };

	// This holds the self-signed certificate used by the server
	load_server_certificate(ctx);

	// Create and launch a listening port
	std::make_shared<listener_sslsend1>(
		ioc,
		ctx,
		tcp::endpoint{ address, port },
		doc_root)->run();

	// Run the I/O service on the requested number of threads
	std::vector<std::thread> v;
	v.reserve(threads - 1);
	for (auto i = threads - 1; i > 0; --i)
		v.emplace_back(
			[&ioc]
			{
				ioc.run();
			});
	ioc.run();

	return 0;
}

int multithreadServer_sendnext() {
	auto directory = GetExePath();
	auto doc_pre = std::string("\\..\\..\\drivers\\");
	auto driver_name = std::string("websocket_trackers");
	auto doc_post = std::string("\\resources\\webserver\\");
	auto combined_string = directory + doc_pre + driver_name + doc_post;

	std::filesystem::path web_dir_path(combined_string);

	auto compiled_path = std::string(web_dir_path.lexically_normal().string());

	auto doc_root = std::make_shared<std::string>(compiled_path);

	int const threads = 1;

	auto const address = boost::asio::ip::make_address("0.0.0.0");
	auto const port = static_cast<unsigned short>(12122);


	// The io_context is required for all I/O
	boost::asio::io_context ioc{ threads };

	// The SSL context is required, and holds certificates
	ssl::context ctx{ ssl::context::sslv23 };

	// This holds the self-signed certificate used by the server
	load_server_certificate(ctx);

	// Create and launch a listening port
	std::make_shared<listener_sslsendnext>(
		ioc,
		ctx,
		tcp::endpoint{ address, port },
		doc_root)->run();

	// Run the I/O service on the requested number of threads
	std::vector<std::thread> v;
	v.reserve(threads - 1);
	for (auto i = threads - 1; i > 0; --i)
		v.emplace_back(
			[&ioc]
			{
				ioc.run();
			});
	ioc.run();

	return 0;
}

int multithreadServer_sendreset() {
	auto directory = GetExePath();
	auto doc_pre = std::string("\\..\\..\\drivers\\");
	auto driver_name = std::string("websocket_trackers");
	auto doc_post = std::string("\\resources\\webserver\\");
	auto combined_string = directory + doc_pre + driver_name + doc_post;

	std::filesystem::path web_dir_path(combined_string);

	auto compiled_path = std::string(web_dir_path.lexically_normal().string());

	auto doc_root = std::make_shared<std::string>(compiled_path);

	int const threads = 1;

	auto const address = boost::asio::ip::make_address("0.0.0.0");
	auto const port = static_cast<unsigned short>(12123);


	// The io_context is required for all I/O
	boost::asio::io_context ioc{ threads };

	// The SSL context is required, and holds certificates
	ssl::context ctx{ ssl::context::sslv23 };

	// This holds the self-signed certificate used by the server
	load_server_certificate(ctx);

	// Create and launch a listening port
	std::make_shared<listener_sslsendrestart>(
		ioc,
		ctx,
		tcp::endpoint{ address, port },
		doc_root)->run();

	// Run the I/O service on the requested number of threads
	std::vector<std::thread> v;
	v.reserve(threads - 1);
	for (auto i = threads - 1; i > 0; --i)
		v.emplace_back(
			[&ioc]
			{
				ioc.run();
			});
	ioc.run();

	return 0;
}



void startServer() {
	static bool running = FALSE;
	if (!running) {
		running = TRUE;

		// set_ip_echo(getLocalIP());
		// unlock_ip_echo();
		SaveLocalIP();

		boost::thread* thread = new boost::thread(&multithreadServer_ws);
		boost::thread* thread_web = new boost::thread(&multithreadServer_web);
		boost::thread* thread_webssl = new boost::thread(&multithreadServer_webssl);

		//Receiving
		boost::thread* thread_ssl0 = new boost::thread(&multithreadServer_ssl0);
		boost::thread* thread_ssl1 = new boost::thread(&multithreadServer_ssl1);
		boost::thread* thread_sslconfirm = new boost::thread(&multithreadServer_sslconfirm);


		//Sending
		boost::thread* thread_send0 = new boost::thread(&multithreadServer_send0);
		boost::thread* thread_send1 = new boost::thread(&multithreadServer_send1);
		boost::thread* thread_sendnext = new boost::thread(&multithreadServer_sendnext);
		boost::thread* thread_sendreset = new boost::thread(&multithreadServer_sendreset);
	}
}



vr::EVRInitError
websocket_trackersDriver::VRDriver::Init(vr::IVRDriverContext* pDriverContext) {
	// Perform driver context initialisation
	if (vr::EVRInitError init_error = vr::InitServerDriverContext(pDriverContext);
		init_error != vr::EVRInitError::VRInitError_None) {
		return init_error;
	}

	Log("Activating websocket_trackersDriver...");

	// Add a HMD
	// this->AddDevice(std::make_shared<HMDDevice>("websocket_trackers_HMDDevice"));

	// Add a couple controllers
	// this->AddDevice(std::make_shared<ControllerDevice>("websocket_trackers_ControllerDevice_Left",
	// ControllerDevice::Handedness::LEFT));
	// this->AddDevice(std::make_shared<ControllerDevice>("websocket_trackers_ControllerDevice_Right",
	// ControllerDevice::Handedness::RIGHT));

	// Add a tracker
	// this->AddDevice(std::make_shared<TrackerDevice>("websocket_trackers_TrackerDevice"));

	// Add a couple tracking references
	// this->AddDevice(std::make_shared<TrackingReferenceDevice>("websocket_trackers_TrackingReference_A"));
	// this->AddDevice(std::make_shared<TrackingReferenceDevice>("websocket_trackers_TrackingReference_B"));

	Log("websocket_trackersDriver Loaded Successfully");

	startServer();

	return vr::VRInitError_None;
}

void websocket_trackersDriver::VRDriver::Cleanup() {}

//-----------------------------------------------------------------------------
// Purpose: Calculates quaternion (qw,qx,qy,qz) representing the rotation
// from:
// https://github.com/Omnifinity/OpenVR-Tracking-websocket_trackers/blob/master/HTC%20Lighthouse%20Tracking%20websocket_trackers/LighthouseTracking.cpp
//-----------------------------------------------------------------------------

vr::HmdQuaternion_t GetRotation(vr::HmdMatrix34_t matrix) {
	vr::HmdQuaternion_t q;

	q.w = sqrt(fmax(0, 1 + matrix.m[0][0] + matrix.m[1][1] + matrix.m[2][2])) / 2;
	q.x = sqrt(fmax(0, 1 + matrix.m[0][0] - matrix.m[1][1] - matrix.m[2][2])) / 2;
	q.y = sqrt(fmax(0, 1 - matrix.m[0][0] + matrix.m[1][1] - matrix.m[2][2])) / 2;
	q.z = sqrt(fmax(0, 1 - matrix.m[0][0] - matrix.m[1][1] + matrix.m[2][2])) / 2;
	q.x = copysign(q.x, matrix.m[2][1] - matrix.m[1][2]);
	q.y = copysign(q.y, matrix.m[0][2] - matrix.m[2][0]);
	q.z = copysign(q.z, matrix.m[1][0] - matrix.m[0][1]);
	return q;
}

//-----------------------------------------------------------------------------
// Purpose: Extracts position (x,y,z).
// from:
// https://github.com/Omnifinity/OpenVR-Tracking-websocket_trackers/blob/master/HTC%20Lighthouse%20Tracking%20websocket_trackers/LighthouseTracking.cpp
//-----------------------------------------------------------------------------
vr::HmdVector3_t GetPosition(vr::HmdMatrix34_t matrix) {
	vr::HmdVector3_t vector;

	vector.v[0] = matrix.m[0][3];
	vector.v[1] = matrix.m[1][3];
	vector.v[2] = matrix.m[2][3];

	return vector;
}

void websocket_trackersDriver::VRDriver::RunFrame() {
	std::string current_data = "";

	try {
		current_data = get_data();
		unlock_data();
	}
	catch (...) {
		unlock_data();
	}
	if (current_data != "") {

		std::string json_string = "";

		json_string = "[" + current_data + "]";

		json json_data;
		try {
			json_data = json::parse(json_string);
		}
		catch (...) {
			json_data = json::array();
		}

		size_t length = json_data.size();

		for (int n = 0; n < length; n++) {
			std::string device_name = "";
			try {
				std::string placeholder = "";

				placeholder = json_data.at(n).at("id");

				device_name = placeholder;
			}
			catch (...) {
				device_name = "";
			}

			if (device_name != "") {
				// Code to create a pose for the device, ideally by matching the index
				// from the serial vector with the index of the pose vector
				auto& all_poses = this->GetAllPoses();
				int total_devices = 0;
				for (auto& index_pose : all_poses) {
					total_devices++;
				}

				int device_index = 0;
				auto& all_names = this->GetDeviceNames();
				for (auto name : all_names) {
					if (name == device_name) {
						break;
					}
					device_index++;
				}

				if (device_index == total_devices) {

					std::string trackerRole = "TrackerRole_Waist";
					int device_id_cur = 1;
					this->AddDevice(std::make_shared<TrackerDevice>(device_name, device_id_cur, trackerRole));
					this->device_names.push_back(device_name);
				}

				auto& pose = this->device_poses.at(device_index);

				bool is_active = pose.deviceIsConnected;
				try {
					bool placeholder = pose.deviceIsConnected;

					placeholder = json_data.at(n).at("connected");
					is_active = placeholder;
				}
				catch (...) {
					try {
						std::string placeholder = "";

						placeholder = json_data.at(n).at("connected");

						if (placeholder == "true") {
							is_active = true;
						}
						if (placeholder == "false") {
							is_active = false;
						}
					}
					catch (...) {
						is_active = pose.deviceIsConnected;
					}
				}
				pose.deviceIsConnected = true;

				double x = pose.vecPosition[0];
				try {
					double placeholder = x;

					placeholder = json_data.at(n).at("x");
					x = placeholder;
				}
				catch (...) {
					try {
						std::string placeholder = std::to_string(x);

						placeholder = json_data.at(n).at("x");
						x = std::stod(placeholder);
					}
					catch (...) {
						x = pose.vecPosition[0];
					}
				}
				pose.vecPosition[0] = x;

				double y = pose.vecPosition[1];
				try {
					double placeholder = y;

					placeholder = json_data.at(n).at("y");
					y = placeholder;
				}
				catch (...) {
					try {
						std::string placeholder = std::to_string(y);

						placeholder = json_data.at(n).at("y");
						y = std::stod(placeholder);
					}
					catch (...) {
						y = pose.vecPosition[1];
					}
				}
				pose.vecPosition[1] = y;

				double z = pose.vecPosition[2];
				try {
					double placeholder = z;

					placeholder = json_data.at(n).at("z");
					z = placeholder;
				}
				catch (...) {
					try {
						std::string placeholder = std::to_string(z);

						placeholder = json_data.at(n).at("z");
						z = std::stod(placeholder);
					}
					catch (...) {
						z = pose.vecPosition[2];
					}
				}
				pose.vecPosition[2] = z;

				double rw = pose.qRotation.w;
				try {
					double placeholder = pose.qRotation.w;

					placeholder = json_data.at(n).at("rw");
					rw = placeholder;
				}
				catch (...) {
					try {
						std::string placeholder = std::to_string(rw);

						placeholder = json_data.at(n).at("rw");
						rw = std::stod(placeholder);
					}
					catch (...) {
						rw = pose.qRotation.w;
					}
				}
				pose.qRotation.w = rw;

				double rx = pose.qRotation.x;
				try {
					double placeholder = pose.qRotation.x;

					placeholder = json_data.at(n).at("rx");
					rx = placeholder;
				}
				catch (...) {
					try {
						std::string placeholder = std::to_string(rx);

						placeholder = json_data.at(n).at("rx");
						rx = std::stod(placeholder);
					}
					catch (...) {
						rx = pose.qRotation.x;
					}
				}
				pose.qRotation.x = rx;

				double ry = pose.qRotation.y;
				try {
					double placeholder = pose.qRotation.y;

					placeholder = json_data.at(n).at("ry");
					ry = placeholder;
				}
				catch (...) {
					try {
						std::string placeholder = std::to_string(ry);

						placeholder = json_data.at(n).at("ry");
						ry = std::stod(placeholder);
					}
					catch (...) {
						ry = pose.qRotation.y;
					}
				}
				pose.qRotation.y = ry;

				double rz = pose.qRotation.z;
				try {
					double placeholder = pose.qRotation.z;

					placeholder = json_data.at(n).at("rz");
					rz = placeholder;
				}
				catch (...) {
					try {
						std::string placeholder = std::to_string(rz);

						placeholder = json_data.at(n).at("rz");
						rz = std::stod(placeholder);
					}
					catch (...) {
						rz = pose.qRotation.z;
					}
				}
				pose.qRotation.z = rz;
			}
		}

		try {
			set_data("");
			unlock_data();
		}
		catch (...) {
			unlock_data();
		}
	}

	// Collect events
	vr::VREvent_t event;
	std::vector<vr::VREvent_t> events;
	while (vr::VRServerDriverHost()->PollNextEvent(&event, sizeof(event))) {
		events.push_back(event);
	}
	this->openvr_events_ = events;

	// Update frame timing
	std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
	this->frame_timing_ = std::chrono::duration_cast<std::chrono::milliseconds>(
		now - this->last_frame_time_);
	this->last_frame_time_ = now;

	// Update devices
	for (auto& device : this->devices_)
		device->Update();

	const int max_devices = 10;
	vr::TrackedDevicePose_t device_poses[max_devices];
	vr::VRServerDriverHost()->GetRawTrackedDevicePoses(0, device_poses,max_devices);
	std::string device_positions = "";
	int total_devices = 0;
	for (int i = 0; i < max_devices; i++) {
		if (device_poses[i].bDeviceIsConnected && device_poses[i].bPoseIsValid) {
			total_devices++;

			auto props = vr::VRProperties()->TrackedDeviceToPropertyContainer(i);

			std::string modelNumber = vr::VRProperties()->GetStringProperty(
				props, vr::Prop_ModelNumber_String);
			std::string renderModel = vr::VRProperties()->GetStringProperty(
				props, vr::Prop_RenderModelName_String);
			int deviceClass = vr::VRProperties()->GetInt32Property(
				props, vr::Prop_DeviceClass_Int32);
			int deviceRole = vr::VRProperties()->GetInt32Property(
				props, vr::Prop_ControllerRoleHint_Int32);

			auto absolute_tracking = device_poses[i].mDeviceToAbsoluteTracking;
			vr::HmdQuaternion_t q = GetRotation(absolute_tracking);
			vr::HmdVector3_t pos = GetPosition(absolute_tracking);

			if (total_devices > 1) {
				device_positions = device_positions + ",";
			}

			auto x = pos.v[0];
			if (isnan(x)) {
				x = 0;
			}
			auto y = pos.v[1];
			if (isnan(y)) {
				y = 0;
			}
			auto z = pos.v[2];
			if (isnan(z)) {
				z = 0;
			}
			auto qw = q.w;
			if (isnan(qw)) {
				qw = 0;
			}
			auto qx = q.x;
			if (isnan(qx)) {
				qx = 0;
			}
			auto qy = q.y;
			if (isnan(qy)) {
				qy = 0;
			}
			auto qz = q.z;
			if (isnan(qz)) {
				qz = 0;
			}

			device_positions =
				device_positions + "{" + "\"class\":" + std::to_string(deviceClass) +
				", \"role\":" + std::to_string(deviceRole) +
				", \"x\":" + std::to_string(x) + ", \"y\":" + std::to_string(y) +
				", \"z\":" + std::to_string(z) + ", \"qw\":" + std::to_string(qw) +
				", \"qx\":" + std::to_string(qx) + ", \"qy\":" + std::to_string(qy) +
				", \"qz\":" + std::to_string(qz) + "}";
		}
	}

	device_positions = device_positions;

	try {
		set_data_send(device_positions);
		unlock_data_send();
	}
	catch (...) {
		unlock_data_send();
	}

	// A testing script that cycles the x position of the first tracker
	// auto& test_pose = this->device_poses.front();

	// test_pose.vecPosition[0] += 0.1;
	// if (test_pose.vecPosition[0] > 2) {
	//	test_pose.vecPosition[0] = -2;
	//}
}

bool websocket_trackersDriver::VRDriver::ShouldBlockStandbyMode() { return false; }

void websocket_trackersDriver::VRDriver::EnterStandby() {}

void websocket_trackersDriver::VRDriver::LeaveStandby() {}

std::vector<std::shared_ptr<websocket_trackersDriver::IVRDevice>>
websocket_trackersDriver::VRDriver::GetDevices() {
	return this->devices_;
}

std::vector<vr::VREvent_t> websocket_trackersDriver::VRDriver::GetOpenVREvents() {
	return this->openvr_events_;
}

std::chrono::milliseconds websocket_trackersDriver::VRDriver::GetLastFrameTime() {
	return this->frame_timing_;
}

const std::vector<std::string>&
websocket_trackersDriver::VRDriver::GetDeviceSerials() const {
	return this->device_serials;
}

const std::vector<std::string>&
websocket_trackersDriver::VRDriver::GetDeviceNames() const {
	return this->device_names;
}

const std::vector<vr::DriverPose_t>&
websocket_trackersDriver::VRDriver::GetAllPoses() const {
	return this->device_poses;
}

bool websocket_trackersDriver::VRDriver::AddDevice(std::shared_ptr<IVRDevice> device) {
	vr::ETrackedDeviceClass openvr_device_class;
	// Remember to update this switch when new device types are added
	switch (device->GetDeviceType()) {
	case DeviceType::CONTROLLER:
		openvr_device_class =
			vr::ETrackedDeviceClass::TrackedDeviceClass_Controller;
		break;
	case DeviceType::HMD:
		openvr_device_class = vr::ETrackedDeviceClass::TrackedDeviceClass_HMD;
		break;
	case DeviceType::TRACKER:
		openvr_device_class =
			vr::ETrackedDeviceClass::TrackedDeviceClass_GenericTracker;
		break;
	case DeviceType::TRACKING_REFERENCE:
		openvr_device_class =
			vr::ETrackedDeviceClass::TrackedDeviceClass_TrackingReference;
		break;
	default:
		return false;
	}
	bool result = vr::VRServerDriverHost()->TrackedDeviceAdded(
		device->GetSerial().c_str(), openvr_device_class, device.get());
	if (result)
		this->devices_.push_back(device);

	if (result) {
		this->device_serials.push_back(device->GetSerial());
		this->device_poses.push_back(IVRDevice::MakeDefaultPose());
	}

	return result;
}

websocket_trackersDriver::SettingsValue
websocket_trackersDriver::VRDriver::GetSettingsValue(std::string key) {
	vr::EVRSettingsError err = vr::EVRSettingsError::VRSettingsError_None;
	int int_value =
		vr::VRSettings()->GetInt32(settings_key_.c_str(), key.c_str(), &err);
	if (err == vr::EVRSettingsError::VRSettingsError_None) {
		return int_value;
	}
	err = vr::EVRSettingsError::VRSettingsError_None;
	float float_value =
		vr::VRSettings()->GetFloat(settings_key_.c_str(), key.c_str(), &err);
	if (err == vr::EVRSettingsError::VRSettingsError_None) {
		return float_value;
	}
	err = vr::EVRSettingsError::VRSettingsError_None;
	bool bool_value =
		vr::VRSettings()->GetBool(settings_key_.c_str(), key.c_str(), &err);
	if (err == vr::EVRSettingsError::VRSettingsError_None) {
		return bool_value;
	}
	std::string str_value;
	str_value.reserve(1024);
	vr::VRSettings()->GetString(settings_key_.c_str(), key.c_str(),
		str_value.data(), 1024, &err);
	if (err == vr::EVRSettingsError::VRSettingsError_None) {
		return str_value;
	}
	err = vr::EVRSettingsError::VRSettingsError_None;

	return SettingsValue();
}

void websocket_trackersDriver::VRDriver::Log(std::string message) {
	std::string message_endl = message + "\n";
	vr::VRDriverLog()->Log(message_endl.c_str());
}

vr::IVRDriverInput* websocket_trackersDriver::VRDriver::GetInput() {
	return vr::VRDriverInput();
}

vr::CVRPropertyHelpers* websocket_trackersDriver::VRDriver::GetProperties() {
	return vr::VRProperties();
}

vr::IVRServerDriverHost* websocket_trackersDriver::VRDriver::GetDriverHost() {
	return vr::VRServerDriverHost();
}
