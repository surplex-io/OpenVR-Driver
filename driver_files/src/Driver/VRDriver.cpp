#include "VRDriver.hpp"
#include <Driver/HMDDevice.hpp>
#include <Driver/TrackerDevice.hpp>
#include <Driver/ControllerDevice.hpp>
#include <Driver/TrackingReferenceDevice.hpp>

// -----------------------
#include <boost/thread.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/coroutine.hpp>
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


#include <mutex>

static std::mutex globalVariableProtector;
std::string raw_data = "";

std::string __fastcall get_data()  // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector);
	return (raw_data);
}

void __fastcall unlock_data()  // retrieves the value of globalVariable
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

std::string __fastcall get_data_send()  // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_send);
	return (raw_data_send);
}

void __fastcall unlock_data_send()  // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> unlock(globalVariableProtector_send);
}

void __fastcall set_data_send(std::string set) // sets the value of globalVariable 
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_send);
	raw_data_send = set;
}



static std::mutex globalVariableProtector_echo;
std::string raw_data_echo = "";

std::string __fastcall get_data_echo()  // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_echo);
	return (raw_data_echo);
}

void __fastcall unlock_data_echo()  // retrieves the value of globalVariable
{
	std::lock_guard<std::mutex> unlock(globalVariableProtector_echo);
}

void __fastcall set_data_echo(std::string set) // sets the value of globalVariable 
{
	std::lock_guard<std::mutex> lock(globalVariableProtector_echo);
	raw_data_echo = set;
}


//------------------------------------------------------------------------------

using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>
namespace websocket = boost::beast::websocket;  // from <boost/beast/websocket.hpp>

//------------------------------------------------------------------------------
std::string ReplaceAll(std::string str, const std::string& from, const std::string& to) {
	size_t start_pos = 0;
	while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
	}
	return str;
}


// Report a failure
void fail(boost::system::error_code ec, char const* what)
{
	std::cerr << what << ": " << ec.message() << "\n";
}

// Echoes back all received WebSocket messages
class session
	: public boost::asio::coroutine
	, public std::enable_shared_from_this<session>
{
	websocket::stream<tcp::socket> ws_;
	boost::asio::strand<boost::asio::io_context::executor_type> strand_;
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
		loop({}, 0);
	}

#include <boost/asio/yield.hpp>

	void
		loop(
			boost::system::error_code ec,
			std::size_t bytes_transferred)
	{
		boost::ignore_unused(bytes_transferred);
		reenter(*this)
		{
			// Accept the websocket handshake
			yield ws_.async_accept(
				boost::asio::bind_executor(
					strand_,
					std::bind(
						&session::loop,
						shared_from_this(),
						std::placeholders::_1,
						0)));
			if (ec)
				return fail(ec, "accept");

			for (;;)
			{
				// Read a message into our buffer
				yield ws_.async_read(
					buffer_,
					boost::asio::bind_executor(
						strand_,
						std::bind(
							&session::loop,
							shared_from_this(),
							std::placeholders::_1,
							std::placeholders::_2)));
				if (ec == websocket::error::closed)
				{
					// This indicates that the session was closed
					return;
				}
				if (ec)
					fail(ec, "read");
				/*
				// Echo the message
				ws_.text(ws_.got_text());
				yield ws_.async_write(
					buffer_.data(),
					boost::asio::bind_executor(
						strand_,
						std::bind(
							&session::loop,
							shared_from_this(),
							std::placeholders::_1,
							std::placeholders::_2)));
				*/
				try {



					std::string current_data = get_data();
					unlock_data();

					std::string current_echo = get_data_echo();
					unlock_data_echo();
					//ws_.write(boost::asio::buffer(current_data));

					//This code updates current_data with the message
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


						std::string new_echo;
						if (current_echo == "") {
							new_echo = message;
						}
						else {
							new_echo = current_echo + "," + message;
						}

						new_echo = ReplaceAll(message, "\"", "\\\"");

						set_data_echo(new_echo);
						unlock_data();
					}

					std::string reply_data = get_data_send();
					unlock_data_send();


					std::string reply_echo = get_data_echo();
					unlock_data_echo();

					std::string reply_message = "{\"vr_trackers\": [" + reply_data + "], \"echo\": \"" + reply_echo + "\"}";
					ws_.write(boost::asio::buffer(reply_message));
				}
				catch (...) {
					unlock_data();
					unlock_data_send();
					unlock_data_echo();
					return fail(ec, "write");
				}
				if (ec)
					return fail(ec, "write");

				// Clear the buffer
				buffer_.consume(buffer_.size());
			}
		}
	}

#include <boost/asio/unyield.hpp>
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the sessions
class listener
	: public boost::asio::coroutine
	, public std::enable_shared_from_this<listener>
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
		loop();
	}

#include <boost/asio/yield.hpp>

	void
		loop(boost::system::error_code ec = {})
	{

		reenter(*this)
		{
			for (;;)
			{
				yield acceptor_.async_accept(
					socket_,
					std::bind(
						&listener::loop,
						shared_from_this(),
						std::placeholders::_1));
				if (ec)
				{
					fail(ec, "accept");
				}
				else
				{
					// Create the session and run it
					std::make_shared<session>(std::move(socket_))->run();
				}
			}
		}
	}

#include <boost/asio/unyield.hpp>
};

//------------------------------------------------------------------------------
#include <boost/asio.hpp>
namespace ip = boost::asio::ip;

std::string getLocalIP()
{
	boost::asio::io_service ioService;
	ip::tcp::resolver resolver(ioService);

	return resolver.resolve(ip::host_name(), "")->endpoint().address().to_string();
}
//------------------------------------------------------------------------------

int multithreadServer() {
	boost::asio::io_context ioc{ 1 };
	auto const address = boost::asio::ip::make_address("127.0.0.1");
	//auto const address = boost::asio::ip::make_address(getLocalIP());
	auto const port = static_cast<unsigned short>(8082);
	std::make_shared<listener>(ioc, tcp::endpoint{ address, port })->run();
	ioc.run();
	return 0;
}

void startServer() {
	static bool running = FALSE;
	if (!running) {
		running = TRUE;
		boost::thread* thread = new boost::thread(&multithreadServer);
	}
}
// -----------------------
#include <nlohmann/json.hpp>
using json = nlohmann::json;
// -----------------------



vr::EVRInitError ExampleDriver::VRDriver::Init(vr::IVRDriverContext* pDriverContext)
{
	// Perform driver context initialisation
	if (vr::EVRInitError init_error = vr::InitServerDriverContext(pDriverContext); init_error != vr::EVRInitError::VRInitError_None) {
		return init_error;
	}

	Log("Activating ExampleDriver...");

	// Add a HMD
	//this->AddDevice(std::make_shared<HMDDevice>("Example_HMDDevice"));

	// Add a couple controllers
	//this->AddDevice(std::make_shared<ControllerDevice>("Example_ControllerDevice_Left", ControllerDevice::Handedness::LEFT));
	//this->AddDevice(std::make_shared<ControllerDevice>("Example_ControllerDevice_Right", ControllerDevice::Handedness::RIGHT));

	// Add a tracker
	//this->AddDevice(std::make_shared<TrackerDevice>("Example_TrackerDevice"));

	// Add a couple tracking references
   // this->AddDevice(std::make_shared<TrackingReferenceDevice>("Example_TrackingReference_A"));
   // this->AddDevice(std::make_shared<TrackingReferenceDevice>("Example_TrackingReference_B"));

	Log("ExampleDriver Loaded Successfully");

	startServer();

	return vr::VRInitError_None;
}



void ExampleDriver::VRDriver::Cleanup()
{
}

//-----------------------------------------------------------------------------
// Purpose: Calculates quaternion (qw,qx,qy,qz) representing the rotation
// from: https://github.com/Omnifinity/OpenVR-Tracking-Example/blob/master/HTC%20Lighthouse%20Tracking%20Example/LighthouseTracking.cpp
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
// from: https://github.com/Omnifinity/OpenVR-Tracking-Example/blob/master/HTC%20Lighthouse%20Tracking%20Example/LighthouseTracking.cpp
//-----------------------------------------------------------------------------
vr::HmdVector3_t GetPosition(vr::HmdMatrix34_t matrix) {
	vr::HmdVector3_t vector;

	vector.v[0] = matrix.m[0][3];
	vector.v[1] = matrix.m[1][3];
	vector.v[2] = matrix.m[2][3];

	return vector;
}



void ExampleDriver::VRDriver::RunFrame()
{
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
				//Code to create a pose for the device, ideally by matching the index from the serial vector with the index of the pose vector
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
					this->AddDevice(std::make_shared<TrackerDevice>(device_name));
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
				pose.deviceIsConnected = is_active;



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
	while (vr::VRServerDriverHost()->PollNextEvent(&event, sizeof(event)))
	{
		events.push_back(event);
	}
	this->openvr_events_ = events;

	// Update frame timing
	std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
	this->frame_timing_ = std::chrono::duration_cast<std::chrono::milliseconds>(now - this->last_frame_time_);
	this->last_frame_time_ = now;

	// Update devices
	for (auto& device : this->devices_)
		device->Update();


	const int max_devices = 10;
	vr::TrackedDevicePose_t device_poses[max_devices];
	vr::VRServerDriverHost()->GetRawTrackedDevicePoses(0, device_poses, max_devices);
	std::string device_positions = "";
	int total_devices = 0;
	for (int i = 0; i < max_devices; i++)
	{
		if (device_poses[i].bDeviceIsConnected && device_poses[i].bPoseIsValid) {
			total_devices++;

			auto props = vr::VRProperties()->TrackedDeviceToPropertyContainer(i);

			std::string modelNumber = vr::VRProperties()->GetStringProperty(props, vr::Prop_ModelNumber_String);
			std::string renderModel = vr::VRProperties()->GetStringProperty(props, vr::Prop_RenderModelName_String);
			int deviceClass = vr::VRProperties()->GetInt32Property(props, vr::Prop_DeviceClass_Int32);
			int deviceRole = vr::VRProperties()->GetInt32Property(props, vr::Prop_ControllerRoleHint_Int32);


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

			device_positions = device_positions + "{" +
				"\"class\":" + std::to_string(deviceClass) +
				", \"role\":" + std::to_string(deviceRole) +
				", \"x\":" + std::to_string(x) +
				", \"y\":" + std::to_string(y) +
				", \"z\":" + std::to_string(z) +
				", \"qw\":" + std::to_string(qw) +
				", \"qx\":" + std::to_string(qx) +
				", \"qy\":" + std::to_string(qy) +
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

	//A testing script that cycles the x position of the first tracker
	//auto& test_pose = this->device_poses.front();

	//test_pose.vecPosition[0] += 0.1;
	//if (test_pose.vecPosition[0] > 2) {
	//	test_pose.vecPosition[0] = -2;
	//}
}

bool ExampleDriver::VRDriver::ShouldBlockStandbyMode()
{
	return false;
}

void ExampleDriver::VRDriver::EnterStandby()
{
}

void ExampleDriver::VRDriver::LeaveStandby()
{
}

std::vector<std::shared_ptr<ExampleDriver::IVRDevice>> ExampleDriver::VRDriver::GetDevices()
{
	return this->devices_;
}

std::vector<vr::VREvent_t> ExampleDriver::VRDriver::GetOpenVREvents()
{
	return this->openvr_events_;
}

std::chrono::milliseconds ExampleDriver::VRDriver::GetLastFrameTime()
{
	return this->frame_timing_;
}



const std::vector<std::string>& ExampleDriver::VRDriver::GetDeviceSerials() const
{
	return this->device_serials;
}

const std::vector<std::string>& ExampleDriver::VRDriver::GetDeviceNames() const
{
	return this->device_names;
}



const std::vector<vr::DriverPose_t>& ExampleDriver::VRDriver::GetAllPoses() const
{
	return this->device_poses;
}


bool ExampleDriver::VRDriver::AddDevice(std::shared_ptr<IVRDevice> device)
{
	vr::ETrackedDeviceClass openvr_device_class;
	// Remember to update this switch when new device types are added
	switch (device->GetDeviceType()) {
	case DeviceType::CONTROLLER:
		openvr_device_class = vr::ETrackedDeviceClass::TrackedDeviceClass_Controller;
		break;
	case DeviceType::HMD:
		openvr_device_class = vr::ETrackedDeviceClass::TrackedDeviceClass_HMD;
		break;
	case DeviceType::TRACKER:
		openvr_device_class = vr::ETrackedDeviceClass::TrackedDeviceClass_GenericTracker;
		break;
	case DeviceType::TRACKING_REFERENCE:
		openvr_device_class = vr::ETrackedDeviceClass::TrackedDeviceClass_TrackingReference;
		break;
	default:
		return false;
	}
	bool result = vr::VRServerDriverHost()->TrackedDeviceAdded(device->GetSerial().c_str(), openvr_device_class, device.get());
	if (result)
		this->devices_.push_back(device);

	if (result) {
		this->device_serials.push_back(device->GetSerial());
		this->device_poses.push_back(IVRDevice::MakeDefaultPose());
	}

	return result;
}

ExampleDriver::SettingsValue ExampleDriver::VRDriver::GetSettingsValue(std::string key)
{
	vr::EVRSettingsError err = vr::EVRSettingsError::VRSettingsError_None;
	int int_value = vr::VRSettings()->GetInt32(settings_key_.c_str(), key.c_str(), &err);
	if (err == vr::EVRSettingsError::VRSettingsError_None) {
		return int_value;
	}
	err = vr::EVRSettingsError::VRSettingsError_None;
	float float_value = vr::VRSettings()->GetFloat(settings_key_.c_str(), key.c_str(), &err);
	if (err == vr::EVRSettingsError::VRSettingsError_None) {
		return float_value;
	}
	err = vr::EVRSettingsError::VRSettingsError_None;
	bool bool_value = vr::VRSettings()->GetBool(settings_key_.c_str(), key.c_str(), &err);
	if (err == vr::EVRSettingsError::VRSettingsError_None) {
		return bool_value;
	}
	std::string str_value;
	str_value.reserve(1024);
	vr::VRSettings()->GetString(settings_key_.c_str(), key.c_str(), str_value.data(), 1024, &err);
	if (err == vr::EVRSettingsError::VRSettingsError_None) {
		return str_value;
	}
	err = vr::EVRSettingsError::VRSettingsError_None;

	return SettingsValue();
}

void ExampleDriver::VRDriver::Log(std::string message)
{
	std::string message_endl = message + "\n";
	vr::VRDriverLog()->Log(message_endl.c_str());
}

vr::IVRDriverInput* ExampleDriver::VRDriver::GetInput()
{
	return vr::VRDriverInput();
}

vr::CVRPropertyHelpers* ExampleDriver::VRDriver::GetProperties()
{
	return vr::VRProperties();
}

vr::IVRServerDriverHost* ExampleDriver::VRDriver::GetDriverHost()
{
	return vr::VRServerDriverHost();
}
