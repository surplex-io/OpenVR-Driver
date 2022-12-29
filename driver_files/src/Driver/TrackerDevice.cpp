#include "TrackerDevice.hpp"
#include <Windows.h>

websocket_trackersDriver::TrackerDevice::TrackerDevice(std::string serial, int deviceId, std::string role):
    serial_(serial), 
    role_(role),
    deviceId_(deviceId)

{
    this->last_pose_ = MakeDefaultPose();
    this->isSetup = false;
}

std::string websocket_trackersDriver::TrackerDevice::GetSerial()
{
    return this->serial_;
}

void websocket_trackersDriver::TrackerDevice::Update()
{
	if (this->device_index_ == vr::k_unTrackedDeviceIndexInvalid)
		return;

	// Check if this device was asked to be identified
	auto events = GetDriver()->GetOpenVREvents();
	for (auto event : events) {
		// Note here, event.trackedDeviceIndex does not necissarily equal this->device_index_, not sure why, but the component handle will match so we can just use that instead
		//if (event.trackedDeviceIndex == this->device_index_) {
		if (event.eventType == vr::EVREventType::VREvent_Input_HapticVibration) {
			if (event.data.hapticVibration.componentHandle == this->haptic_component_) {
				this->did_vibrate_ = true;
			}
		}
		//}
	}

	// Check if we need to keep vibrating
	if (this->did_vibrate_) {
		this->vibrate_anim_state_ += (GetDriver()->GetLastFrameTime().count() / 1000.f);
		if (this->vibrate_anim_state_ > 1.0f) {
			this->did_vibrate_ = false;
			this->vibrate_anim_state_ = 0.0f;
		}
	}


	//Code to find the index of the device by serial
	int device_index = -1;
	int i = 0;
	bool working = false;
	auto active_serial = GetSerial();
	auto& all_serials = GetDriver()->GetDeviceSerials();
	for (auto index_serial : all_serials) {
		int is_match = active_serial.compare(index_serial);
		if (is_match == 0) {
			//Device index is how set to a number between 0 and all_serials.length
			device_index = i;
		}
		i++;
	}

	//Code to create a pose for the device, ideally by matching the index from the serial vector with the index of the pose vector
	//auto raw_pose = IVRDevice::MakeDefaultPose();
    auto pose = this->last_pose_;
	//auto& pose = this->last_pose_;
	if (device_index >= 0) {
		auto& all_poses = GetDriver()->GetAllPoses();
		int i = 0;
		for (auto index_pose : all_poses) {
			if (i == device_index) {
				//The pose should now be set to the pose located at device index in all_poses
				pose = index_pose;
				working = true;
			}
			i++;
		}
	}


    // Setup pose for this frame
    //auto pose = IVRDevice::MakeDefaultPose();

    // Find a HMD
    //auto devices = GetDriver()->GetDevices();
    //auto hmd = std::find_if(devices.begin(), devices.end(), [](const std::shared_ptr<IVRDevice>& device_ptr) {return device_ptr->GetDeviceType() == DeviceType::HMD; });
    //if (hmd != devices.end()) {
    //    // Found a HMD
    //    vr::DriverPose_t hmd_pose = (*hmd)->GetPose();

    //    // Here we setup some transforms so our controllers are offset from the headset by a small amount so we can see them
    //    linalg::vec<float, 3> hmd_position{ (float)hmd_pose.vecPosition[0], (float)hmd_pose.vecPosition[1], (float)hmd_pose.vecPosition[2] };
    //    linalg::vec<float, 4> hmd_rotation{ (float)hmd_pose.qRotation.x, (float)hmd_pose.qRotation.y, (float)hmd_pose.qRotation.z, (float)hmd_pose.qRotation.w };

    //    // Do shaking animation if haptic vibration was requested
    //    float controller_y = -0.35f + 0.01f * std::sinf(8 * 3.1415f * vibrate_anim_state_);

    //    linalg::vec<float, 3> hmd_pose_offset = { 0.f, controller_y, -0.5f };

    //    hmd_pose_offset = linalg::qrot(hmd_rotation, hmd_pose_offset);

    //    linalg::vec<float, 3> final_pose = hmd_pose_offset + hmd_position;

    //    pose.vecPosition[0] = final_pose.x;
    //    pose.vecPosition[1] = final_pose.y;
    //    pose.vecPosition[2] = final_pose.z;

    //    pose.qRotation.w = hmd_rotation.w;
    //    pose.qRotation.x = hmd_rotation.x;
    //    pose.qRotation.y = hmd_rotation.y;
    //    pose.qRotation.z = hmd_rotation.z;
    //}

	if (working) {
		//pose.vecPosition[1] = 3;
	}

    // Post pose
    GetDriver()->GetDriverHost()->TrackedDevicePoseUpdated(this->device_index_, pose, sizeof(vr::DriverPose_t));
    this->last_pose_ = pose;
}

DeviceType websocket_trackersDriver::TrackerDevice::GetDeviceType()
{
    return DeviceType::TRACKER;
}

vr::TrackedDeviceIndex_t websocket_trackersDriver::TrackerDevice::GetDeviceIndex()
{
    return this->device_index_;
}

vr::EVRInitError websocket_trackersDriver::TrackerDevice::Activate(uint32_t unObjectId)
{
    this->device_index_ = 10;

    GetDriver()->Log("Activating tracker " + this->serial_);

    // Get the properties handle
    auto props = GetDriver()->GetProperties()->TrackedDeviceToPropertyContainer(this->device_index_);

    // Set some universe ID (Must be 2 or higher)
    GetDriver()->GetProperties()->SetUint64Property(props, vr::Prop_CurrentUniverseId_Uint64, 3);
    
    // Set up a model "number" (not needed but good to have)
    GetDriver()->GetProperties()->SetStringProperty(props, vr::Prop_ModelNumber_String, "websocket_trackers_tracker");

    // Opt out of hand selection
    GetDriver()->GetProperties()->SetInt32Property(props, vr::Prop_ControllerRoleHint_Int32, vr::ETrackedControllerRole::TrackedControllerRole_OptOut);

    // Set up a render model path
    GetDriver()->GetProperties()->SetStringProperty(props, vr::Prop_RenderModelName_String, "{htc}/rendermodels/vr_tracker_vive_1_0");

    // Set controller profile
//    GetDriver()->GetProperties()->SetStringProperty(props, vr::Prop_InputProfilePath_String, "{websocket_trackers}/input/websocket_trackers_tracker_bindings.json");

    // Set the icon
    GetDriver()->GetProperties()->SetStringProperty(props, vr::Prop_NamedIconPathDeviceReady_String, "{websocket_trackers}/icons/tracker_ready.png");

    GetDriver()->GetProperties()->SetStringProperty(props, vr::Prop_NamedIconPathDeviceOff_String, "{websocket_trackers}/icons/tracker_not_ready.png");
    GetDriver()->GetProperties()->SetStringProperty(props, vr::Prop_NamedIconPathDeviceSearching_String, "{websocket_trackers}/icons/tracker_not_ready.png");
    GetDriver()->GetProperties()->SetStringProperty(props, vr::Prop_NamedIconPathDeviceSearchingAlert_String, "{websocket_trackers}/icons/tracker_not_ready.png");
    GetDriver()->GetProperties()->SetStringProperty(props, vr::Prop_NamedIconPathDeviceReadyAlert_String, "{websocket_trackers}/icons/tracker_not_ready.png");
    GetDriver()->GetProperties()->SetStringProperty(props, vr::Prop_NamedIconPathDeviceNotReady_String, "{websocket_trackers}/icons/tracker_not_ready.png");
    GetDriver()->GetProperties()->SetStringProperty(props, vr::Prop_NamedIconPathDeviceStandby_String, "{websocket_trackers}/icons/tracker_not_ready.png");
    GetDriver()->GetProperties()->SetStringProperty(props, vr::Prop_NamedIconPathDeviceAlertLow_String, "{websocket_trackers}/icons/tracker_not_ready.png");


    std::string rolehint = "vive_tracker";
    if (role_ == "TrackerRole_LeftFoot")
        rolehint = "vive_tracker_left_foot";
    else if (role_ == "TrackerRole_RightFoot")
        rolehint = "vive_tracker_right_foot";
    else if (role_ == "TrackerRole_Waist")
        rolehint = "vive_tracker_waist";

    GetDriver()->GetProperties()->SetStringProperty(props, vr::Prop_ControllerType_String, rolehint.c_str());

    vr::VRProperties()->SetInt32Property(props, vr::Prop_DeviceClass_Int32, vr::TrackedDeviceClass_GenericTracker);
    vr::VRProperties()->SetInt32Property(props, vr::Prop_ControllerHandSelectionPriority_Int32, -1);

    std::string l_registeredDevice("/devices/websocket_trackers/");
    l_registeredDevice.append(serial_);

    vr::VRSettings()->SetString(vr::k_pch_Trackers_Section, l_registeredDevice.c_str(), role_.c_str());


    return vr::EVRInitError::VRInitError_None;
}

void websocket_trackersDriver::TrackerDevice::Deactivate()
{
    this->device_index_ = vr::k_unTrackedDeviceIndexInvalid;
}

void websocket_trackersDriver::TrackerDevice::EnterStandby()
{
}

void* websocket_trackersDriver::TrackerDevice::GetComponent(const char* pchComponentNameAndVersion)
{
    return nullptr;
}

void websocket_trackersDriver::TrackerDevice::DebugRequest(const char* pchRequest, char* pchResponseBuffer, uint32_t unResponseBufferSize)
{
    if (unResponseBufferSize >= 1)
        pchResponseBuffer[0] = 0;
}

vr::DriverPose_t websocket_trackersDriver::TrackerDevice::GetPose()
{
    return last_pose_;
}


int websocket_trackersDriver::TrackerDevice::getDeviceId()
{
    return deviceId_;
}