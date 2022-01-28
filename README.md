# Websocket OpenVR Driver
The aim of this repository is to give the end user a driver that hosts a local websocket server on their computer which they can connect to and spawn trackers in VR.  
It also echoes back the position of all currently active VR devices, allowing you to use the driver to find the position of a HMD using local websockets.  

This is desirable as it allows simple applications (such as web based applications) to interface with SteamVR without the hassle of setting up their own driver.

Finally, the driver also has the ability to host a simple webserver, which serves the files in `/resources/webserver` on port 8088.  
This can be accessed from: [http://localhost:8088](http://localhost:8088), which serves `/resources/webserver/index.html`.  

This is built upon the work of [terminal29's](https://github.com/terminal29) ["Simple-OpenVR-Driver-Tutorial"](https://github.com/terminal29/Simple-OpenVR-Driver-Tutorial), the license for which is found at the bottom of this document.

---

# Quick setup
A release file for this driver can be downloaded [here](https://github.com/John-Dean/OpenVR-Tracker-Websocket-Driver/releases/latest/download/driver.zip).

## Installation
Find your SteamVR driver directory, which should be at:  
  `C:\Program Files (x86)\Steam\steamapps\common\SteamVR\drivers`  
and copy the `websocket_trackers` directory into the SteamVR drivers directory.

---

# Websocket server
The websocket server is hosted on port 8082, and can be connected to at:  
`ws://127.0.0.1:8082`

## Creating/updating trackers
Commands are sent using a JSON object in the format:  
`{"id":"tracker_0","x":0,"y":1,"z":2}`

Where the following are valid keys:  
- id (String - Required)
	- Unique name of the tracker, if no tracker exists with the id a new tracker is created. For all intents and purposes there is no limit on the number that can be spawned.
- x,y,z (Numeric - Optional - default 0)
	- Position in 3D space from origin in metres
- rx,ry,rz,rw (Numeric - Optional - default 0)
	- Rotation in 3D space 
- connected (Boolean - Optional - default true)
	- Set to true/false to enable/disable the tracker


If a key is omitted the value will not be changed from the previous update.

## Updating multiple trackers in a single request
Commands can be stacked in a JSON array as follows (there should be no limit on how many can be added):  
`[{"id":"tracker_0","x":0,"y":1,"z":2}, {"id":"tracker_1","x":0,"y":1,"z":2}]`

## Invalid commands
If any part of a command contains invalid JSON the whole request is ignored.

## Example code
If you would like to test this out, please do the following.

- Install the driver (from the releases or build it yourself using below instructions)
- Start SteamVR
- Navigate to [http://localhost:8088](http://localhost:8088)
- Open a console and paste and run the following:
```js
// Create WebSocket connection.
const socket = new WebSocket('ws://127.0.0.1:8082');

// Connection opened
socket.addEventListener('open', function (event) {
 socket.send('{"id":"tracker_0","x":0,"y":1,"z":-1}');
});

// Listen for messages
socket.addEventListener('message', function (event) {
    console.log('Message from server ', JSON.parse(event.data));
});
```

---

# Building
To build the project do the following (tested with CMake 3.20.1 and Visual Studio 2019):  
- Clone the project and submodules
	- `git clone --recursive https://github.com/John-Dean/OpenVR-Tracker-Websocket-Driver.git`
- Build project with CMake
	- `cd OpenVR-Tracker-Websocket-Driver && cmake .`
- Open project with Visual Studio, select release and build
	- Driver folder structure and files will be copied to the output folder as `websocket_trackers`.

---

# Licenses
## Websocket OpenVR Driver license
MIT License

Copyright (c) 2022 John Dean

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Original license (for [terminal29's](https://github.com/terminal29) ["Simple-OpenVR-Driver-Tutorial"](https://github.com/terminal29/Simple-OpenVR-Driver-Tutorial))
MIT License

Copyright (c) 2020 Jacob Hilton [Terminal29](https://github.com/terminal29)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
