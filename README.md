# Websocket OpenVR Driver
The aim of this repository is to give the end user a driver that hosts a local websocket server on their computer which they can connect to and spawn trackers in VR.  
It also echoes back the position of all currently active VR devices, allowing you to use the driver to find the position of a HMD using local websockets.  

This is desirable as it allows simple applications (such as web based applications) to interface with SteamVR without the hassle of setting up their own driver.

The driver also hosts a simple HTTP webserver, which serves the files in `/resources/webserver` on port 12101.  
This can be accessed from: [http://localhost:12101](http://localhost:12101), which serves `/resources/webserver/index.html`.  


The driver also hosts 7 additional HTTPS servers with non-trusted certificates, which serve the files in `/resources/webserver`.
By sending requests to these in binary you can remotely set/get data stored in the echo value on the websocket. An example of this and the port numbers are included in `ServerMessaging.js`.  

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
The websocket server is hosted on port 12100, and can be connected to at:  
`ws://127.0.0.1:12100`

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

## Using the echo feature
If you wish for the driver to echo a message back, sent a command that starts with a space.  
```
Sample message:
 "echo message"
```  

When the server replies the `echo` field will now display your message.  

This supports JSON formatting.  
```
Sample message:
 ["echo message list item 1", "echo message list item 2"]
```

The only condition is to start the message with a space.

## Local IPs
The driver also replies with an `ip` field. This field houses an array of all potential local IP addresses.

## Example code
If you would like to test this out, please do the following.

- Install the driver (from the releases or build it yourself using below instructions)
- Start SteamVR
- Navigate to [http://localhost:12101](http://localhost:12101)
- Open a console and paste and run the following:
```js
// Create WebSocket connection.
const socket = new WebSocket('ws://127.0.0.1:12100');

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
- Download OpenSSL from here `https://slproweb.com/products/Win32OpenSSL.html`  
  Tested with `Win64 OpenSSL v3.0.1`. Install into the default location (`C:\Program Files\OpenSSL-Win64`).
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

Copyright (c) 2021-2022 John Dean

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
