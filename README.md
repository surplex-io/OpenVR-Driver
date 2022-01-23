# Websocket OpenVR Driver Tutorial

This is an adaptation of the repository authored by terminal29, "Simple-OpenVR-Driver-Tutorial"

The aim of this repository is to give the end user a driver that hosts a local websocket server on their computer which they can connect to and spawn trackers in VR using simple JSON.

This is desirable as it allows simple Python or JavaScript applications to interface with SteamVR and create trackers.
This means you can write simple Python code to, for example, emulate a hip tracker using neural networks and a webcam and easily add it to SteamVR.

# Websocket server
The websocket server can be connected to at:
`ws://127.0.0.1:8082`

And commands are sent using JSON in the format:
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

Commands can be stacked in a JSON array as follows (there should be no limit on how many can be added):
`[{"id":"tracker_0","x":0,"y":1,"z":2}, {"id":"tracker_1","x":0,"y":1,"z":2}]`

If a command contains invalid JSON the whole command is ignored.

## Testing

If you would like to test this out, please do the following.

- Install the driver (from the releases or build it yourself using below instructions)
- Start SteamVR and connect a headset
- Start a local webserver
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
    console.log('Message from server ', event.data);
});
```

## Building
- Clone the project and submodules
	- `git clone --recursive https://github.com/John-Dean/OpenVR-Tracker-Websocket-Driver.git`
- Build project with CMake
	- `cd OpenVR-Tracker-Websocket-Driver && cmake .`
- Open project with Visual Studio and hit build
	- Driver folder structure and files will be copied to the output folder as `example`.
	
## Installation

There are two ways to "install" your plugin (The first one is recommended):

- Find your SteamVR driver directory, which should be at:
  `C:\Program Files (x86)\Steam\steamapps\common\SteamVR\drivers`
  and copy the `example` directory from the project's build directory into the SteamVR drivers directory. Your folder structure should look something like this:

![Drivers folder structure](https://i.imgur.com/hOsDk1H.png)
or

- Navigate to `C:\Users\<Username>\AppData\Local\openvr` and find the `openvrpaths.vrpath` file. Open this file with your text editor of choice, and under `"external_drivers"`, add another entry with the location of the `example` folder. For example mine looks like this after adding the entry:

```json
{
	"config" : 
	[
		"C:\\Program Files (x86)\\Steam\\config",
		"c:\\program files (x86)\\steam\\config"
	],
	"external_drivers" : 
	[
		"C:\\Users\\<Username>\\Documents\\Programming\\c++\\Simple-OpenVR-Driver-Tutorial\\build\\Debug\\example"
	],
	"jsonid" : "vrpathreg",
	"log" : 
	[
		"C:\\Program Files (x86)\\Steam\\logs",
		"c:\\program files (x86)\\steam\\logs"
	],
	"runtime" : 
	[
		"C:\\Program Files (x86)\\Steam\\steamapps\\common\\SteamVR"
	],
	"version" : 1
}
```

## License
MIT License

Copyright (c) 2020 Jacob Hilton (Terminal29)

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
