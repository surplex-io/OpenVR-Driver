class ServerMessaging{
	constructor(url, port_send_0, port_send_1, port_send_confirm, port_receive_0, port_receive_1, port_receive_next, port_receive_start){
		const This = this;
		if(url.indexOf("https://") != 0){
			url	=	"https://" + url;
		}
		
		this.url	=	url;
		
		this.ports	=	{};
		this.ports.send	=	{};
		this.ports.send[0]			=	port_send_0 || 12110;
		this.ports.send[1]			=	port_send_1 || 12111;
		this.ports.send.confirm	=	port_send_confirm || 12112;
		
		this.ports.receive	=	{};
		this.ports.receive[0]		=	port_receive_0 || 12120;
		this.ports.receive[1]		=	port_receive_1 || 12121;
		this.ports.receive.next		=	port_receive_next || 12122;
		this.ports.receive.start	=	port_receive_start || 12123;
		
		this.ports.socket			= 12100
		this.ports.web_sever_http	= 12101
		this.ports.web_sever_https	= 12102
	}
	
	request_data(url, value){
		let Resolve, Reject;
		let promise	=	new Promise(function(resolve, reject){
			Resolve	=	resolve;
			Reject	=	reject;
		}).then(
			function(){
				return value;
			}
		)

		var oReq = new XMLHttpRequest();
		oReq.addEventListener("load", Resolve);
		oReq.addEventListener("error", Resolve);
		oReq.open("GET", url);
		oReq.send();
		
		return promise
	}
	
	binary_to_string(str){
		var binString = '';

		str.split(' ').map(function(bin){
			binString += String.fromCharCode(parseInt(bin, 2));
		});
		return binString;
	}

	string_to_binary(text){
		var length = text.length;
		var output = [];
		for(var i = 0; i < length; i++){
			var bin = text[i].charCodeAt().toString(2);
			output.push(Array(8 - bin.length + 1).join("0") + bin);
		}
		return output.join("");
	}
	
	set(message){
		const This = this;
		return Promise.resolve()
		.then(async function(){
			const binary_string	=	This.string_to_binary(message);
					
			const send_0	=	function(){
				const url	=	This.url + ":" + This.ports.send[0];
				return This.request_data(url);
			}
			const send_1	=	function(){
				const url	=	This.url + ":" + This.ports.send[1];
				return This.request_data(url)
			}
			const send_submit	=	function(){
				const url	=	This.url + ":" + This.ports.send.confirm;
				return This.request_data(url);
			}
			
			// Do an initial flush of all 3 so the browser doesn't double fire trying to connect
			await send_0();
			await send_1();
			await send_submit();
			
			for(let i = 0; i < binary_string.length; i++){
				let number = 	Number(binary_string[i]);
				if(number == 0){
					await send_0();
				} else{
					await send_1();
				}
			}
			await send_submit()
		})
	}
	
	get(){
		const This = this;
		return Promise.resolve()
		.then(async function(){
			// Flush any double firing out the way
			await This.request_data(This.url + ":" + This.ports.receive[0]);
			await This.request_data(This.url + ":" + This.ports.receive[1]);
			await This.request_data(This.url + ":" + This.ports.receive.next);
			
			await This.request_data(This.url + ":" + This.ports.receive.start);
	
	
			let output_string	=	"";
			let output = "";
			while(true){
				let fetch_0	=	This.request_data(This.url + ":" + This.ports.receive[0], 0);
				let fetch_1	=	This.request_data(This.url + ":" + This.ports.receive[1], 1);
		
				Promise.race([fetch_0, fetch_1]).then((value) => {
					output =	output + value;
				});
				await This.request_data(This.url + ":" + This.ports.receive.next);
				await Promise.all([fetch_0, fetch_1]);
		
				if(output.length == 8){
					if(Number(output) == 0){
						break;
					} else{
						let character	=	This.binary_to_string(output)
						
						output_string = output_string + character;
						output	=	"";
				
						if(output_string.length > 10000){
							break;
						}
					}
				}
			}
			return output_string;
		})
	}
}



/*
const socket = new WebSocket('ws://localhost:12100')

// Connection opened
socket.addEventListener('open', function (event) {
 socket.send(' test');
});

// Listen for messages
socket.addEventListener('message', function (event) {
    console.log('Message from server ', JSON.parse(event.data));
});
*/

/*
	Example usage:
	
	let messaging = new ServerMessaging("192.168.1.167")
	await messaging.set("Test message")
	let message_out = await messaging.get()
	console.log(message_out);
*/


export {ServerMessaging}
