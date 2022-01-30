class SendEchoSSL{
	constructor(url, port_0, port_1, port_submit){
		if(port_0 == undefined){
			port_0 = 8090
		}
		if(port_1 == undefined){
			port_1 = 8091
		}
		if(port_submit == undefined){
			port_submit = 8089
		}
		
		if(url.indexOf("https://")!=0){
			url	=	"https://"+url;
		}
		
		const This = this;
		
		This.url = url;
		This.port_0 = port_0;
		This.port_1 = port_1;
		This.port_submit = port_submit;
	}
	
	convert_to_binary(string){
		const convert_to_byte_string	=	function(n){
			if(n < 0 || n > 255 || n % 1 !== 0){
				throw new Error(n + " does not fit in a byte");
			}
			return (("000000000" + n.toString(2)).substr(-8));
		}

		let output = ""
		for(var i = 0; i < string.length; i++){
			output += convert_to_byte_string(string[i].charCodeAt(0));
		}
		
		return output;
	}	
	
	send(message){
		const This = this;
		return Promise.resolve()
		.then(async function(){
			const binary_string	=	This.convert_to_binary(message);
		
			let counter	=	0;
		
			const	send_data	= function(url){
				let Resolve, Reject;
				let promise	=	new Promise(function(resolve, reject){
					Resolve	=	resolve;
					Reject	=	reject;
				});

				var oReq = new XMLHttpRequest();
				oReq.addEventListener("load", Resolve);
				oReq.addEventListener("error", Resolve);
				oReq.open("GET", url + "?" + counter);
				oReq.send();
		
				counter++;
				return promise
			}
		
			const send_0	=	function(){
				const url	=	This.url + ":" + This.port_0;
				return send_data(url);
			}
			const send_1	=	function(){
				const url	=	This.url + ":" + This.port_1;
				return send_data(url);
			}
			const send_submit	=	function(){
				const url	=	This.url + ":" + This.port_submit;
				return send_data(url);
			}
			
			// Do an initial flush of all 3 so the browser doesn't double fire trying to connect
			await send_0();
			await send_1();
			await send_submit();
			counter	=	0;
			
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
}

/*
	Example usage:
	
	let send_data = new SendEchoSSL("192.168.1.167")
	send_data.send("Test message")
*/


export {SendEchoSSL}
