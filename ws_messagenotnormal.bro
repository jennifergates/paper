#Module to parse and log WebSocket messages that are not normal activity for a custom app, such as DVWS's command execution ping app

#load processes the __load__.bro scripts in the directories loaded 
#which basically includes libraries
@load base/protocols/http
@load base/protocols/conn
@load bintools

const CustomURI = "/command-execution";

#create namespace 
module WS_MESSAGENOTNORMAL;

export {
	#Create an ID for our new stream. 
	redef enum Log::ID += { LOG };

	#Define the record type that will contain the data to log.
	type Info: record {
		## Timestamp for when the request happened
		#ws_ts: time &log;
		## Unique ID for the connection
		ws_uid: string &log;
		## Client IP requesting WebSocket
		ws_client: addr	&log;
		## Server IP providing WebSocket
		ws_svr: addr &log;
		## Server port providing WebSocket
		ws_svrp: port &log;
		## Opcode indicating if text, binary, etc
		ws_opcode: count &log;
		## Maskkey used by client to XOR mask data
		ws_maskkey: string &log;
		## Data in websocket packet
		ws_data: string &log;
	};
}

event bro_init()  &priority=5
{
	#Create the stream. this adds a default filter automatically
	Log::create_stream(WS_MESSAGENOTNORMAL::LOG, [$columns=Info, $path="WS_MessageNotNormal"]);
}

#add a new field to the connection record so that data is accessible in variety of event handlers
redef record connection += {
	ws_messagenotnormal: Info &optional;
};


#define the first2B tuple for Bro for the record that will be passed in from spicy parser
type Brofirst2B: record {
	fin: count;
	rsv1: count;
	rsv2: count;
	rsv3: count;
	op: count;
	mask: count;
	pay1: count;
};

#event to detect and log when the response to the custom url is not the expected ping response. 
#if normal, the ping is successful or not and the second to last line returned starts with "3 packets trasmitted"
event ws_unmaskedmessage(c: connection, first2B: Brofirst2B, data: string) {
	if (c$http$uri == CustomURI) {
	        local mkey = " - ";
		local wsdata = data;
	        #Log format
		local urec: WS_MESSAGENOTNORMAL::Info = [$ws_uid=c$uid, $ws_client=c$id$orig_h, $ws_svr=c$id$resp_h, $ws_svrp=c$id$resp_p, $ws_opcode=first2B$op, $ws_maskkey=mkey, $ws_data=wsdata];
		c$ws_messagenotnormal = urec;
		if (first2B$op == 1) {
			local thearray = split_string(data, /\x0a/);
			local pkts = thearray[(|thearray|-3)];
			if (pkts != /^3 packets transmitted,.+/) {
				print c;
				Log::write(WS_MESSAGENOTNORMAL::LOG, urec);   
			};
		};
	};
}