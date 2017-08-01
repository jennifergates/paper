#Module to parse and log WebSocket handshake information from http headers

#load processes the __load__.bro scripts in the directories loaded 
#which basically includes libraries
@load base/protocols/http
@load base/protocols/conn

#create namespace 
module WS_MESSAGE;

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
	Log::create_stream(WS_MESSAGE::LOG, [$columns=Info, $path="WS_Message"]);
}

#add a new field to the connection record so that data is accessible in variety of event handlers
redef record connection += {
	ws_message: Info &optional;
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

event ws_maskedmessage(c: connection, first2B: Brofirst2B, maskkey: string, data: string) {
	local mkey = " - ";
	local wsdata = " - ";

	if ( |maskkey| > 1 ) {
		mkey = maskkey;
	};

	if (|data| > 0 ) {
		wsdata = data;
	};

	#Log format
	local rec: WS_MESSAGE::Info = [$ws_uid=c$uid, $ws_client=c$id$orig_h, $ws_svr=c$id$resp_h, $ws_svrp=c$id$resp_p, $ws_opcode=first2B$op, $ws_maskkey=mkey, $ws_data=wsdata];
	c$ws_message = rec;

	Log::write(WS_MESSAGE::LOG, rec);	
}

#event ws_unmaskedmessage(c: connection, first2B: Brofirst2B) {
#        local mkey = " - ";
#        local wsdata = " - ";

#        #Log format
#        local urec: WS_MESSAGE::Info = [$ws_uid=c$uid, $ws_client=c$id$orig_h, $ws_svr=c$id$resp_h, $ws_svrp=c$id$resp_p, $ws_opcode=first2B$op, $ws_maskkey=mkey, $ws_data=wsdata];
#        c$ws_message = urec;

#        Log::write(WS_MESSAGE::LOG, urec);
#}

#event ws_nodatamessage(c: connection, first2B: Brofirst2B) {
#        local mkey = " - ";
#        local wsdata = " - ";

        #Log format
#        local urec: WS_MESSAGE::Info = [$ws_uid=c$uid, $ws_client=c$id$orig_h, $ws_svr=c$id$resp_h, $ws_svrp=c$id$resp_p, $ws_opcode=first2B$op, $ws_maskkey=mkey, $ws_data=wsdata];
#        c$ws_message = urec;

#        Log::write(WS_MESSAGE::LOG, urec);
#}