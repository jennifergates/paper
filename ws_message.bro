# *****************************************************************************
# WebSockets Message Bro script
# Jennifer Gates
# August 2017
# 
# Script to expose the WebSockets protocol fields and payload data. The 
# messages are separated into three different types: masked (from the client), 
# unmasked (from the server), and no data (control messages from either host) 
# for processing within the script, but all three log to the WS_Message.log file. 
# The log file contains the connection UID, the client IP, the server IP, the 
# server port, OpCode, mask key, and payload data. 
# *****************************************************************************

# load processes the __load__.bro scripts in the directories loaded 
@load base/protocols/http
@load base/protocols/conn
@load bintools

# create namespace 
module WS_MESSAGE;

export {
	# Create an ID for our new stream. 
	redef enum Log::ID += { LOG };

	# Define the record type that will contain the data to log.
	type Info: record {
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
	# Create the stream. this adds a default filter automatically
	Log::create_stream(WS_MESSAGE::LOG, [$columns=Info, $path="WS_Message"]);
}

# add a new field to the connection record so that data is accessible in variety of event handlers
redef record connection += {
	ws_message: Info &optional;
};


# define the first2B tuple for Bro for the record that will be passed in from spicy parser
type Brofirst2B: record {
	fin: count;
	rsv1: count;
	rsv2: count;
	rsv3: count;
	op: count;
	mask: count;
	pay1: count;
};

# log information from a message with masked data
event ws_maskedmessage(c: connection, first2B: Brofirst2B, maskkey: string, data: string) {
	local mkey = " - ";
	local wsdata = " - ";
	local xordata = "";
	if ( |maskkey| > 1 ) {
		mkey = maskkey;
	};

	local ct: count = 0;
	
	# XOR lookup function provided by https://github.com/justbeck/bro-xorpe/blob/master/bintools.bro
	# mask key is 4 bytes so need to mod to iterate through bytes
	for ( byte in data) {
		xordata += BinTools::xor(byte, mkey[(ct % 4)]);
		ct = ct + 1;
	}
		
	wsdata = xordata;

	# Log format
	local rec: WS_MESSAGE::Info = [$ws_uid=c$uid, $ws_client=c$id$orig_h, $ws_svr=c$id$resp_h, $ws_svrp=c$id$resp_p, $ws_opcode=first2B$op, $ws_maskkey=mkey, $ws_data=wsdata];
	c$ws_message = rec;

	Log::write(WS_MESSAGE::LOG, rec);	
}

# log information from a message with unmasked data
event ws_unmaskedmessage(c: connection, first2B: Brofirst2B, data: string) {
        local mkey = " - ";
        local wsdata = data;
        #Log format
        local urec: WS_MESSAGE::Info = [$ws_uid=c$uid, $ws_client=c$id$orig_h, $ws_svr=c$id$resp_h, $ws_svrp=c$id$resp_p, $ws_opcode=first2B$op, $ws_maskkey=mkey, $ws_data=wsdata];
        c$ws_message = urec;

        Log::write(WS_MESSAGE::LOG, urec);
}

# log information from a message with no data
event ws_nodatamessage(c: connection, first2B: Brofirst2B) {
        local mkey = " - ";
        local wsdata = " - ";

        #Log format
        local nrec: WS_MESSAGE::Info = [$ws_uid=c$uid, $ws_client=c$id$orig_h, $ws_svr=c$id$resp_h, $ws_svrp=c$id$resp_p, $ws_opcode=first2B$op, $ws_maskkey=mkey, $ws_data=wsdata];
        c$ws_message = nrec;

        Log::write(WS_MESSAGE::LOG, nrec);
}