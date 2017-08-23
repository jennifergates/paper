# *****************************************************************************
# WebSockets Handshake Bro script
# Jennifer Gates
# August 2017
#
# This script takes the WebSockets connection parsed by the Spicy script and, 
# using the allheaders event, creates the WS_Handshake.log file. The log 
# file provides WebSockets handshake header information such as the host, URI, 
# origin, location, subprotocols, and extensions, as well as basic connection 
# information such as the timestamp, UID, server IP address, server port, and 
# client IP address.
# *****************************************************************************

#load processes the __load__.bro scripts in the directories loaded 
#which basically includes libraries
@load base/protocols/http
@load base/protocols/conn

#create namespace 
module WS_HANDSHAKE;

export {
	#Create an ID for our new stream. 
	redef enum Log::ID += { LOG };

	#Define the record type that will contain the data to log.
	type Info: record {
		## Indicates if log info is for WebSocket Handshake Request or Reply
		ws_handshake: string &log;  
		## Timestamp for when the request happened
		ws_ts: time &log;
		## Unique ID for the connection
		ws_uid: string &log;
		## Client IP requesting WebSocket
		ws_client: addr	&log;
		## Server IP providing WebSocket
		ws_svr: addr &log;
		## Server port providing WebSocket
		ws_svrp: port &log;
		## Value of the HOST header
		ws_host: string &log;
		## URI used in the request
		ws_uri: string &log;
		## Value of the User-Agent header from the client
		ws_useragent: string &log;
		## Value of the client's SEC-WEBSOCKET-KEY if a request, still base64 encoded 
		## or Value of the servers's SEC-WEBSOCKET-ACCEPT if a reply,  still base64 encoded 
		ws_acceptkey: string &log;  
		## Value of the ORIGIN header
		ws_origin: string &log;
		## Value of the LOCATION header
		ws_location: string &log;
		## Value of the SEC-WEBSOCKET-PROTOCOL header
		ws_protocol: string &log;
		## Value of Sec-WebSocket-Extensions if present
		ws_extensions: string &log;
	};
}

event bro_init()  &priority=5
{
	# Create the stream. this adds a default filter automatically
	Log::create_stream(WS_HANDSHAKE::LOG, [$columns=Info, $path="WS_Handshake"]);
}

# add a new field to the connection record so that data is accessible in variety of event handlers
redef record connection += {
	ws_handshake: Info &optional;
};

# define for Bro the record that will be passed in from spicy parser in the headers list
type BroHdr: record {
	name: string;
	value: string;
};

# define for Bro the vector that will be passed in from spicy parser as the headers list
type BroHdrs: vector of BroHdr;

# define the first2B tuple for Bro for the record that will be passed in from spicy parser
type Brofirst2B: record {
	fin: count;
	rsv1: count;
	rsv2: count;
	rsv3: count;
	op: int;
	mask: count;
	pay1: int;
};

# define for Bro the record that will be passed in from spicy parser in the ws messages list
#<first2B=(fin=1, rsv1=0, rsv2=0, rsv3=0, op=1, mask=1, pay1=12)
type BroMsg: record {
	first2B: Brofirst2B;
	pay2: int &optional;
	pay3: int &optional;
	maskkey: string &optional;
	data: string &optional;
};

# define for Bro the vector that will be passed in from spicy parser as the ws messages list
type BroMsgs: vector of BroMsg;


# event that is basically same data as http parser alone with custom bro script, which this code is from
event allheaders(c: connection, hlist: BroHdrs, reqlinedata: string) {

	#initialize non-required fields or fields not always present in a packet

	local uri = " - ";
	local host = " - ";
	local origin = " - ";
	local location = " - ";
	local acceptkey = " - ";
	local useragent= " - ";
	local handshake=" ";
	local wsproto=" - ";
	local wsexts=" - ";
	local svrip: addr;
	local cltip: addr;
	local svrp: port;

	# look through all headers for handshake headers to log
	for (i in hlist)
	{

		# start with a blank handshake until logic determines if this header is a websocket handshake header
		handshake=" ";

		# if this is a client request to handshake, the client must indicate the version as 13 per the RFC
		if ("sec-websocket-version" in to_lower(hlist[i]$name) && "13" in hlist[i]$value )  
		{
			handshake="REQUEST";
			
						
			local reqlinedatasplit= split_string_all(reqlinedata, /HTTP/);
			uri = reqlinedatasplit[0];

			for (y in hlist)
			{

				if ( "sec-websocket-key" in to_lower(hlist[y]$name) )
				{
					acceptkey=hlist[y]$value;
				} ;

				if ( "host" in to_lower(hlist[y]$name) )
                                {
                                        host=hlist[y]$value;
                                } ;

				if ( "origin" in to_lower(hlist[y]$name) )
				{
					origin=hlist[y]$value;
				} ;

				if ( "user-agent" in to_lower(hlist[y]$name) )
				{
					useragent=hlist[y]$value;
				} ;
				#In the Request, there could be multiple protocols headers  
				if ( "sec-websocket-protocol" in to_lower(hlist[y]$name) )
				{
					if ( wsproto == " - " )
					{
						wsproto=hlist[y]$value;
					} else {
						wsproto+=hlist[y]$value;
					} ;
				} ;
				# In the Request, there could be multiple extensions headers 
				if ( "sec-websocket-extensions" in to_lower(hlist[y]$name) )
				{
					if ( wsexts == " - " )
					{ 
						wsexts=hlist[y]$value;
					} else {
						wsexts+=hlist[y]$value;
					};
				} ;
			};

		};

		# if this is a server response to a successful handshake, it will have a status code of 101
		# To test if a field that is &optional has been assigned a value, use the ?$operator
		if ("sec-websocket-accept" in to_lower(hlist[i]$name) )
		{
			handshake = "REPLY";

			for (x in hlist)
			{
				
				if ("sec-websocket-accept" in to_lower(hlist[x]$name) )
				{
					acceptkey=hlist[x]$value;
				};

				if ("websocket-origin" in to_lower(hlist[x]$name))
				{
					origin=hlist[x]$value;
				};

				if ("websocket-location" in to_lower(hlist[x]$name))
				{
					location=hlist[x]$value;
				};
				# Per the RFC, the protocol header can only appear once in a server reply, unlike in the request
				if ( "sec-websocket-protocol" in to_lower(hlist[x]$name) )
				{
					wsproto=hlist[x]$value;
				} ;				
				# In the Reply, there could be multiple extensions headers 
				if ( "sec-websocket-extensions" in to_lower(hlist[x]$name) )
				{
					if ( wsexts == " - " )
					{ 
						wsexts=hlist[x]$value;
					} else {
						wsexts+=hlist[x]$value;
					};
				} ;
			};

		};


		# if a handshake header was found, log the handshake header information to ws_handshake.log
		if (|handshake| > 1)
		{
		# Log format
		local rec: WS_HANDSHAKE::Info = [$ws_ts=c$http$ts, $ws_uid=c$uid, $ws_client=c$id$orig_h, $ws_svr=c$id$resp_h, $ws_svrp=c$id$resp_p, $ws_origin=origin, $ws_location=location, $ws_acceptkey=acceptkey,$ws_host=host, $ws_uri=uri, $ws_useragent=useragent, $ws_handshake=handshake, $ws_protocol=wsproto, $ws_extensions=wsexts];

			
		c$ws_handshake = rec;

		Log::write(WS_HANDSHAKE::LOG, rec);
		};
	};
}