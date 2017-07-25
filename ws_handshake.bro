#Module to parse and log WebSocket handshake information from http headers

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
		#### Not sure the key/accept is needed to detect any exploits
		## Value of the client's SEC-WEBSOCKET-KEY if a request, still base64 encoded 
		## or Value of the servers's SEC-WEBSOCKET-ACCEPT if a reply,  still base64 encoded 
		ws_acceptkey: string &log;  
		## Value of the ORIGIN header
		ws_origin: string &log;
		## Value of the LOCATION header
		ws_location: string &log;
		## Value of the SEC-WEBSOCKET-PROTOCOL header
		ws_protocol: string &log;
		#### Are these useful for detecting any exploits?
		## Value of Sec-WebSocket-Extensions if present
		ws_extensions: string &log;
	};
}

event bro_init()  &priority=5
{
	#Create the stream. this adds a default filter automatically
	Log::create_stream(WS_HANDSHAKE::LOG, [$columns=Info, $path="WS_Handshake"]);
}

#add a new field to the connection record so that data is accessible in variety of event handlers
redef record connection += {
	ws_handshake: Info &optional;
};

type BroHdr: record {
	name: string;
	value: string;
};

type BroHdrs: vector of BroHdr;

event ws_handshake(c: connection, get: string) {
	print " ";
	print "*****ws_handshake.bro ws_handshake event:";
        print get;
}

event header(c: connection, name: string, value: string) {
	if ( name == "Sec-WebSocket-Key") {
		print " ";
		print "*****ws_handshake.bro header event:";
		print value;	
	}
}

event allheaders(c: connection, hlist: BroHdrs) {
        print " ";
        print "*****ws_handshake.bro allheaders event:";
	#initialize non-required fields or fields not always present in a packet
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

	#look through all headers for handshake headers to log
	for (i in hlist)
	{

		#print hlist[i];
		#start with a blank handshake until logic determines if this header is a websocket handshake header
		handshake=" ";

		# if this is a client request to handshake, the client must indicate the version as 13 per the RFC
		#### Should these "in" statements be set to lowercase comparisons since http rfc says case insensitive?
		#### Or does bro http script normalize the field names?
		if ("SEC-WEBSOCKET-VERSION" in hlist[i]$name && "13" in hlist[i]$value )  
		{
			print "1313131313131313";
			handshake="REQUEST";
			

			for (y in hlist)
			{

				if ( "SEC-WEBSOCKET-KEY" in hlist[y]$name )
				{
					acceptkey=hlist[y]$value;
				} ;

				if ( "ORIGIN" in hlist[y]$name )
				{
					origin=hlist[y]$value;
				} ;

				if ( "USER-AGENT" in hlist[y]$name )
				{
					useragent=hlist[y]$value;
				} ;
				#In the Request, there could be multiple protocols headers  
				if ( "SEC-WEBSOCKET-PROTOCOL" in hlist[y]$name )
				{
					if ( wsproto == " - " )
					{
						wsproto=hlist[y]$value;
					} else {
						wsproto+=hlist[y]$value;
					} ;
				} ;
				# In the Request, there could be multiple extensions headers 
				if ( "SEC-WEBSOCKET-EXTENSIONS" in hlist[y]$name )
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
		if ("UPGRADE" in hlist[i]$name && "websocket" in to_lower(hlist[i]$value) && c$http?$status_code && c$http$status_code == 101)  
		{
			print "101101101101101101101101";
			handshake = "REPLY";

			for (x in hlist)
			{
				
				if ("SEC-WEBSOCKET-ACCEPT" in hlist[x]$name )
				{
					acceptkey=hlist[x]$value;
				};

				if ("WEBSOCKET-ORIGIN" in hlist[x]$name)
				{
					origin=hlist[x]$value;
				};

				if ("WEBSOCKET-LOCATION" in hlist[x]$name)
				{
					location=hlist[x]$value;
				};
				# Per the RFC, the protocol header can only appear once in a server reply, unlike in the request
				if ( "SEC-WEBSOCKET-PROTOCOL" in hlist[x]$name )
				{
					wsproto=hlist[x]$value;
				} ;				
				#In the Reply, there could be multiple extensions headers 
				if ( "SEC-WEBSOCKET-EXTENSIONS" in hlist[x]$name )
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


		# if a handshake header was found, log the handshake header information to httpWSupgrade.log
		if (|handshake| > 1)
		{
		#Log format
		local rec: WS_HANDSHAKE::Info = [$ws_ts=c$http$ts, $ws_uid=c$uid, $ws_client=c$id$orig_h, $ws_svr=c$id$resp_h, $ws_svrp=c$id$resp_p, $ws_origin=origin, $ws_location=location, $ws_acceptkey=acceptkey, $ws_host=c$http$host, $ws_uri=c$http$uri, $ws_useragent=useragent, $ws_handshake=handshake, $ws_protocol=wsproto, $ws_extensions=wsexts];
			
		c$ws_handshake = rec;

		Log::write(WS_HANDSHAKE::LOG, rec);
		};
	};
}