#Module to parse and log WebSocket origin mismatch information from http headers

#load processes the __load__.bro scripts in the directories loaded 
#which basically includes libraries
@load base/protocols/http
@load base/protocols/conn

#create namespace 
module WS_ORIGINMISMATCH;

const accepted_origins: set[string] = ["http://dvws.local"];

export {
	#Create an ID for our new stream. 
	redef enum Log::ID += { LOG };

	#Define the record type that will contain the data to log.
	type Info: record {
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
		## Value of the ORIGIN header
		ws_origin: string &log;
		## Value of the LOCATION header
		ws_location: string &log;
	};
}

event bro_init()  &priority=5
{
	#Create the stream. this adds a default filter automatically
	Log::create_stream(WS_ORIGINMISMATCH::LOG, [$columns=Info, $path="WS_Originmismatch"]);
}

#add a new field to the connection record so that data is accessible in variety of event handlers
redef record connection += {
	ws_originmismatch: Info &optional;
};

# define for Bro the record that will be passed in from spicy parser in the headers list
type BroHdr: record {
	name: string;
	value: string;
};

# define for Bro the vector that will be passed in from spicy parser as the headers list
type BroHdrs: vector of BroHdr;

# event that is basically same data as http parser alone with custom bro script, which this code is from
event allheaders(c: connection, hlist: BroHdrs, reqlinedata: string) {
        print " ";
        print "*****ws_originmismatch.bro allheaders event:";
	#initialize non-required fields or fields not always present in a packet
	#print c;
	print reqlinedata;
	local uri = " - ";
	local host = " - ";
	local origin = " - ";
	local location = " - ";
	local useragent= " - ";
	local svrip: addr;
	local cltip: addr;
	local svrp: port;

	#look through all headers for handshake headers to log
	for (i in hlist)
	{

		#print hlist[i];
		#start with a blank handshake until logic determines if this header is a websocket handshake header
		local handshake =" ";

		# if this is a client request to handshake, the client must indicate the version as 13 per the RFC
		#### Should these "in" statements be set to lowercase comparisons since http rfc says case insensitive?
		#### Or does bro http script normalize the field names?
		if ("sec-websocket-version" in to_lower(hlist[i]$name) && "13" in hlist[i]$value )  
		{
			print "1313131313131313";
			handshake="REQUEST";
			
						
			local reqlinedatasplit= split_string_all(reqlinedata, /HTTP/);
			uri = reqlinedatasplit[0];

			for (y in hlist)
			{

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
			};

		};

		# if a handshake header was found, log the handshake header information to ws_handshakenotnormal.log
		if (|handshake| > 1)
		{
			if (origin !in accepted_origins ) {
			#Log format
			#local rec: WS_ORIGINMISMATCH::Info = [$ws_ts=c$http$ts, $ws_uid=c$uid, $ws_client=c$id$orig_h, $ws_svr=c$id$resp_h, $ws_svrp=c$id$resp_p, $ws_origin=origin, $ws_location=location, $ws_acceptkey=acceptkey, $ws_host=host, $ws_uri=uri, $ws_useragent=useragent, $ws_handshakenotnormal=handshake, $ws_protocol=wsproto, $ws_extensions=wsexts];
			local rec: WS_ORIGINMISMATCH::Info = [$ws_uid=c$uid, $ws_client=c$id$orig_h, $ws_svr=c$id$resp_h, $ws_svrp=c$id$resp_p, $ws_origin=origin, $ws_location=location, $ws_host=host, $ws_uri=uri, $ws_useragent=useragent];

			
			c$ws_originmismatch = rec;

			Log::write(WS_ORIGINMISMATCH::LOG, rec);
			};
		};
	};
}