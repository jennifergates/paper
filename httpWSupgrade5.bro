#Module to parse and log websocket handshake information from http headers

#load processes the __load__.bro scripts in the directories loaded 
#which basically includes libraries
@load base/protocols/http
@load base/protocols/conn

#create namespace 
module httpWSupgrade;

export {
	#Create an ID for our new stream. 
	redef enum Log::ID += { LOG };

	#Define the record type that will contain the data to log.
	type Info: record {
		ws_handshake: string &log;
		ws_svr: addr	&log;
		ws_svrp: port &log;
		ws_client: addr	&log;
		ws_host: string &log;
		ws_uri: string &log;
		ws_useragent: string &log;
		ws_acceptkey: string &log;
		ws_origin: string &log;
		ws_location: string &log;
	};
}

event bro_init()  &priority=5
{
	#Create the stream. this adds a default filter automatically
	Log::create_stream(httpWSupgrade::LOG, [$columns=Info, $path="httpWSupgrade"]);
}

#add a new field to the connection record so that data is accessible in variety of event handlers
redef record connection += {
	httpwsupgrade: Info &optional;
};

#use http_all_headers event as defined in Bro_HTTP.events.bif.bro. It returns a list of headers
#indexed by order in packet and containing name/value pairs
event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
{
	#initialize non-required fields
	local origin = " - ";
	local location = " - ";
	local acceptkey = " - ";
	local useragent= " - ";
	local handshake=" ";
	local svrip: addr;
	local cltip: addr;
	local svrp: port;

	#look through all headers for handshake headers to log
	for (i in hlist)
	{
		#print "New header -----------------------------------------";
		#print hlist[i];
		handshake=" ";

		# if this is a client request to handshake the client must indicate the version as 13 per the RFC
		if ("SEC-WEBSOCKET-VERSION" in hlist[i]$name && "13" in hlist[i]$value )  
		{
			print "1313131313131313";
			handshake="REQUEST";
			svrip=c$id$resp_h;
			svrp=c$id$resp_p;
			cltip=c$id$orig_h;

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
			};

		};

		# if this is a server response to a successful handshake it will have a status code of 101
		if ("UPGRADE" in hlist[i]$name && "websocket" in to_lower(hlist[i]$value) && c$http?$status_code && c$http$status_code == 101)  #the ? lets you check if it exists
		{
			print "101101101101101101101101";
			handshake = "REPLY";
			svrip=c$id$resp_h;
			svrp=c$id$resp_p;
			cltip=c$id$orig_h;

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

			};

		};


		# if a handshake header was found, log the handshake header information to httpWSupgrade.log
		if (|handshake| > 1)
		{
		#Log format
		local rec: httpWSupgrade::Info = [$ws_client=cltip, $ws_svr=svrip, $ws_svrp=svrp, $ws_origin=origin, $ws_location=location, $ws_acceptkey=acceptkey, $ws_host=c$http$host, $ws_uri=c$http$uri, $ws_useragent=useragent, $ws_handshake=handshake];
			
		c$httpwsupgrade = rec;

		Log::write(httpWSupgrade::LOG, rec);
		};
		
	};
}
