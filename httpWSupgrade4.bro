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
		ws_svr: addr	&log;
		ws_svrp: port &log;
		ws_client: addr	&log;
		ws_host: string &log;
		ws_uri: string &log;
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
	local key = " - ";
	local location = " - ";
	local acceptkey = " - ";
	local svrorigin= " - ";
	local svrlocation= " - ";

	for (i in hlist)
	{
		#print "New header -----------------------------------------";
		#print hlist[i];
		# if this is a server response to a successful handshake it will have a status code of 101
		if ("UPGRADE" in hlist[i]$name && "websocket" in to_lower(hlist[i]$value) && c$http?$status_code && c$http$status_code == 101)  #the ? lets you check if it exists
		{
			print "101101101101101101101101";
			for (x in hlist)
			{
				
				if ("SEC-WEBSOCKET-ACCEPT" in hlist[x]$name )
				{
					acceptkey=hlist[x]$value;
				};

				if ("WEBSOCKET-ORIGIN" in hlist[x]$name)
				{
					svrorigin=hlist[x]$value;
				};

				if ("WEBSOCKET-LOCATION" in hlist[x]$name)
				{
					svrlocation=hlist[x]$value;
				};

			};
			#Log format
			local svrrec: httpWSupgrade::Info = [$ws_client=c$id$orig_h, $ws_svr=c$id$resp_h, $ws_svrp=c$id$resp_p, $ws_origin=svrorigin, $ws_location=svrlocation, $ws_acceptkey=acceptkey, $ws_host=c$http$host, $ws_uri=c$http$uri];
			
			c$httpwsupgrade = svrrec;

			Log::write(httpWSupgrade::LOG, svrrec);
		};

		# if this is a client request to handshake the client must indicate the version as 13
		if ("SEC-WEBSOCKET-VERSION" in hlist[i]$name && "13" in hlist[i]$value )  
		{
			print "1313131313131313";

			for (y in hlist)
			{
				#print type_name(hlist[y]$name);

				#if ( hlist[y]$name == "SEC-WEBSOCKET-KEY" )
				if ( "SEC-WEBSOCKET-KEY" in hlist[y]$name )
				{
					key=hlist[y]$value;
				} ;

				if ( "ORIGIN" in hlist[y]$name )
				{
					origin=hlist[y]$value;
				} ;

			};

			#Log format
			local rec: httpWSupgrade::Info = [$ws_client=c$id$resp_h, $ws_svr=c$id$orig_h, $ws_svrp=c$id$orig_p, $ws_origin=origin, $ws_location=location, $ws_acceptkey=key, $ws_host=c$http$host, $ws_uri=c$http$uri];
			
			c$httpwsupgrade = rec;

			Log::write(httpWSupgrade::LOG, rec);
		};
	};
}
