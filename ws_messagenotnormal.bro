#Module to parse and log WebSocket messages that are not normal activity for a custom app, such as DVWS's command execution ping app

#load processes the __load__.bro scripts in the directories loaded 
#which basically includes libraries
@load base/protocols/http
@load base/protocols/conn
@load bintools
@load policy/frameworks/intel/seen

#Create some constants 
const CustomURI1 = "/command-execution";
const ExpResp1 = /^3 packets transmitted,.+/;
const CustomURI2 = "/reflected-xss";
const ExpResp2 = /^Hello [a-zA-Z\' ]+:\) How are you\?/;
const CustomURI3 = "/authenticate-user";
const ExpResp3a = /^Welcome to your account\. How are you [a-zA-Z\' ]+\?/;
const ExpResp3b = /<pre>Invalid username\/password<\/pre>/;
const SQLinjectionRegEx = /.*(table_schema|floor|concat|having|union|select|delete|drop|declare|create|insert|column_name|table_name).*/;
const CustomURI4 = "/post-comments";
const HTMLRegExs: set[string] = ["href", "img", "src", "script", "alert", "onerror", "=", "<", ">", ":", "//"];
const CustomURI5 = "/authenticate-user-blind";

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
		## URI in websocket packet
		ws_uri: string &log;
		## Data in websocket packet
		ws_data: string &log;

	};

	##Append a new notice value to the Notice::Type enumerable.
	redef enum Notice::Type += { Unexpected_Response };
	redef enum Notice::Type += { SQL_Injection_words };

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

#event to detect and log when the response to the custom url is not the expected response. 
event ws_unmaskedmessage(c: connection, first2B: Brofirst2B, data: string) {
	#if normal, the ping is successful or not and the second to last line returned starts with "3 packets trasmitted"
	if (c$http$uri == CustomURI1) {
	        local mkey = " - ";
		local wsdata = data;
	        #Log format
		local urec1: WS_MESSAGENOTNORMAL::Info = [$ws_uid=c$uid, $ws_client=c$id$orig_h, $ws_svr=c$id$resp_h, $ws_svrp=c$id$resp_p, $ws_opcode=first2B$op, $ws_maskkey=mkey, $ws_uri=c$http$uri, $ws_data=wsdata];
		c$ws_messagenotnormal = urec1;
		if (first2B$op == 1) {
			local thearray = split_string(data, /\x0a/);
			local pkts = thearray[(|thearray|-3)];
			if (pkts != ExpResp1) {
				Log::write(WS_MESSAGENOTNORMAL::LOG, urec1); 
				NOTICE([$note=WS_MESSAGENOTNORMAL::Unexpected_Response, $msg = fmt("Unexpected Response to %s", CustomURI1), $sub = fmt("reponse = %s", pkts), $conn=c]);  
			};
		};
	};

	#if normal, the response only includes letters and possibly '
        if (c$http$uri == CustomURI2) {
		#Log format
                local urec2: WS_MESSAGENOTNORMAL::Info = [$ws_uid=c$uid, $ws_client=c$id$orig_h, $ws_svr=c$id$resp_h, $ws_svrp=c$id$resp_p, $ws_opcode=first2B$op, $ws_maskkey=mkey, $ws_uri=c$http$uri, $ws_data=wsdata];
                c$ws_messagenotnormal = urec2;
                if (first2B$op == 1) {
                        if (data != ExpResp2 ) {
                                Log::write(WS_MESSAGENOTNORMAL::LOG, urec2);
				NOTICE([$note=WS_MESSAGENOTNORMAL::Unexpected_Response, $msg = fmt("Unexpected Response to %s", CustomURI2), $sub = fmt("reponse = %s", data), $conn=c]);
                        };
                };
        };

        #if normal, the response is only an error message or welcome message '
        if (c$http$uri == CustomURI3) {
                #Log format
                local urec3: WS_MESSAGENOTNORMAL::Info = [$ws_uid=c$uid, $ws_client=c$id$orig_h, $ws_svr=c$id$resp_h, $ws_svrp=c$id$resp_p, $ws_opcode=first2B$op, $ws_maskkey=mkey, $ws_uri=c$http$uri, $ws_data=wsdata];
                c$ws_messagenotnormal = urec3;
                if (first2B$op == 1) {
                        if ((data != ExpResp3a ) && (data != ExpResp3b)) {
                                Log::write(WS_MESSAGENOTNORMAL::LOG, urec3);
                                NOTICE([$note=WS_MESSAGENOTNORMAL::Unexpected_Response, $msg = fmt("Unexpected Response to %s", CustomURI3), $sub = fmt("reponse = %s", data), $conn=c]);
                        };
                };
        };
}

event ws_maskedmessage(c: connection, first2B: Brofirst2B, maskkey: string, data: string) {
if (first2B$op != 8) {
	local mkey = " - ";
	local wsdata = " - ";
	local xordata = "";
	if ( |maskkey| > 1 ) {
		mkey = maskkey;
	};

	local ct: count = 0;
	
	#XOR lookup function provided by https://github.com/justbeck/bro-xorpe/blob/master/bintools.bro
	# mask key is 4 bytes so need to mod to iterate through bytes
	for ( byte in data) {
		xordata += BinTools::xor(byte, mkey[(ct % 4)]);
		ct = ct + 1;
	}
		
	wsdata = xordata;

	#detect SQL injection and HTML code words in the input and develop a score
	local SQLscore = 0;
	local HTMLscore = 0;

	if ((c$http$uri == CustomURI3) || (c$http$uri == CustomURI5)) {
		#Log format
                local urec3: WS_MESSAGENOTNORMAL::Info = [$ws_uid=c$uid, $ws_client=c$id$orig_h, $ws_svr=c$id$resp_h, $ws_svrp=c$id$resp_p, $ws_opcode=first2B$op, $ws_maskkey=mkey, $ws_uri=c$http$uri, $ws_data=wsdata];
                c$ws_messagenotnormal = urec3;

		#parse the input into username and password 
		local array3 = split_string(wsdata, /,/);

		#parse out input for username and decode from base64
		local username3encoded = split_string(array3[0], /:/)[1][1:-2];
		local username3 = decode_base64(username3encoded);
		local wordsinusername3 = split_string(username3, / /);

		
		#test for common SQL injection words in username
		for (w in wordsinusername3) {
			if (SQLinjectionRegEx in to_lower(wordsinusername3[w])) {
				SQLscore = SQLscore +1;
			};
		};

		#parse out input for username and decode from base64
		local pass3encoded = split_string(array3[1], /:/)[1][1:-2];
		local pass3 = decode_base64(pass3encoded);
		local wordsinpass3 = split_string(pass3, / /);

                #test for common SQL injection words in password
                for (w in wordsinpass3) {
                        if (SQLinjectionRegEx in to_lower(wordsinpass3[w])) {
				SQLscore = SQLscore +1;
                        };
                };

		if (SQLscore > 4) {
			Log::write(WS_MESSAGENOTNORMAL::LOG, urec3);
			NOTICE([$note=WS_MESSAGENOTNORMAL::SQL_Injection_words, $msg = fmt("SQL Injection words found going to %s", c$http$uri), $sub = fmt("username = %s and pass = %s", username3, pass3), $conn=c]);
		};
	};

	if (c$http$uri == CustomURI4) {
		#Log format
                local urec4: WS_MESSAGENOTNORMAL::Info = [$ws_uid=c$uid, $ws_client=c$id$orig_h, $ws_svr=c$id$resp_h, $ws_svrp=c$id$resp_p, $ws_opcode=first2B$op, $ws_maskkey=mkey, $ws_uri=c$http$uri, $ws_data=wsdata];
                c$ws_messagenotnormal = urec4;

                #parse the input into name and comments
                local array4 = split_string(wsdata, /,/);

                #parse out input for name 
                local name4 = split_string1(array4[0], /:/)[1][1:-1];
          
                # test for HTML reg ex in name
                for (r in HTMLRegExs) {
                        if (r in to_lower(name4)) {
                                HTMLscore = HTMLscore + 1;
                        };
                };

	        #parse out input for comments
                local comments4 = split_string1(array4[1], /:/)[1][1:-1];

		# test for HTML reg ex in comments
		for (r in HTMLRegExs) {
			if (r in to_lower(comments4)) {
				HTMLscore = HTMLscore + 1;
			};
		};

                if (HTMLscore > 4) {
                        Log::write(WS_MESSAGENOTNORMAL::LOG, urec4);
                        NOTICE([$note=WS_MESSAGENOTNORMAL::SQL_Injection_words, $msg = fmt("HTML code found going to %s", CustomURI4), $sub = fmt("name = %s and comments = %s", name4, comments4), $conn=c]);
                };
        };
};
}