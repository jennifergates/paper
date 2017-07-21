module WS;

event ws_message(c: connection, op: int, m: int ) {
	print op;
	print m;
	print " made it";
} 

event ws_masked(c: connection, mk: int, d: string) {
	print mk;
	print d;
}