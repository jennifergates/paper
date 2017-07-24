module WS_HANDSHAKE;

#event ws_handshake(c: connection, get: string, headers: vector of string) {
event ws_handshake(c: connection, get: string) {
        print get;
#       print headers;
        print " ";
}