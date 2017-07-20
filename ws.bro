module WS;

event ws_message(c: connection, op: int ) {
        print op;
        print " made it";
}