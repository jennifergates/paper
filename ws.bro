module WS;

event ws_message(c: connection, opcode: int) {
        print opcode;
        print " made it";
}