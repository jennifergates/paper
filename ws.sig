
signature dpd_ws_client {
    ip-proto == tcp
    payload /(Sec-WebSocket-Key|SEC-WEBSOCKET-KEY)/
    tcp-state originator
    enable "ws_handshake"
  }

signature dpd_ws_server {
    ip-proto == tcp
    payload /(Sec-WebSocket-Accept|WEB-SOCKET-ACCEPT)/
    tcp-state responder
    enable "ws_handshake"
  }

# Test with: bro -r ndn-tlv-websocket.pcap ws_handshake.evt ws.bro -C -s ./ws.sig  