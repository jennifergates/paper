
signature dpd_ws_client {
    ip-proto == tcp
    payload /(Sec-WebSocket-Key|SEC-WEBSOCKET-KEY)/
    tcp-state originator
    enable "ws"
  }

signature dpd_ws_server {
    ip-proto == tcp
    payload /(Sec-WebSocket-Accept|SEC-WEBSOCKET-ACCEPT)/
    tcp-state responder
    enable "ws"
  }

# Test with: bro -r ndn-tlv-websocket.pcap ws_handshake.evt ws.bro -C -s ./ws.sig  