
signature dpd_ws_client {
    ip-proto == tcp
    payload /(Sec-WebSocket-Key|SEC-WEBSOCKET-KEY)/
    tcp-state originator
    enable "ws"
  }

signature dpd_ws_server {
    ip-proto == tcp
    payload /(Sec-WebSocket-Accept|WEB-SOCKET-ACCEPT)/
    tcp-state responder
    enable "ws"
  }