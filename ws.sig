  signature dpd_ws_client {
    ip-proto == tcp
    payload /^ *(Sec-WebSocket-Key|SEC-WEBSOCKET-KEY) */
    tcp-state originator
  }

signature dpd_ws_server {
    ip-proto == tcp
    payload /^ *(Sec-WebSocket-Key|SEC-WEBSOCKET-ACCEPT) */
    tcp-state responder
    requires-reverse-signature dpd_ws_client
    enable "ws"
  }