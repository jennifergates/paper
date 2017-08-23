# *****************************************************************************
# Bro signature script for WebSockets traffic
# Jennifer Gates
# August 2017
# 
# Defines the signature by the IP protocol TCP, a key identifying factor of the 
# payload as a regular expression, if it is for the traffic originator or 
# responder, and specifies to enable the Spicy WebSockets protocol analyzer 
# *****************************************************************************

signature dpd_ws_client {
    ip-proto == tcp
    payload /(Sec-WebSocket-Key|SEC-WEBSOCKET-KEY)/
    tcp-state originator
    enable "ws_handshake"
  }

signature dpd_ws_server {
    ip-proto == tcp
    payload /(Sec-WebSocket-Accept|SEC-WEBSOCKET-ACCEPT)/
    tcp-state responder
    enable "ws_handshake"
  }