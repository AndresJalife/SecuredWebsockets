package com.communication.securedWebsockets.websockets.handler;

import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

public interface TextWebSocketHandler {
    void handleMessage(WebSocketSession incomingSession, TextMessage message);
}
