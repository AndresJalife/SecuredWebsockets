package com.communication.securedWebsockets.websockets.handler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.util.HashMap;
import java.util.Map;

@Component @Slf4j
public class MessageHandler extends TextWebSocketHandler {
    private final Map<String, WebSocketSession> sessions = new HashMap<>();

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        sessions.put(session.getId(), session);
    }

    @Override
    protected void handleTextMessage(WebSocketSession _incomingSession, TextMessage message){
        for (WebSocketSession session : sessions.values()) {
            if(!session.isOpen()){
                sessions.remove(session.getId());
                return;
            }
            try {
                session.sendMessage(message);
            } catch (Exception e) {
                log.error("----- Exception catched while sending message through websocket -----");
                e.printStackTrace();
            }
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        sessions.remove(session.getId());
    }
}
