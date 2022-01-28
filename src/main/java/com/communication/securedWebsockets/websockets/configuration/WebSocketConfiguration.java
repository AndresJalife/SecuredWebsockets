package com.communication.securedWebsockets.websockets.configuration;

import com.communication.securedWebsockets.websockets.handler.MessageHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

/**
 * Configuración de los websockets.
 * Se definen los endpoints.
 */
@Configuration
@EnableWebSocket
public class WebSocketConfiguration implements WebSocketConfigurer {

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry){
        registry.addHandler(getMessageHandler(), "/ws").setAllowedOrigins("*");
    }

    @Bean
    public MessageHandler getMessageHandler(){
        return new MessageHandler();
    }
}