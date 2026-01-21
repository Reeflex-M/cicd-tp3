package com.devops;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public final class MiniApiServer {

    public static void main(String[] args) throws Exception {
        int port = 8080;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        // GET /health -> {"status":"UP"}
        server.createContext("/health", exchange -> {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }
            sendJson(exchange, 200, "{\"status\":\"UP\"}");
        });

        // GET /api/orders -> list of demo orders
        server.createContext("/api/orders", exchange -> {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }

            String ordersJson = """
        [
          { "id": 1, "product": "Laptop", "price": 1200.0 },
          { "id": 2, "product": "Mouse",  "price": 25.0 }
        ]
        """;

            sendJson(exchange, 200, ordersJson);
        });


        // Petite page HTML racine (utile pour ZAP, et pour montrer qu'on a aussi du "web")
        server.createContext("/", exchange -> {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendText(exchange, 405, "Method Not Allowed");
                return;
            }
            String html = """
                    <!doctype html>
                    <html lang="en">
                      <head><meta charset="utf-8"><title>Mini API</title></head>
                      <body>
                        <h1>Mini API Server</h1>
                        <ul>
                          <li><a href="/health">/health</a></li>
                          <li><a href="/api/orders">/api/orders</a></li>
                        </ul>
                      </body>
                    </html>
                    """;
            sendHtml(exchange, 200, html);
        });

        server.setExecutor(null);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Stopping server...");
            server.stop(0);
        }));

        server.start();
        System.out.println("Mini API Server started on http://localhost:" + port);
        // Keep process alive
        Thread.currentThread().join();
    }

    private static void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static void sendText(HttpExchange exchange, int status, String text) throws IOException {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static void sendHtml(HttpExchange exchange, int status, String html) throws IOException {
        byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
