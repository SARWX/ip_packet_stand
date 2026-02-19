// server.c - принимает соединения и показывает метку клиента
// Компиляция: gcc -Wall -o server server.c -lparsec-base -lparsec-mac

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include <parsec/mac.h>
#include <parsec/parsec_mac.h>

#define PORT 9001
#define MAX_QUEUE_LEN 16
#define BUFFER_SIZE 1024

void handle_client(int client_sock, struct sockaddr_in *client_addr) {
    char buffer[BUFFER_SIZE];
    parsec_mac_label_t mac_label;
    
    printf("Новое соединение от %s:%d\n", 
           inet_ntoa(client_addr->sin_addr), 
           ntohs(client_addr->sin_port));
    
    // Получаем мандатную метку клиента через сокет
    if (parsec_fstatmac(client_sock, &mac_label) == 0) {
        printf("Метка клиента: уровень=%d\n", mac_label.mac.lev);
        
        // Отправляем информацию о метке обратно клиенту
        char response[256];
        snprintf(response, sizeof(response), 
                 "Ваша мандатная метка: уровень %d\n", 
                 mac_label.mac.lev);
        send(client_sock, response, strlen(response), 0);
    } else {
        perror("parsec_fstatmac");
        const char *msg = "Не удалось получить метку\n";
        send(client_sock, msg, strlen(msg), 0);
    }
    
    // Принимаем данные от клиента
    int bytes = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("Получено от клиента: %s\n", buffer);
        
        // Отправляем подтверждение
        send(client_sock, "Данные получены сервером\n", 26, 0);
    }
    
    close(client_sock);
    printf("Соединение закрыто\n");
}

int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // Создаем сокет
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket");
        return 1;
    }
    
    // Настройка адреса
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    
    // Разрешаем переиспользование порта
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Привязываем сокет
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_sock);
        return 1;
    }
    
    // Начинаем прослушивание
    if (listen(server_sock, MAX_QUEUE_LEN) < 0) {
        perror("listen");
        close(server_sock);
        return 1;
    }
    
    printf("Сервер запущен на порту %d\n", PORT);
    printf("Ожидание соединений...\n");
    
    while (1) {
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("accept");
            continue;
        }
        
        // Обрабатываем клиента
        handle_client(client_sock, &client_addr);
    }
    
    close(server_sock);
    return 0;
}