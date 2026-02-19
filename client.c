// client.c - подключается к серверу и отправляет данные с меткой
// Компиляция: gcc -Wall -o client client.c -lparsec-base -lparsec-mac

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <parsec/mac.h>
#include <parsec/parsec_mac.h>

#define PORT 9001
#define BUFFER_SIZE 1024

// Установка мандатной метки для процесса
void set_process_label(const char *label_text) {
    mac_t *mac = mac_alloc(0);
    if (!mac) {
        perror("mac_alloc");
        return;
    }
    
    if (mac_from_text(mac, label_text) < 0) {
        perror("mac_from_text");
        mac_free(mac);
        return;
    }
    
    if (mac_set_proc(mac) < 0) {
        perror("mac_set_proc");
    } else {
        printf("Метка процесса установлена: %s\n", label_text);
    }
    
    mac_free(mac);
}

// Получение текущей метки процесса
void print_current_label() {
    mac_t *mac = mac_alloc(0);
    if (!mac) return;
    
    if (mac_get_proc() == 0) {
        // Исправлено: добавляем недостающие аргументы
        ssize_t size = 0;
        char *text = mac_to_text(mac, &size, 0);
        int level = mac_get_lev(mac);
        
        printf("Текущая метка процесса: уровень=%d", level);
        if (text) {
            printf(", текст=%s (размер=%zd)", text, size);
            free(text);
        }
        printf("\n");
    }
    
    mac_free(mac);
}

int main(int argc, char *argv[]) {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char *server_ip = "127.0.0.1";
    int port = PORT;
    char *message = "Привет от клиента!";
    char *label = NULL;
    
    // Разбор аргументов
    if (argc > 1) server_ip = argv[1];
    if (argc > 2) port = atoi(argv[2]);
    if (argc > 3) label = argv[3];
    if (argc > 4) message = argv[4];
    
    printf("Клиент запущен\n");
    printf("Сервер: %s:%d\n", server_ip, port);
    
    // Устанавливаем метку процесса, если указана
    if (label) {
        set_process_label(label);
    }
    
    // Показываем текущую метку
    print_current_label();
    
    // Создаем сокет
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    // Настраиваем адрес сервера
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return 1;
    }
    
    // Подключаемся к серверу
    printf("Подключение к серверу...\n");
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }
    
    printf("Подключено к серверу\n");
    
    // Получаем ответ от сервера (сервер должен отправить метку)
    memset(buffer, 0, BUFFER_SIZE);
    int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (bytes > 0) {
        printf("Ответ сервера: %s", buffer);
    }
    
    // Отправляем сообщение серверу
    printf("Отправка сообщения: %s\n", message);
    send(sock, message, strlen(message), 0);
    
    // Получаем подтверждение
    memset(buffer, 0, BUFFER_SIZE);
    bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    if (bytes > 0) {
        printf("Сервер: %s", buffer);
    }
    
    close(sock);
    printf("Соединение закрыто\n");
    
    return 0;
}