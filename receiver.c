#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <parsec/parsec.h>
#include <parsec/mac.h>

#define BUFFER_SIZE 65536
#define DEFAULT_PORT 8888

// Функция для получения метки пакета
int get_packet_label(int sock, mac_t **mac) {
    // Получаем метку через PARSEC
    *mac = mac_alloc(MAC_ATTR_LEV | MAC_ATTR_TYPE | MAC_ATTR_CAT);
    if (!*mac) {
        perror("mac_alloc");
        return -1;
    }
    
    // Пытаемся получить метку сокета
    if (parsec_getmac(sock, *mac) < 0) {
        perror("parsec_getmac");
        mac_free(*mac);
        return -1;
    }
    
    return 0;
}

// Функция для проверки доступа к пакету
int check_packet_access(mac_t *packet_mac) {
    mac_t *proc_mac;
    int result;
    
    // Получаем метку текущего процесса
    proc_mac = mac_alloc(MAC_ATTR_LEV | MAC_ATTR_TYPE | MAC_ATTR_CAT);
    if (!proc_mac) {
        perror("mac_alloc");
        return -1;
    }
    
    if (mac_get_proc(proc_mac) < 0) {
        perror("mac_get_proc");
        mac_free(proc_mac);
        return -1;
    }
    
    // Проверяем, может ли процесс прочитать пакет с такой меткой
    result = mac_permit(proc_mac, packet_mac, MAC_READ);
    
    if (result > 0) {
        printf("Доступ разрешен (мандатный контроль)\n");
    } else if (result == 0) {
        printf("Доступ ЗАПРЕЩЕН (мандатный контроль)\n");
    } else {
        perror("mac_permit");
    }
    
    mac_free(proc_mac);
    return result;
}

// Функция для преобразования метки в текст
void print_mac_attributes(mac_t *mac) {
    char *text;
    int level;
    
    // Получаем уровень
    level = mac_get_lev(mac);
    printf("  Уровень: %d\n", level);
    
    // Получаем текстовое представление
    text = mac_to_text(mac);
    if (text) {
        printf("  Текстовая метка: %s\n", text);
        free(text);
    }
}

int main(int argc, char *argv[]) {
    int sock;
    char buffer[BUFFER_SIZE];
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int port = DEFAULT_PORT;
    int packet_count = 0;
    
    if (argc > 1) port = atoi(argv[1]);
    
    printf("Приемник запущен на порту %d\n", port);
    printf("Ожидание пакетов с мандатными метками...\n");
    
    // Инициализируем PARSEC
    if (parsec_open() < 0) {
        perror("parsec_open");
        return 1;
    }
    
    // Создаем raw socket для приема всех пакетов
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("socket");
        parsec_close();
        return 1;
    }
    
    // Привязываем сокет к интерфейсу
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sock);
        parsec_close();
        return 1;
    }
    
    // Получаем метку процесса
    mac_t *proc_mac = mac_alloc(MAC_ATTR_LEV | MAC_ATTR_TYPE | MAC_ATTR_CAT);
    if (proc_mac && mac_get_proc(proc_mac) == 0) {
        printf("\nМетка процесса-приемника:\n");
        print_mac_attributes(proc_mac);
        mac_free(proc_mac);
    }
    
    printf("\n--- Начинаем прослушивание ---\n\n");
    
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        
        // Принимаем пакет
        int packet_size = recvfrom(sock, buffer, BUFFER_SIZE, 0,
                                   (struct sockaddr *)&client_addr, &client_len);
        
        if (packet_size < 0) {
            perror("recvfrom");
            continue;
        }
        
        packet_count++;
        
        // Извлекаем IP-заголовок
        struct iphdr *iph = (struct iphdr *)buffer;
        
        // Проверяем, что это UDP пакет и на нужный порт
        if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr *)(buffer + (iph->ihl * 4));
            
            // Проверяем порт назначения
            if (ntohs(udph->dest) == port) {
                char *data = buffer + (iph->ihl * 4) + sizeof(struct udphdr);
                int data_len = ntohs(udph->len) - sizeof(struct udphdr);
                
                printf("\n=== Пакет #%d ===\n", packet_count);
                printf("Источник: %s:%d\n", 
                       inet_ntoa(*(struct in_addr *)&iph->saddr),
                       ntohs(udph->source));
                printf("Назначение: %s:%d\n", 
                       inet_ntoa(*(struct in_addr *)&iph->daddr),
                       ntohs(udph->dest));
                
                // Получаем метку пакета
                mac_t *packet_mac;
                if (get_packet_label(sock, &packet_mac) == 0) {
                    printf("Метка пакета:\n");
                    print_mac_attributes(packet_mac);
                    
                    // Проверяем доступ
                    check_packet_access(packet_mac);
                    
                    mac_free(packet_mac);
                } else {
                    printf("Не удалось получить метку пакета\n");
                }
                
                // Выводим данные
                if (data_len > 0 && data_len < 1000) {
                    printf("Данные (%d байт): %.*s\n", data_len, data_len, data);
                }
                
                printf("========================\n");
            }
        }
    }
    
    close(sock);
    parsec_close();
    return 0;
}