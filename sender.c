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

#define BUFFER_SIZE 4096
#define DEFAULT_PORT 8888

// Структура для хранения метки
typedef struct {
    uint32_t mcat_low;
    uint32_t mcat_high;
} mac_label_t;

// Функция для установки мандатной метки процессу
int set_process_label(const char* level_name) {
    mac_t *mac;
    
    // Инициализируем библиотеку PARSEC
    if (parsec_open() < 0) {
        perror("parsec_open");
        return -1;
    }
    
    // Создаем новую метку
    mac = mac_alloc(MAC_ATTR_TYPE|MAC_ATTR_LEV|MAC_ATTR_CAT);
    if (!mac) {
        perror("mac_alloc");
        parsec_close();
        return -1;
    }
    
    // Устанавливаем уровень из текстового представления
    if (mac_from_text(mac, level_name) < 0) {
        perror("mac_from_text");
        mac_free(mac);
        parsec_close();
        return -1;
    }
    
    // Устанавливаем метку текущему процессу
    if (mac_set_proc(mac) < 0) {
        perror("mac_set_proc");
        mac_free(mac);
        parsec_close();
        return -1;
    }
    
    printf("Метка процесса установлена: %s\n", level_name);
    
    mac_free(mac);
    parsec_close();
    return 0;
}

// Функция расчета контрольной суммы
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main(int argc, char *argv[]) {
    int sock;
    char buffer[BUFFER_SIZE];
    struct sockaddr_in dest_addr;
    mac_label_t label;
    char *dest_ip = "127.0.0.1";
    int dest_port = DEFAULT_PORT;
    char *level_name = "1";
    
    // Разбор аргументов командной строки
    if (argc > 1) dest_ip = argv[1];
    if (argc > 2) dest_port = atoi(argv[2]);
    if (argc > 3) level_name = argv[3];
    
    printf("Отправитель: цель %s:%d, метка %s\n", dest_ip, dest_port, level_name);
    
    // Устанавливаем метку процессу (опционально)
    // set_process_label(level_name);
    
    // Создаем raw socket
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    // Разрешаем формировать IP-заголовок самостоятельно
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(sock);
        return 1;
    }
    
    // Инициализируем PARSEC
    if (parsec_open() < 0) {
        perror("parsec_open");
        close(sock);
        return 1;
    }
    
    // Создаем метку для пакета
    mac_t *mac = mac_alloc(MAC_ATTR_LEV);
    if (!mac) {
        perror("mac_alloc");
        parsec_close();
        close(sock);
        return 1;
    }
    
    // Устанавливаем уровень метки из текста
    if (mac_from_text(mac, level_name) < 0) {
        perror("mac_from_text");
        mac_free(mac);
        parsec_close();
        close(sock);
        return 1;
    }
    
    // Получаем числовые значения уровня
    label.mcat_low = mac_get_lev(mac);
    label.mcat_high = mac_get_lev(mac);
    
    printf("Метка пакета: низкий=%u, высокий=%u\n", label.mcat_low, label.mcat_high);
    
    // Устанавливаем метку для отправляемых пакетов через сокет
    // Используем системный вызов PARSEC (если доступен)
    if (parsec_setmac(sock, mac) < 0) {
        // Если не сработало, пробуем через setsockopt с IP_SECOPT
        #ifdef IP_SECOPT
        if (setsockopt(sock, IPPROTO_IP, IP_SECOPT, &label, sizeof(label)) < 0) {
            perror("setsockopt IP_SECOPT");
        } else {
            printf("Метка установлена через IP_SECOPT\n");
        }
        #else
        perror("parsec_setmac");
        #endif
    } else {
        printf("Метка установлена через parsec_setmac\n");
    }
    
    // Формируем пакет
    memset(buffer, 0, BUFFER_SIZE);
    
    struct iphdr *iph = (struct iphdr *)buffer;
    struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct iphdr));
    char *data = buffer + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    // Данные для отправки
    sprintf(data, "Тестовый пакет с меткой %s (уровень %u)", 
            level_name, label.mcat_low);
    
    int data_len = strlen(data);
    int packet_len = sizeof(struct iphdr) + sizeof(struct udphdr) + data_len;
    
    // Заполняем IP-заголовок
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(packet_len);
    iph->id = htons(getpid());
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr("127.0.0.1");
    iph->daddr = inet_addr(dest_ip);
    
    // Контрольная сумма IP
    iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));
    
    // Заполняем UDP-заголовок
    udph->source = htons(12345);
    udph->dest = htons(dest_port);
    udph->len = htons(sizeof(struct udphdr) + data_len);
    udph->check = 0;  // Для UDP контрольная сумма опциональна
    
    // Адрес назначения
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = iph->daddr;
    dest_addr.sin_port = htons(dest_port);
    
    // Отправляем пакет
    int sent = sendto(sock, buffer, packet_len, 0,
                      (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    
    if (sent < 0) {
        perror("sendto");
    } else {
        printf("Отправлено %d байт с меткой (low=%u, high=%u)\n", 
               sent, label.mcat_low, label.mcat_high);
        printf("Данные: %s\n", data);
    }
    
    mac_free(mac);
    parsec_close();
    close(sock);
    
    return 0;
}