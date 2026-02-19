// gcc -Wall -lparsec-base -lparsec-mac server.c -o server

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/prctl.h>

/* for pdp_set_EQU_fd */
/* #include <parsec/pdp.h> */

#include <parsec/mac.h>
#include <parsec/parsec_mac.h>
#include <parsec/parsec_integration.h>

#define PORT 9001
#define MAX_QUEUE_LEN 16
#define ANSWER_TO_CLIENT "client parsec label: "

#define REPORT_AND_EXIT(output_number) \
do \
{ \
    fprintf(stderr, "%s, %s, %d: ", __FILE__, __FUNCTION__, __LINE__); \
    perror(NULL); \
    exit(output_number); \
} while(0)

#define REPORT() \
do \
{ \
    fprintf(stderr, "%s, %s, %d: ", __FILE__, __FUNCTION__, __LINE__); \
    perror(NULL); \
} while(0)


/*
 * TCP socket,
 * descriptor and sockaddr
 */
struct TCP_socket
{
    int sd;
    struct sockaddr_in addr;
    unsigned addr_size;
};


/************children process************/

void children_process(int csd)
{
    /*get mac level*/
    parsec_mac_label_t mac_label;
    if(parsec_fstatmac(csd, &mac_label))
        REPORT_AND_EXIT(7);

    /*answer client*/
    char answer[strlen(ANSWER_TO_CLIENT) + 2*sizeof(char)];
    sprintf(answer, ANSWER_TO_CLIENT "%d\n", mac_label.mac.lev);
    if((send(csd, answer, sizeof(answer), 0) != sizeof(answer)))
        REPORT_AND_EXIT(8);
}

/****************************************/


/**************main process**************/

struct TCP_socket create_listen_socket()
{
    /*create listen socket and its sockaddr*/
    struct TCP_socket ls;
    ls.sd = socket(AF_INET, SOCK_STREAM, 0);
    if((ls.sd == -1))
        REPORT_AND_EXIT(3);

    ls.addr.sin_family = AF_INET;
    ls.addr.sin_port = htons(PORT);
    ls.addr.sin_addr.s_addr = htonl(INADDR_ANY);
    ls.addr_size = sizeof(ls.addr);

    /*set port reuse*/
    int optval = 1;
    if((setsockopt(ls.sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1))
        REPORT_AND_EXIT(4);

    /*bind socket with its params*/
    if((bind(ls.sd, (struct sockaddr *)&ls.addr, ls.addr_size) == -1))
        REPORT_AND_EXIT(5);

    /*make socket listen*/
    if((listen(ls.sd, MAX_QUEUE_LEN) == -1))
        REPORT_AND_EXIT(6);

    return ls;
}

void set_caps()
{
    parsec_caps_t pcaps = {0, 0, 0};

    pcaps.cap_permitted |= CAP_TO_MASK(PARSEC_CAP_SETMAC);
    pcaps.cap_permitted |= CAP_TO_MASK(PARSEC_CAP_PRIV_SOCK);
    pcaps.cap_effective |= CAP_TO_MASK(PARSEC_CAP_SETMAC);
    pcaps.cap_effective |= CAP_TO_MASK(PARSEC_CAP_PRIV_SOCK);
    pcaps.cap_inheritable |= CAP_TO_MASK(PARSEC_CAP_PRIV_SOCK);
    pcaps.cap_inheritable |= CAP_TO_MASK(PARSEC_CAP_SETMAC);

    if(prctl(PR_SET_KEEPCAPS, 1))
        REPORT_AND_EXIT(1);

    /*set privilege*/
    if(parsec_cur_caps_set(NULL, &pcaps) < 0)
        REPORT_AND_EXIT(2);
}

int main(void)
{
    set_caps();
    struct TCP_socket ls = create_listen_socket();

    /* alternative set_caps */
    /* pdp_set_EQU_fd(ls.sd); */

    /*main loop*/
    for(;;)
    {
        int csd = accept(ls.sd, (struct sockaddr *)&ls.addr, (socklen_t *)&ls.addr_size);
        if((csd == -1))
        {
            REPORT();
            continue;
        }

        /*create service process */
        int pid = fork();
        if((pid == -1))
            REPORT();

        if((pid == 0))
        {
            /*service process*/
            close(ls.sd);
            children_process(csd);
            exit(0);
        }

        /*main process*/
        close(csd);
        /*check children*/
        do
        {
            pid = wait3(NULL, WNOHANG, NULL);
        } while((pid > 0));
    }

    return 0;
}

/****************************************/