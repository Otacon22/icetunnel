#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>


#define MULTICAST_PORT 1900
#define MULTICAST_GROUP "239.255.255.250"
#define MSGBUFSIZE 65536

int sockfd;
struct sockaddr_in addr;
socklen_t addrlen;

void *ssdp_discovery(void *arg)
{
    char *message = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: ssdp:discover\r\nMX: 5\r\nST: ssdp:all\r\n\r\n";
    
    printf("Starting the SSDP discovery thread\n");
    
    while(1){
        if (sendto(sockfd, message, strlen(message), 0, (struct sockaddr *) &addr,
             addrlen) < 0) {
            perror("Sendto error");
            exit(1);
        }
        printf("[!] Sent SSDP discovery message \n");
        sleep(10);
    }
}


int main(int argc, char *argv[])
{
    int nbytes;
    struct ip_mreq mreq;
    char msgbuf[MSGBUFSIZE];
    pthread_t ssdp_tid;

    u_int yes = 1;

    /* create what looks like an ordinary UDP socket */
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	perror("Socket creation error");
	exit(1);
    }


    /* allow multiple sockets to use the same PORT number */
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
	perror("Reusing address failed");
	exit(1);
    }

    /* set up destination address */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);	/* N.B.: differs from sender */
    addr.sin_port = htons(MULTICAST_PORT);

    /* bind to receive address */
    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
	perror("Bind failed");
	exit(1);
    }

    /* use setsockopt() to request that the kernel join a multicast group */
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))
	< 0) {
	perror("Setsocketopt failed");
	exit(1);
    }

    addrlen = sizeof(addr);

    pthread_create(&ssdp_tid, NULL, ssdp_discovery, NULL);

    printf("Starting reading loop\n");

    /* now just enter a read-print loop */
    while (1) {
	if ((nbytes = recvfrom(sockfd, msgbuf, MSGBUFSIZE, 0,
			       (struct sockaddr *) &addr, &addrlen)) < 0) {
	    perror("Recvfrom error");
	    exit(1);
	}
	msgbuf[nbytes] = '\0';
        printf("[!] UPNP MSG ---\n%s\n---END---\n", msgbuf);
    }
    return 0;
}
