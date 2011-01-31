#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* We want to favor the BSD structs over the Linux ones */
#ifndef __USE_BSD
#define __USE_BSD
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

/* The AVL tree */
#include "pavl.h"


#define BINDADDR "132.239.1.114"
#define BINDPORT 2055
#define SOCKBUFF 1024 * 1024 /* 1 MB */
#define BUFFSIZE 65536

/* Function prototypes */
int main(int, char * const []);


int main(int argc, char * const argv[]) {

  /* Socket vars */
  struct sockaddr_in bind_addrin, peer_addrin;
  in_addr_t bind_addr;
  int sock_fh;
  int setsockbuff = SOCKBUFF, getsockbuff;
  socklen_t sockbufflen = sizeof(getsockbuff);
  socklen_t peeraddrlen = sizeof(peer_addrin);

  /* Network data */
  char buffer[BUFFSIZE];
  ssize_t msgsize;

  /* Make our socket */
  if ((sock_fh = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
    fprintf(stderr, "Creation of socket failed.\n");
    return 1;
  }

  /* Try to set the socket buffer */
  if (setsockopt(sock_fh, SOL_SOCKET, SO_RCVBUF,
		 &setsockbuff, sizeof(setsockbuff)) == -1) {
    fprintf(stderr, "Setting socket receive buffer failed.\n");
    return 1;
  }

  /* Now find out what our socket buffer really is set to */
  if (getsockopt(sock_fh, SOL_SOCKET, SO_RCVBUF,
		 &getsockbuff, &sockbufflen) == -1) {
    fprintf(stderr, "Unable to get socket receive buffer.\n");
    return 1;
  }
  else {
    fprintf(stderr, "Socket receive buffer is %d bytes\n", getsockbuff);
  }

  /* Setup the binding struct */
  bind_addr = inet_addr(BINDADDR);
  memset(&bind_addrin, 0, sizeof(bind_addrin));
  bind_addrin.sin_family = AF_INET;
  bind_addrin.sin_port = htons(BINDPORT);
  bind_addrin.sin_addr.s_addr = bind_addr;

  /* Do the bind */
  if (bind(sock_fh, (const struct sockaddr *)&bind_addrin,
	   sizeof(bind_addrin)) == -1) {
    fprintf(stderr, "Binding to socket failed.\n");
    perror("bind");
    return 1;
  }  


  /* Testing receive, will do better in final code */
  if ((msgsize = recvfrom(sock_fh, buffer, BUFFSIZE, 0,
			  (struct sockaddr *)&peer_addrin,
			  &peeraddrlen)) == -1) {
    fprintf(stderr, "recvfrom() call failed!\n");
    perror("recvfrom");
    return 1;
  }
  else {
    fprintf(stderr, "Got a packet from %s:%d; size=%d\n",
	    inet_ntoa(peer_addrin.sin_addr), ntohs(peer_addrin.sin_port),
	    (int)msgsize);
  }

  close(sock_fh);

  return 0;
}
