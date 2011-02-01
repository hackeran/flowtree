#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>

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

/* The listen loop */
int listen_stop = 0;

/* Network stuff */
#define BINDADDR "132.239.1.114"
#define BINDPORT 2055
#define SOCKBUFF 1024 * 1024 /* 1 MB */
#define BUFFSIZE 65536


/* ===
 * Netflow structs
 * http://www.cisco.com/en/US/docs/net_mgmt/netflow_collection_engine/
 * 3.6/user/guide/format.html#wp1006108
 * ===
 */
struct netflow_v5 {
  uint16_t version;
  uint16_t count;
  time_t uptime;
  struct timespec timestamp;
  uint32_t flow_sequence;
  uint8_t engine_type;
  uint8_t engine_id;
  uint16_t sample_rate;
};

struct netflow_v5_record {
  in_addr_t src_addr;
  in_addr_t dst_addr;
  in_addr_t next_hop;
  uint16_t int_in; 
  uint16_t int_out;
  uint32_t num_packets;
  uint32_t num_bytes;
  time_t start_time;
  time_t end_time;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t pad1;
  uint8_t tcp_flags;
  uint8_t protocol;
  uint8_t tos;
  uint16_t src_as;
  uint16_t dst_as;
  uint8_t src_mask;
  uint8_t dst_mask;
  uint8_t pad2;
};  


/* Function prototypes */
int main(int, char * const []);
void sig_stop_listen(int);
void flow_callback(const struct sockaddr_in *, const u_char *, size_t);


int main(int argc, char * const argv[]) {

  /* === Signal vars === */
  struct sigaction sa_new, sa_old;
  sigset_t sigmask, emptysigmask;

  /* === Socket vars === */
  struct sockaddr_in bind_addrin, peer_addrin;
  in_addr_t bind_addr;
  int sock_fh;
  int setsockbuff = SOCKBUFF, getsockbuff;
  socklen_t sockbufflen = sizeof(getsockbuff);
  socklen_t peeraddrlen = sizeof(peer_addrin);

  /* Network data */
  u_char buffer[BUFFSIZE];
  ssize_t msgsize;
  fd_set read_fd;
  struct timespec sel_timespec;
  int select_ret;

  /* Before we start listening we need to setup a signal
   * handler so we can cleanly exit */
  memset(&sa_new, 0, sizeof(struct sigaction));
  sa_new.sa_handler = sig_stop_listen;
  sigaction(SIGTERM, &sa_new, &sa_old);
  memset(&sa_new, 0, sizeof(struct sigaction));
  sa_new.sa_handler = sig_stop_listen;
  sigaction(SIGINT, &sa_new, &sa_old);

  /* Setup the masks for pselect() */
  sigemptyset(&emptysigmask);
  sigemptyset(&sigmask);
  sigaddset(&sigmask, SIGTERM);
  sigaddset(&sigmask, SIGINT);


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
  while (listen_stop == 0) {

    FD_ZERO(&read_fd);
    FD_SET(sock_fh, &read_fd);
    sel_timespec.tv_sec = 0;
    sel_timespec.tv_nsec = 100000000; /* .1 seconds */

    /* Block signals */
    sigprocmask(SIG_BLOCK, &emptysigmask, NULL);

    /* See if we have data */
    if ((select_ret = pselect(sock_fh + 1, &read_fd, NULL, NULL,
			      &sel_timespec, &emptysigmask)) == -1) {
      if (errno != EINTR) {
	fprintf(stderr, "Call to pselect() failed.\n");
	perror("pselect");
	return 1;
      }
    }

    /* Nothing became ready */
    if (select_ret <= 0) {
      continue;
    }


    /* Select says we have a message, grab it */
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

      flow_callback(&peer_addrin, buffer, msgsize);
    }
    
  }

  close(sock_fh);

  return 0;
}


void flow_callback(const struct sockaddr_in *peer,
		   const u_char *flow, size_t flow_size) {

  

}


void sig_stop_listen(int signo) {
  /* It is dangerous to do much more than this in a signal handler */
  listen_stop = 1;
}
