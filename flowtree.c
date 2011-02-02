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
 * Netflow structs and other values
 * http://www.cisco.com/en/US/docs/net_mgmt/netflow_collection_engine/
 * 3.6/user/guide/format.html#wp1006108
 * ===
 */

/* === Netflow v5 === */
struct netflow_v5 {
  uint16_t version;
  uint16_t flow_count;
  uint32_t uptime;
  uint32_t unix_sec;
  uint32_t nsec;
  uint32_t flow_sequence;
  uint8_t engine_type;
  uint8_t engine_id;
  uint16_t sample_rate;
} __attribute__((__packed__));

struct netflow_v5_record {
  in_addr_t src_addr;
  in_addr_t dst_addr;
  in_addr_t next_hop;
  uint16_t int_in; 
  uint16_t int_out;
  uint32_t num_packets;
  uint32_t num_bytes;
  uint32_t start_time;
  uint32_t end_time;
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
  uint16_t pad2;
} __attribute__((__packed__));  


/* ===
 * The unified flow struct that all other formats will be converted to
 * ===
 */
struct unified_flow {
  in_addr_t flow_src;
  struct in_addr src_addr;
  struct in_addr dst_addr;
  uint8_t protocol;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t tcp_flags;
  uint32_t num_packets;
  uint32_t num_bytes;
  time_t start_time;
  time_t end_time;
};


/* ===
 * The flow summary to insert into the flow trees
 * ===
 */
struct flow_source_summary {
  in_addr_t flow_src;
  uint64_t num_packets;
  uint64_t num_bytes;  
  uint64_t num_flows;  
  struct flow_source_summary *next;
};

struct flow_summary {
  uint8_t protocol;
  struct in_addr src_addr;
  struct in_addr dst_addr;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t tcp_flags;
  time_t start_time;
  time_t end_time;
  uint8_t source_count;
  struct flow_source_summary *sources;
};


#define TREES 65536
struct pavl_table *flow_tree[TREES];  

#define ROL16(x, a) ((((x) << (a))  & 0xFFFF) | (((x) & 0xFFFF) >> (16 - (a))))

#define TREEHASH(f) (((((struct flow_summary *)				\
			(f))->src_addr.s_addr) &			\
		      0xFFFF) ^						\
		     (ROL16((((((struct flow_summary *)			\
				(f))->src_addr.s_addr) &		\
			      0xFFFF0000) >> 16), 7)) ^			\
		     ((((struct flow_summary *)				\
			(f))->dst_addr.s_addr) &			\
		      0xFFFF) ^						\
		     (ROL16((((((struct flow_summary *)			\
				(f))->dst_addr.s_addr) &		\
			      0xFFFF0000) >> 16), 13)) ^		\
		     (((struct flow_summary *)				\
		       (f))->src_port) ^				\
		     (ROL16((((struct flow_summary *)			\
			      (f))->dst_port), 3)) ^			\
		     (((struct flow_summary *)(f))->protocol))


/* ===
 * Some stats vars
 * ===
 */
uint64_t stat_new_flows, stat_dup_flows, stat_current_flows;
uint64_t stat_icmp_flows, stat_tcp_flows, stat_udp_flows, stat_other_flows;


/* ===
 * Function prototypes
 * ===
 */
int main(int, char * const []);
void sig_stop_listen(int);
void flow_callback(const struct sockaddr_in *, const u_char *, size_t);
int compare_flows(const void *, const void *, void *);
void * copy_flow(const void *, void *);


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

  /* === Network data vars === */
  u_char buffer[BUFFSIZE];
  ssize_t msgsize;
  fd_set read_fd;
  struct timespec sel_timespec;
  int select_ret;

  /* === Misc vars === */
  int i;

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


  /* Create the flow trees */
  for (i = 0; i < TREES; i++) {
    flow_tree[i] = pavl_create(compare_flows, NULL, NULL);
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
      /*fprintf(stderr, "Got a packet from %s:%d; size=%d\n",
	      inet_ntoa(peer_addrin.sin_addr), ntohs(peer_addrin.sin_port),
	      (int)msgsize);*/

      flow_callback(&peer_addrin, buffer, msgsize);
    }
    
  }

  close(sock_fh);

  return 0;
}


void flow_callback(const struct sockaddr_in *peer,
		   const u_char *flow, size_t flow_size) {

  struct unified_flow current_flow;
  struct netflow_v5_record * record_v5;

  /* ===
   * Flow tree and summary vars
   * ===
   */
  struct flow_summary cur_flow_summary;
  struct flow_summary *flow_summary_copy;
  struct flow_summary **flow_summary_probe;
  struct flow_source_summary *new_flow_source_summary;
  struct flow_source_summary **cur_flow_source_summary;
  int tree_num;

  /* ===
   * Misc vars
   * ===
   */
  int records = 0;
  int i;
  struct in_addr temp_inaddr_src, temp_inaddr_dst;
  int source_updated;

  /* ===
   * Check if it looks like we have a netflow v5 record
   * Other version of netflow / sflow / jflow will be handled later
   * === 
   */
  if (flow_size < sizeof(struct netflow_v5)) {
      fprintf(stderr, "not big enough\n");
    return;
  }

  if (ntohs(((struct netflow_v5 *)flow)->version) != 5) {
    fprintf(stderr, "not v5\n");
    return;
  }

  records = ntohs(((struct netflow_v5 *)flow)->flow_count);
  if (flow_size != sizeof(struct netflow_v5) +
      (records * sizeof(struct netflow_v5_record))) {
    
    fprintf(stderr,
	    "wrong size; flow_count=%d; flow_size=%d; v5=%d, v5r=%d\n",
	    (int)ntohs(((struct netflow_v5 *)flow)->flow_count),
	    (int)flow_size, (int)sizeof(struct netflow_v5),
	    (int)sizeof(struct netflow_v5_record));
    return;
  }
  /*fprintf(stderr, "Got a valid looking netflow v5 packet\n");*/
  

  /* ===
   * Looks like valid netflow v5 so parse it
   * === 
   */
  
/* Now loop through the records */
  record_v5 = (struct netflow_v5_record *)(flow + sizeof(struct netflow_v5));
  for (i = 0; i < records; i++) {
    
    /* Fill in our current flow info */
    current_flow.flow_src = peer->sin_addr.s_addr;
    current_flow.src_addr.s_addr = ntohl(record_v5[i].src_addr);
    current_flow.dst_addr.s_addr = ntohl(record_v5[i].dst_addr);
    current_flow.protocol = record_v5[i].protocol;
    current_flow.src_port = ntohs(record_v5[i].src_port);
    current_flow.dst_port = ntohs(record_v5[i].dst_port);
    current_flow.tcp_flags = record_v5[i].tcp_flags;
    current_flow.num_packets = ntohl(record_v5[i].num_packets);
    current_flow.num_bytes = ntohl(record_v5[i].num_bytes);


    /* Time calculations require a bit of math, namely
     * curtime - ((uptime - start) / 1000)
     */
    current_flow.start_time = ntohl(((struct netflow_v5 *)flow)->unix_sec) -
      (((ntohl(((struct netflow_v5 *)flow)->uptime) -		\
	 ntohl(record_v5[i].start_time)) & 0xFFFFFFFF) / 1000);
    current_flow.end_time = ntohl(((struct netflow_v5 *)flow)->unix_sec) -
      (((ntohl(((struct netflow_v5 *)flow)->uptime) -		\
	 ntohl(record_v5[i].end_time)) & 0xFFFFFFFF) / 1000);

    temp_inaddr_src.s_addr = htonl(current_flow.src_addr.s_addr);
    temp_inaddr_dst.s_addr = htonl(current_flow.dst_addr.s_addr);

    /*
    fprintf(stderr, "Got proto %d flow from %s:%d",
	    current_flow.protocol,
	    inet_ntoa(temp_inaddr_src),
	    current_flow.src_port);
    fprintf(stderr, " to %s:%d (%u to %u)\n",
	    inet_ntoa(temp_inaddr_dst),
	    current_flow.dst_port,
	    (unsigned int)current_flow.start_time,
	    (unsigned int)current_flow.end_time);
    */


  /* ===
   * Now insert or update the flow in the tree
   * === 
   */

    /* Setup the current flow summary struct */
    cur_flow_summary.protocol = current_flow.protocol;
    cur_flow_summary.src_addr = current_flow.src_addr;
    cur_flow_summary.dst_addr = current_flow.dst_addr;
    cur_flow_summary.src_port = current_flow.src_port;
    cur_flow_summary.dst_port = current_flow.dst_port;
    cur_flow_summary.tcp_flags = current_flow.tcp_flags;
    cur_flow_summary.start_time = current_flow.start_time;
    cur_flow_summary.end_time = current_flow.end_time;
    cur_flow_summary.source_count = 1;
    cur_flow_summary.sources = NULL;

    /* Now make an insert-ready copy */
    flow_summary_copy = copy_flow(&cur_flow_summary, NULL);

    /* Figure out which tree to use */
    tree_num = TREEHASH(flow_summary_copy);
   
    /* Search and possibly insert this flow */
    flow_summary_probe =
      (struct flow_summary **)pavl_probe(flow_tree[tree_num],
					 flow_summary_copy);

    /* Figure out what happened */
    if (flow_summary_probe == NULL) {
      fprintf(stderr, "There was a failure inserting the flow into tree.\n");
      return;
    }


    /* Now find out if it was already there or we just inserted it */
    if (*flow_summary_probe == flow_summary_copy) {
      /* well that was easy, nothing fancy to do now */

      /* should increment new flow counters */
      stat_new_flows++;
      stat_current_flows++;
      if ((*flow_summary_probe)->protocol == 17) {
	stat_udp_flows++;
      }
      else if ((*flow_summary_probe)->protocol == 6) {
	stat_tcp_flows++;
      }
      else if ((*flow_summary_probe)->protocol == 1) {
	stat_icmp_flows++;
      }
      else {
	stat_other_flows++;
      }
    }
    else {
      /* fprintf(stderr, "Flow already in tree; flows=%u\n",
	      (unsigned int)pavl_count(flow_tree[tree_num]));
      */

      /* update the stats */
      stat_dup_flows++;

      
      /* update some summay stuff about this flow */
      (*flow_summary_probe)->tcp_flags |= flow_summary_copy->tcp_flags;
      if ((*flow_summary_probe)->start_time > flow_summary_copy->start_time) {
	(*flow_summary_probe)->start_time = flow_summary_copy->start_time;
      }
      if ((*flow_summary_probe)->end_time < flow_summary_copy->end_time) {
	(*flow_summary_probe)->end_time = flow_summary_copy->end_time;
      }
      
      /*
      fprintf(stderr, "Sources: %d\n",
	      (*flow_summary_probe)->source_count); */
      
      /* We don't need the copy anymore */
      free(flow_summary_copy);
      flow_summary_copy = NULL;
    }

    /*
    fprintf(stderr, "Stats: new=%lu, dup=%lu, cur=%lu, tcp=%lu, "
	    "udp=%lu, icmp=%lu; oth=%lu\n",
	    stat_new_flows, stat_dup_flows, stat_current_flows,
	    stat_tcp_flows, stat_udp_flows, stat_icmp_flows,
	    stat_other_flows);
    */

  /* ===
   * The flow is now in the tree, we need to update the flow source info
   * === 
   */

    /* Find the spot to update or where to insert */
    source_updated = 0;
    cur_flow_source_summary = &((*flow_summary_probe)->sources);
    while (*cur_flow_source_summary != NULL) {

      if (current_flow.flow_src < (*cur_flow_source_summary)->flow_src) {
	/* We are going to need to insert a new flow source here */
	break;
      }
      else if (current_flow.flow_src == (*cur_flow_source_summary)->flow_src) {
	/* We need to update this flow source */
	(*cur_flow_source_summary)->num_packets += current_flow.num_packets;
	(*cur_flow_source_summary)->num_bytes += current_flow.num_bytes;
	(*cur_flow_source_summary)->num_flows += 1;

	source_updated = 1;
	break;
      }
      else {
	/* Go on */
	cur_flow_source_summary = &((*cur_flow_source_summary)->next);
      }
    }

    /* If we didn't do an update then we need to insert a new flow source */
    if (source_updated == 0) {
      new_flow_source_summary = malloc(sizeof(struct flow_source_summary));

      /* Set the new fields */
      new_flow_source_summary->flow_src = current_flow.flow_src;
      new_flow_source_summary->num_packets = current_flow.num_packets;
      new_flow_source_summary->num_bytes = current_flow.num_bytes;
      new_flow_source_summary->num_flows = 1;
      
      /* Now insert this into the list */
      new_flow_source_summary->next = *cur_flow_source_summary;
      *cur_flow_source_summary = new_flow_source_summary;

      /* Update the source count for the flow */
      (*flow_summary_probe)->source_count += 1;
    }	

  }
}


void sig_stop_listen(int signo) {
  /* It is dangerous to do much more than this in a signal handler */
  listen_stop = 1;
}


int compare_flows(const void *a, const void *b, void *param) {

  const struct flow_summary *fa = a;
  const struct flow_summary *fb = b;

  if (fa->protocol > fb->protocol) {
    return 1;
  }
  else if (fa->protocol < fb->protocol) {
    return -1;
  }
  else if (fa->src_addr.s_addr > fb->src_addr.s_addr) {
    return 1;
  }
  else if (fa->src_addr.s_addr < fb->src_addr.s_addr) {
    return -1;
  }
  else if (fa->dst_addr.s_addr > fb->dst_addr.s_addr) {
    return 1;
  }
  else if (fa->dst_addr.s_addr < fb->dst_addr.s_addr) {
    return -1;
  }
  else if (fa->src_port > fb->src_port) {
    return 1;
  }
  else if (fa->src_port < fb->src_port) {
    return -1;
  }
  else if (fa->dst_port > fb->dst_port) {
    return 1;
  }
  else if (fa->dst_port < fb->dst_port) {
    return -1;
  }
  else {
    return 0;
  }
}


void * copy_flow(const void *a, void *param) {
  
  struct flow_summary * f = malloc(sizeof(struct flow_summary));

  if (f == NULL) {
    return NULL;
  }
  else {
    memcpy(f, a, sizeof(struct flow_summary));
  }
  
  return f;
}
