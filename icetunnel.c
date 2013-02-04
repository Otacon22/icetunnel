/* 
 * Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 * Copyright (C) 2013 Daniele Iamartino <danieleiamartino at gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <pjlib.h>
#include <pjlib-util.h>
#include <pjnath.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>   /* IP addresses conversion utilities */
#include <sys/socket.h>  /* socket constants, types and functions */
#include <errno.h>
#include <unistd.h>

pthread_mutex_t lock_on_ice_init, lock_on_buffer_data;
pthread_t sdp_tcp_server_tid;

#define MAXLINE 65536
#define BACKLOG 10

char buffer_data[MAXLINE] = {0};
char recv_buff[MAXLINE] = {0};
int tool_sock;
int tool_sock_conn;
struct sockaddr_in tool_endpoint_addr;

int sdp_tcp_server_port = 7001;
int tool_server_port = 7002;
int tool_client_port = 7003;
char *tool_client_address = "127.0.0.1";

int sdp_conn_fd; /* SDP TCP connection socket, shared for sending errors */

int verbose = 0; /* Verbose level */

enum connection_status {
    ESTABLISHED,
    CLOSED
} tool_conn_status = CLOSED;

enum working_modes {
    UDP_MODE,
    TCP_MODE
} tool_mode = UDP_MODE;

enum control_mode {
    OFFERER,
    ANSWERER
} tool_control_mode = OFFERER;



#define THIS_FILE   "icetunnel"

/*
 * STUN keep-alive time, default value 15 seconds.
 * It prevents the NATs from closing idle-connections.
 */
#define KA_INTERVAL 15


/* This is our global variables */
static struct app_t
{
    /* Command line options are stored here */
    struct options
    {
	    unsigned    comp_cnt;
	    pj_str_t    ns;
	    int	    max_host;
	    pj_bool_t   regular;
	    pj_str_t    stun_srv;
	    pj_str_t    turn_srv;
	    pj_bool_t   turn_tcp;
	    pj_str_t    turn_username;
	    pj_str_t    turn_password;
	    pj_bool_t   turn_fingerprint;
	    unsigned   max_pkt_size;
    } opt;

    /* Our global variables */
    pj_caching_pool	 cp;
    pj_pool_t		*pool;
    pj_thread_t		*thread;
    pj_thread_t     *sdp_thread;
    pj_bool_t		 thread_quit_flag;
    pj_ice_strans_cfg	 ice_cfg;
    pj_ice_strans	*icest;

    /* Variables to store parsed remote ICE info */
    struct rem_info
    {
	    char		 ufrag[80];
	    char		 pwd[80];
	    unsigned	 comp_cnt;
	    pj_sockaddr	 def_addr[PJ_ICE_MAX_COMP];
	    unsigned	 cand_cnt;
	    pj_ice_sess_cand cand[PJ_ICE_ST_MAX_CAND];
    } rem;

} icedemo;

static int socketWrite(int socket_fd, char *buffer, size_t bufsize){
    int nleft = bufsize;
    int nwritten;

    while (nleft > 0) {
        if ((nwritten = write(socket_fd, buffer, nleft)) < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                return nwritten; /* Return the error */
            }
        }
        nleft -= nwritten;
        buffer += nwritten;
    }
    return 0;
}

static int socketRead(int socket_fd, char *buffer, size_t bufsize){
    return read(socket_fd, buffer, bufsize);
}


/* Utility to display error messages */
static void icedemo_perror(const char *title, pj_status_t status)
{
    char errmsg[PJ_ERR_MSG_SIZE];

    pj_strerror(status, errmsg, sizeof(errmsg));
    PJ_LOG(1,(THIS_FILE, "%s: %s", title, errmsg));
}

/*
 * Utility: display error message and exit application (usually
 * because of fatal error).
 */
static void err_exit(const char *title, pj_status_t status)
{
    if (status != PJ_SUCCESS) {
	    icedemo_perror(title, status);
    }
    PJ_LOG(3,(THIS_FILE, "Shutting down.."));

    if (icedemo.icest)
	    pj_ice_strans_destroy(icedemo.icest);
    
    pj_thread_sleep(500);

    icedemo.thread_quit_flag = PJ_TRUE;
    if (icedemo.thread) {
	    pj_thread_join(icedemo.thread);
	    pj_thread_destroy(icedemo.thread);
    }

    if (icedemo.ice_cfg.stun_cfg.ioqueue)
	    pj_ioqueue_destroy(icedemo.ice_cfg.stun_cfg.ioqueue);

    if (icedemo.ice_cfg.stun_cfg.timer_heap)
	    pj_timer_heap_destroy(icedemo.ice_cfg.stun_cfg.timer_heap);

    pj_caching_pool_destroy(&icedemo.cp);

    pj_shutdown();


    exit(status != PJ_SUCCESS);
}

#define CHECK(expr)	status=expr; \
			if (status!=PJ_SUCCESS) { \
			    err_exit(#expr, status); \
			}

/*
 * This function checks for events from both timer and ioqueue (for
 * network events). It is invoked by the worker thread.
 */
static pj_status_t handle_events(unsigned max_msec, unsigned *p_count)
{
    enum { MAX_NET_EVENTS = 1 };
    pj_time_val max_timeout = {0, 0};
    pj_time_val timeout = { 0, 0};
    unsigned count = 0, net_event_count = 0;
    int c;

    max_timeout.msec = max_msec;

    /* Poll the timer to run it and also to retrieve the earliest entry. */
    timeout.sec = timeout.msec = 0;
    c = pj_timer_heap_poll( icedemo.ice_cfg.stun_cfg.timer_heap, &timeout );
    if (c > 0)
	    count += c;

    /* timer_heap_poll should never ever returns negative value, or otherwise
     * ioqueue_poll() will block forever!
     */
    pj_assert(timeout.sec >= 0 && timeout.msec >= 0);
    if (timeout.msec >= 1000) timeout.msec = 999;

    /* compare the value with the timeout to wait from timer, and use the 
     * minimum value. 
    */
    if (PJ_TIME_VAL_GT(timeout, max_timeout))
	    timeout = max_timeout;

    /* Poll ioqueue. 
     * Repeat polling the ioqueue while we have immediate events, because
     * timer heap may process more than one events, so if we only process
     * one network events at a time (such as when IOCP backend is used),
     * the ioqueue may have trouble keeping up with the request rate.
     *
     * For example, for each send() request, one network event will be
     *   reported by ioqueue for the send() completion. If we don't poll
     *   the ioqueue often enough, the send() completion will not be
     *   reported in timely manner.
     */
    do {
	    c = pj_ioqueue_poll( icedemo.ice_cfg.stun_cfg.ioqueue, &timeout);
	    if (c < 0) {
	        pj_status_t err = pj_get_netos_error();
	        pj_thread_sleep(PJ_TIME_VAL_MSEC(timeout));
	        if (p_count)
		    *p_count = count;
	        return err;
	    } else if (c == 0) {
	        break;
	    } else {
	        net_event_count += c;
	        timeout.sec = timeout.msec = 0;
	    }
    } while (c > 0 && net_event_count < MAX_NET_EVENTS);

    count += net_event_count;
    if (p_count)
	    *p_count = count;

    return PJ_SUCCESS;

}

/*
 * This is the worker thread that polls event in the background.
 */
static int icedemo_worker_thread(void *unused)
{
    PJ_UNUSED_ARG(unused);

    while (!icedemo.thread_quit_flag) {
	    handle_events(500, NULL);
    }

    return 0;
}

/*
 * This is the callback that is registered to the ICE stream transport to
 * receive notification about incoming data. By "data" it means application
 * data such as RTP/RTCP, and not packets that belong to ICE signaling (such
 * as STUN connectivity checks or TURN signaling).
 */
static void cb_on_rx_data(pj_ice_strans *ice_st,
			  unsigned comp_id, 
			  void *pkt, pj_size_t size,
			  const pj_sockaddr_t *src_addr,
			  unsigned src_addr_len)
{
    char ipstr[PJ_INET6_ADDRSTRLEN+10];
    int nwritten;

    PJ_UNUSED_ARG(ice_st);
    PJ_UNUSED_ARG(src_addr_len);
    PJ_UNUSED_ARG(pkt);

    if (tool_mode == UDP_MODE) {
        if ( sendto(tool_sock, (char*)pkt, (unsigned)size, 0,
               (struct sockaddr *)&tool_endpoint_addr, sizeof(tool_endpoint_addr)) < 0) {
            perror("UDP socket sendto error");
            exit(-1);
        }
    }
    else if (tool_conn_status == ESTABLISHED) {
        if (socketWrite(tool_sock_conn, (char *)pkt, (unsigned)size) < 0)
            perror("error on socket write");
    }
}

/*
 * This is the callback that is registered to the ICE stream transport to
 * receive notification about ICE state progression.
 */
static void cb_on_ice_complete(pj_ice_strans *ice_st, 
			       pj_ice_strans_op op,
			       pj_status_t status)
{
    const char *opname = 
	(op==PJ_ICE_STRANS_OP_INIT? "initialization" :
	    (op==PJ_ICE_STRANS_OP_NEGOTIATION ? "negotiation" : "unknown_op"));
    char *message = "ICE negotiation completed\n";
    char *fail_message = "Error ";

    if (status == PJ_SUCCESS) {
    	PJ_LOG(3,(THIS_FILE, "ICE %s successful", opname)); //TODO verbose
    	
    	if(op == PJ_ICE_STRANS_OP_NEGOTIATION) {
    	    if (socketWrite(sdp_conn_fd, message, strlen(message)) < 0){
    	        perror("error on socket write");
    	    }
    	    close(sdp_conn_fd);
    	}

    } else {
	    char errmsg[PJ_ERR_MSG_SIZE];

	    pj_strerror(status, errmsg, sizeof(errmsg));
	    PJ_LOG(1,(THIS_FILE, "ICE %s failed: %s", opname, errmsg));

	    pj_ice_strans_destroy(ice_st);
	    icedemo.icest = NULL;
	    if (socketWrite(sdp_conn_fd, fail_message, strlen(fail_message)) < 0){
	        perror("error on socket write");
        }
	    if (socketWrite(sdp_conn_fd, errmsg, strlen(errmsg)) < 0){
	                perror("error on socket write");
        }
        close(sdp_conn_fd);
    }

    if (op == PJ_ICE_STRANS_OP_INIT)
	    pthread_mutex_unlock(&lock_on_ice_init);
    if (op == PJ_ICE_STRANS_OP_NEGOTIATION)
        pthread_mutex_unlock(&lock_on_ice_init);
}

/*
 * This is the main application initialization function. It is called
 * once (and only once) during application initialization sequence by 
 * main().
 */
static pj_status_t icedemo_init(void)
{
    pj_status_t status;

    /* Initialize the libraries before anything else */
    CHECK( pj_init() );
    CHECK( pjlib_util_init() );
    CHECK( pjnath_init() );

    /* Must create pool factory, where memory allocations come from */
    pj_caching_pool_init(&icedemo.cp, NULL, 0);

    /* Init our ICE settings with null values */
    pj_ice_strans_cfg_default(&icedemo.ice_cfg);

    icedemo.ice_cfg.stun_cfg.pf = &icedemo.cp.factory;

    /* Create application memory pool */
    icedemo.pool = pj_pool_create(&icedemo.cp.factory, "icedemo", 
				  5120, 5120, NULL);

    /* Create timer heap for timer stuff */
    CHECK( pj_timer_heap_create(icedemo.pool, 100, 
				&icedemo.ice_cfg.stun_cfg.timer_heap) );

    /* and create ioqueue for network I/O stuff */
    CHECK( pj_ioqueue_create(icedemo.pool, 16, 
			     &icedemo.ice_cfg.stun_cfg.ioqueue) );

    /* something must poll the timer heap and ioqueue, 
     * unless we're on Symbian where the timer heap and ioqueue run
     * on themselves.
     */
    CHECK( pj_thread_create(icedemo.pool, "icedemo", &icedemo_worker_thread,
			    NULL, 0, 0, &icedemo.thread) );

    icedemo.ice_cfg.af = pj_AF_INET();

    /* Create DNS resolver if nameserver is set */
    if (icedemo.opt.ns.slen) {
	    CHECK( pj_dns_resolver_create(&icedemo.cp.factory, 
				          "resolver", 
				          0, 
				          icedemo.ice_cfg.stun_cfg.timer_heap,
				          icedemo.ice_cfg.stun_cfg.ioqueue, 
				          &icedemo.ice_cfg.resolver) );

	    CHECK( pj_dns_resolver_set_ns(icedemo.ice_cfg.resolver, 1, 
				          &icedemo.opt.ns, NULL) );
    }

    /* -= Start initializing ICE stream transport config =- */

    /* Maximum number of host candidates */
    if (icedemo.opt.max_host != -1)
	    icedemo.ice_cfg.stun.max_host_cands = icedemo.opt.max_host;

    /* Nomination strategy */
    if (icedemo.opt.regular)
	    icedemo.ice_cfg.opt.aggressive = PJ_FALSE;
    else
	    icedemo.ice_cfg.opt.aggressive = PJ_TRUE;

    /* Configure STUN/srflx candidate resolution */
    if (icedemo.opt.stun_srv.slen) {
	    char *pos;

	    /* Command line option may contain port number */
	    if ((pos=pj_strchr(&icedemo.opt.stun_srv, ':')) != NULL) {
	        icedemo.ice_cfg.stun.server.ptr = icedemo.opt.stun_srv.ptr;
	        icedemo.ice_cfg.stun.server.slen = (pos - icedemo.opt.stun_srv.ptr);

	        icedemo.ice_cfg.stun.port = (pj_uint16_t)atoi(pos+1);
	    } else {
	        icedemo.ice_cfg.stun.server = icedemo.opt.stun_srv;
	        icedemo.ice_cfg.stun.port = PJ_STUN_PORT;
	    }

	    /* For this demo app, configure longer STUN keep-alive time
	     * so that it does't clutter the screen output.
	     */
	    icedemo.ice_cfg.stun.cfg.ka_interval = KA_INTERVAL;

	    icedemo.ice_cfg.stun.cfg.max_pkt_size = icedemo.opt.max_pkt_size;
    }

    /* -= That's it for now, initialization is complete =- */
    return PJ_SUCCESS;
}


/*
 * Create ICE stream transport instance, invoked from the menu.
 */
static void icedemo_create_instance(void)
{
    pj_ice_strans_cb icecb;
    pj_status_t status;

    if (icedemo.icest != NULL) {
	    puts("ICE instance already created, destroy it first");
	    return;
    }

    /* init the callback */
    pj_bzero(&icecb, sizeof(icecb));
    icecb.on_rx_data = cb_on_rx_data;
    icecb.on_ice_complete = cb_on_ice_complete;

    /* create the instance */
    status = pj_ice_strans_create("icedemo",		    /* object name  */
				&icedemo.ice_cfg,	    /* settings	    */
				icedemo.opt.comp_cnt,	    /* comp_cnt	    */
				NULL,			    /* user data    */
				&icecb,			    /* callback	    */
				&icedemo.icest)		    /* instance ptr */
				;
    if (status != PJ_SUCCESS)
	    icedemo_perror("error creating ice", status);
    else
	    PJ_LOG(3,(THIS_FILE, "ICE instance successfully created"));
}

/* Utility to nullify parsed remote info */
static void reset_rem_info(void)
{
    pj_bzero(&icedemo.rem, sizeof(icedemo.rem));
}


/*
 * Destroy ICE stream transport instance, invoked from the menu.
 */
static void icedemo_destroy_instance(void)
{
    if (icedemo.icest == NULL) {
	    PJ_LOG(1,(THIS_FILE, "Error: No ICE instance, create it first"));
	    return;
    }

    pj_ice_strans_destroy(icedemo.icest);
    icedemo.icest = NULL;

    reset_rem_info();

    PJ_LOG(3,(THIS_FILE, "ICE instance destroyed"));
}


/*
 * Create ICE session, invoked from the menu.
 */
static void icedemo_init_session()
{
    pj_ice_sess_role role = ((tool_control_mode == OFFERER) ? 
				PJ_ICE_SESS_ROLE_CONTROLLING : 
				PJ_ICE_SESS_ROLE_CONTROLLED);
    pj_status_t status;

    if (icedemo.icest == NULL) {
	    PJ_LOG(1,(THIS_FILE, "Error: No ICE instance, create it first"));
	    return;
    }

    if (pj_ice_strans_has_sess(icedemo.icest)) {
	    PJ_LOG(1,(THIS_FILE, "Error: Session already created"));
	    return;
    }

    status = pj_ice_strans_init_ice(icedemo.icest, role, NULL, NULL);
    if (status != PJ_SUCCESS)
	    icedemo_perror("error creating session", status);
    else
	    PJ_LOG(3,(THIS_FILE, "ICE session created"));

    reset_rem_info();
}


/*
 * Stop/destroy ICE session, invoked from the menu.
 */
static void icedemo_stop_session(void)
{
    pj_status_t status;

    if (icedemo.icest == NULL) {
	    PJ_LOG(1,(THIS_FILE, "Error: No ICE instance, create it first"));
	    return;
    }

    if (!pj_ice_strans_has_sess(icedemo.icest)) {
	    PJ_LOG(1,(THIS_FILE, "Error: No ICE session, initialize first"));
	    return;
    }

    status = pj_ice_strans_stop_ice(icedemo.icest);
    if (status != PJ_SUCCESS)
	    icedemo_perror("error stopping session", status);
    else
	    PJ_LOG(3,(THIS_FILE, "ICE session stopped"));

    reset_rem_info();
}

#define PRINT(fmt, arg0, arg1, arg2, arg3, arg4, arg5)	    \
	printed = pj_ansi_snprintf(p, maxlen - (p-buffer),  \
				   fmt, arg0, arg1, arg2, arg3, arg4, arg5); \
	if (printed <= 0) return -PJ_ETOOSMALL; \
	p += printed


/* Utility to create a=candidate SDP attribute */
static int print_cand(char buffer[], unsigned maxlen,
		      const pj_ice_sess_cand *cand)
{
    char ipaddr[PJ_INET6_ADDRSTRLEN];
    char *p = buffer;
    int printed;

    PRINT("a=candidate:%.*s %u UDP %u %s %u typ ",
	  (int)cand->foundation.slen,
	  cand->foundation.ptr,
	  (unsigned)cand->comp_id,
	  cand->prio,
	  pj_sockaddr_print(&cand->addr, ipaddr, 
			    sizeof(ipaddr), 0),
	  (unsigned)pj_sockaddr_get_port(&cand->addr));

    PRINT("%s\n",
	  pj_ice_get_cand_type_name(cand->type),
	  0, 0, 0, 0, 0);

    if (p == buffer+maxlen)
	    return -PJ_ETOOSMALL;

    *p = '\0';

    return p-buffer;
}

/* 
 * Encode ICE information in SDP.
 */
static int encode_session(char buffer[], unsigned maxlen)
{
    char *p = buffer;
    unsigned comp;
    int printed;
    pj_str_t local_ufrag, local_pwd;
    pj_status_t status;

    /* Write "dummy" SDP v=, o=, s=, and t= lines */
    PRINT("v=0\no=- 3414953978 3414953978 IN IP4 localhost\ns=ice\nt=0 0\n", 
	  0, 0, 0, 0, 0, 0);

    /* Get ufrag and pwd from current session */
    pj_ice_strans_get_ufrag_pwd(icedemo.icest, &local_ufrag, &local_pwd,
				NULL, NULL);

    /* Write the a=ice-ufrag and a=ice-pwd attributes */
    PRINT("a=ice-ufrag:%.*s\na=ice-pwd:%.*s\n",
	   (int)local_ufrag.slen,
	   local_ufrag.ptr,
	   (int)local_pwd.slen,
	   local_pwd.ptr, 
	   0, 0);

    /* Write each component */
    for (comp=0; comp<icedemo.opt.comp_cnt; ++comp) {
	    unsigned j, cand_cnt = PJ_ICE_ST_MAX_CAND;
	    pj_ice_sess_cand cand[PJ_ICE_ST_MAX_CAND];
	    char ipaddr[PJ_INET6_ADDRSTRLEN];

	    /* Get default candidate for the component */
	    status = pj_ice_strans_get_def_cand(icedemo.icest, comp+1, &cand[0]);
	    if (status != PJ_SUCCESS)
	        return -status;

	    /* Write the default address */
	    if (comp == 0) {
	        /* For component 1, default address is in m= and c= lines */
	        PRINT("m=audio %d RTP/AVP 0\n"
		      "c=IN IP4 %s\n",
		      (int)pj_sockaddr_get_port(&cand[0].addr),
		      pj_sockaddr_print(&cand[0].addr, ipaddr,
				        sizeof(ipaddr), 0),
		      0, 0, 0, 0);
	    } else if (comp == 1) {
	        /* For component 2, default address is in a=rtcp line */
	        PRINT("a=rtcp:%d IN IP4 %s\n",
		      (int)pj_sockaddr_get_port(&cand[0].addr),
		      pj_sockaddr_print(&cand[0].addr, ipaddr,
				        sizeof(ipaddr), 0),
		      0, 0, 0, 0);
	    } else {
	        /* For other components, we'll just invent this.. */
	        PRINT("a=Xice-defcand:%d IN IP4 %s\n",
		      (int)pj_sockaddr_get_port(&cand[0].addr),
		      pj_sockaddr_print(&cand[0].addr, ipaddr,
				        sizeof(ipaddr), 0),
		      0, 0, 0, 0);
	    }

	    /* Enumerate all candidates for this component */
	    status = pj_ice_strans_enum_cands(icedemo.icest, comp+1,
					      &cand_cnt, cand);
	    if (status != PJ_SUCCESS)
	        return -status;

	    /* And encode the candidates as SDP */
	    for (j=0; j<cand_cnt; ++j) {
	        printed = print_cand(p, maxlen - (p-buffer), &cand[j]);
	        if (printed < 0)
		        return -PJ_ETOOSMALL;
	        p += printed;
	    }
    }

    if (p == buffer+maxlen)
	    return -PJ_ETOOSMALL;

    *p = '\0';
    return p - buffer;
}

/*
 * Input and parse SDP from the remote (containing remote's ICE information) 
 * and save it to global variables.
 */
static void icedemo_input_remote(char *data)
{
    char *linebuf;
    unsigned media_cnt = 0;
    unsigned comp0_port = 0;
    char     comp0_addr[80];
    pj_bool_t done = PJ_FALSE;
    char *rest;

    //printf("\nComplete data received from user:\n%s\n",data);

    reset_rem_info();

    comp0_addr[0] = '\0';

    while (!done) {
	    int len;
	    char *line;

	    //printf(">");
	    if (stdout) fflush(stdout);


        //strtok on data
        linebuf = strtok_r(data, "\n", &rest);
        data = rest;
        

        if (linebuf == NULL)
            break;
        //printf("Linea analizzata: %s\n",linebuf);

	    len = strlen(linebuf);
	    while (len && (linebuf[len-1] == '\r' || linebuf[len-1] == '\n'))
	        linebuf[--len] = '\0';

	    line = linebuf;
	    while (len && pj_isspace(*line))
	        ++line, --len;

	    if (len == 0)
	        break;

	    /* Ignore subsequent media descriptors */
	    if (media_cnt > 1)
	        continue;

	    switch (line[0]) {
	        case 'm':
	            {
		        int cnt;
		        char media[32], portstr[32];

		        ++media_cnt;
		        if (media_cnt > 1) {
		            puts("Media line ignored");
		            break;
		        }

		        cnt = sscanf(line+2, "%s %s RTP/", media, portstr);
		        if (cnt != 2) {
		            PJ_LOG(1,(THIS_FILE, "Error parsing media line"));
		            goto on_error;
		        }

		        comp0_port = atoi(portstr);
		
	            }
	            break;
	        
	        case 'c':
	            {
		        int cnt;
		        char c[32], net[32], ip[80];
		
		        cnt = sscanf(line+2, "%s %s %s", c, net, ip);
		        if (cnt != 3) {
		            PJ_LOG(1,(THIS_FILE, "Error parsing connection line"));
		            goto on_error;
		        }

		        strcpy(comp0_addr, ip);
	            }
	            break;
	        
	        case 'a':
	            {
		        char *attr = strtok(line+2, ": \t\r\n");
		        if (strcmp(attr, "ice-ufrag") == 0) {
		            strcpy(icedemo.rem.ufrag, attr+strlen(attr)+1);
		        } else if (strcmp(attr, "ice-pwd") == 0) {
		            strcpy(icedemo.rem.pwd, attr+strlen(attr)+1);
		        } else if (strcmp(attr, "rtcp") == 0) {
		            char *val = attr+strlen(attr)+1;
		            int af, cnt;
		            int port;
		            char net[32], ip[64];
		            pj_str_t tmp_addr;
		            pj_status_t status;

		            cnt = sscanf(val, "%d IN %s %s", &port, net, ip);
		            if (cnt != 3) {
			            PJ_LOG(1,(THIS_FILE, "Error parsing rtcp attribute"));
			            goto on_error;
		            }

		            if (strchr(ip, ':'))
			            af = pj_AF_INET6();
		            else
			            af = pj_AF_INET();

		            pj_sockaddr_init(af, &icedemo.rem.def_addr[1], NULL, 0);
		            tmp_addr = pj_str(ip);
		            status = pj_sockaddr_set_str_addr(af, &icedemo.rem.def_addr[1],
						              &tmp_addr);
		            if (status != PJ_SUCCESS) {
			            PJ_LOG(1,(THIS_FILE, "Invalid IP address"));
			            goto on_error;
		            }
		            pj_sockaddr_set_port(&icedemo.rem.def_addr[1], (pj_uint16_t)port);

		        } else if (strcmp(attr, "candidate") == 0) {
		            char *sdpcand = attr+strlen(attr)+1;
		            int af, cnt;
		            char foundation[32], transport[12], ipaddr[80], type[32];
		            pj_str_t tmpaddr;
		            int comp_id, prio, port;
		            pj_ice_sess_cand *cand;
		            pj_status_t status;

		            cnt = sscanf(sdpcand, "%s %d %s %d %s %d typ %s",
				         foundation,
				         &comp_id,
				         transport,
				         &prio,
				         ipaddr,
				         &port,
				         type);
		            if (cnt != 7) {
			            PJ_LOG(1, (THIS_FILE, "error: Invalid ICE candidate line"));
			            goto on_error;
		            }

		            cand = &icedemo.rem.cand[icedemo.rem.cand_cnt];
		            pj_bzero(cand, sizeof(*cand));
		            
		            if (strcmp(type, "host") == 0)
			           cand->type = PJ_ICE_CAND_TYPE_HOST;
		            else if (strcmp(type, "srflx") == 0)
			           cand->type = PJ_ICE_CAND_TYPE_SRFLX;
		            else if (strcmp(type, "relay") == 0)
			           cand->type = PJ_ICE_CAND_TYPE_RELAYED;
		            else {
			            PJ_LOG(1, (THIS_FILE, "Error: invalid candidate type '%s'", 
				               type));
			            goto on_error;
		            }

		            cand->comp_id = (pj_uint8_t)comp_id;
		            pj_strdup2(icedemo.pool, &cand->foundation, foundation);
		            cand->prio = prio;
		            
		            if (strchr(ipaddr, ':'))
			            af = pj_AF_INET6();
		            else
			            af = pj_AF_INET();

		            tmpaddr = pj_str(ipaddr);
		            pj_sockaddr_init(af, &cand->addr, NULL, 0);
		            status = pj_sockaddr_set_str_addr(af, &cand->addr, &tmpaddr);
		            if (status != PJ_SUCCESS) {
			            PJ_LOG(1,(THIS_FILE, "Error: invalid IP address '%s'",
				              ipaddr));
			            goto on_error;
		            }

		            pj_sockaddr_set_port(&cand->addr, (pj_uint16_t)port);

		            ++icedemo.rem.cand_cnt;

		            if (cand->comp_id > icedemo.rem.comp_cnt)
			            icedemo.rem.comp_cnt = cand->comp_id;
		        }
	            }
	            break;
	    }
    }

    if (icedemo.rem.cand_cnt == 0 ||
	        icedemo.rem.ufrag[0] == 0 ||
	        icedemo.rem.pwd[0] == 0 ||
	        icedemo.rem.comp_cnt == 0)
    {
	    PJ_LOG(1, (THIS_FILE, "Error: not enough info"));
	    goto on_error;
    }

    if (comp0_port == 0 || comp0_addr[0] == '\0') {
	    PJ_LOG(1, (THIS_FILE, "Error: default address for component 0 not found"));
	    goto on_error;
    } else {
	    int af;
	    pj_str_t tmp_addr;
	    pj_status_t status;

	    if (strchr(comp0_addr, ':'))
	        af = pj_AF_INET6();
	    else
	        af = pj_AF_INET();

	    pj_sockaddr_init(af, &icedemo.rem.def_addr[0], NULL, 0);
	    tmp_addr = pj_str(comp0_addr);
	    status = pj_sockaddr_set_str_addr(af, &icedemo.rem.def_addr[0],
					      &tmp_addr);
	    if (status != PJ_SUCCESS) {
	        PJ_LOG(1,(THIS_FILE, "Invalid IP address in c= line"));
	        goto on_error;
	    }
	    pj_sockaddr_set_port(&icedemo.rem.def_addr[0], (pj_uint16_t)comp0_port);
    }

    PJ_LOG(3, (THIS_FILE, "Done, %d remote candidate(s) added", 
	       icedemo.rem.cand_cnt));
    return;

on_error:
    reset_rem_info();
}


/*
 * Start ICE negotiation! This function is invoked from the menu.
 */
static void icedemo_start_nego(void)
{
    pj_str_t rufrag, rpwd;
    pj_status_t status;

    if (icedemo.icest == NULL) {
	    PJ_LOG(1,(THIS_FILE, "Error: No ICE instance, create it first"));
	    return;
    }

    if (!pj_ice_strans_has_sess(icedemo.icest)) {
	    PJ_LOG(1,(THIS_FILE, "Error: No ICE session, initialize first"));
	    return;
    }

    if (icedemo.rem.cand_cnt == 0) {
	    PJ_LOG(1,(THIS_FILE, "Error: No remote info, input remote info first"));
	    return;
    }

    PJ_LOG(3,(THIS_FILE, "Starting ICE negotiation.."));

    status = pj_ice_strans_start_ice(icedemo.icest, 
				     pj_cstr(&rufrag, icedemo.rem.ufrag),
				     pj_cstr(&rpwd, icedemo.rem.pwd),
				     icedemo.rem.cand_cnt,
				     icedemo.rem.cand);
    if (status != PJ_SUCCESS)
	    icedemo_perror("Error starting ICE", status);
    else
	    PJ_LOG(3,(THIS_FILE, "ICE negotiation started"));
}


/*
 * Send application data to remote agent.
 */
static void icedemo_send_data(unsigned comp_id, const char *data, unsigned int length)
{
    pj_status_t status;

    if (icedemo.icest == NULL) {
	    PJ_LOG(1,(THIS_FILE, "Error: No ICE instance, create it first"));
	    return;
    }

    if (!pj_ice_strans_has_sess(icedemo.icest)) {
	    PJ_LOG(1,(THIS_FILE, "Error: No ICE session, initialize first"));
	    return;
    }

    if (comp_id < 1 || comp_id > pj_ice_strans_get_running_comp_cnt(icedemo.icest)) {
	    PJ_LOG(1,(THIS_FILE, "Error: invalid component ID"));
	    return;
    }

    status = pj_ice_strans_sendto(icedemo.icest, comp_id, data, length,
				  &icedemo.rem.def_addr[comp_id-1],
				  pj_sockaddr_get_len(&icedemo.rem.def_addr[comp_id-1]));
    if (status != PJ_SUCCESS)
	    icedemo_perror("Error sending data", status);
    /*else
	PJ_LOG(3,(THIS_FILE, "Data sent"));*/
}

/*
 * SDP_tcp_server: receive SDP data using a TCP server.
 */
static int sdp_tcp_server(void *arg){
    struct sockaddr_in serv_add;
    int sdp_sock_fd;
    size_t nleft;
    int nread;
    ssize_t nwritten;
    int cursor = 0;
    int tr = 1;
    
    
	if ( (sdp_sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Socket creation error");
		exit(1);
	}
    
    memset((void *)&serv_add, 0, sizeof(serv_add)); 
    serv_add.sin_family = AF_INET;                  
    serv_add.sin_port = htons(sdp_tcp_server_port);    
    serv_add.sin_addr.s_addr = htonl(INADDR_ANY); 
    
    if (setsockopt(sdp_sock_fd, SOL_SOCKET, SO_REUSEADDR, &tr, sizeof(tr)) == -1) {
        perror("setsockopt");
        exit(1);
    }
    
    if (bind(sdp_sock_fd, (struct sockaddr *)&serv_add, sizeof(serv_add)) < 0) {
	    perror("bind error");
	    exit(1);
    }
    if (listen(sdp_sock_fd, 10) < 0 ) {
	    perror("listen error");
	    exit(1);
    }
    
    PJ_LOG(1,(THIS_FILE, "SDP TCP server waiting for connection"));
	/* accept connection */
    if ( (sdp_conn_fd = accept(sdp_sock_fd, NULL, NULL)) < 0) {
        perror("accept error");
        exit(1);
    }
    PJ_LOG(1,(THIS_FILE, "TCP Connection accepted"));
   
    pthread_mutex_lock(&lock_on_buffer_data);
    pthread_mutex_unlock(&lock_on_buffer_data);
    

    /* We use strlen because we know that the buffer is zero-ended */
    if (socketWrite(sdp_conn_fd, buffer_data, strlen(buffer_data)) < 0){
        perror("error on socket write");
    }

    while ( (nread = socketRead(sdp_conn_fd, (recv_buff+cursor), (MAXLINE-cursor))) != 0) {
        cursor += nread;
        if(cursor >= MAXLINE){
            perror("recv buffer full");
            exit(1);
        }
        if (strstr(recv_buff, "\n\n") != NULL){ /* Search for a \n\n in string, if found the input is ended */
            break;
        }
    }
	close(sdp_sock_fd); /* Close the main socket but not the connection */

	return 0;
}

static void iceauto_toolsrv() {
    int n;
    char tool_buffer[MAXLINE]; 
    int tr=1;
    socklen_t addr_len;
    
    if (tool_mode == UDP_MODE) {
        PJ_LOG(1,(THIS_FILE, "Starting the tool server in UDP mode"));

        /* create socket for later use UDP server */
        if ((tool_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            perror("Tool Socket creation error");
            exit(-1);
        }
    }
    else {
        PJ_LOG(1,(THIS_FILE, "Starting the tool server in TCP mode"));

        if ((tool_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Tool Socket creation error");
            exit(-1);
        }
        if (setsockopt(tool_sock, SOL_SOCKET, SO_REUSEADDR, &tr, sizeof(tr)) == -1) {
            perror("Tool setsockopt error");
            exit(1);
        }
    }
    /* initialize address */
    memset((void *)&tool_endpoint_addr, 0, sizeof(tool_endpoint_addr));
    tool_endpoint_addr.sin_family = AF_INET;
    if (tool_control_mode == OFFERER){
        tool_endpoint_addr.sin_port = htons(tool_server_port);
        tool_endpoint_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        
        PJ_LOG(1,(THIS_FILE, "Binding tool socket"));
        /* bind socket */
        if (bind(tool_sock, (struct sockaddr *)&tool_endpoint_addr, sizeof(tool_endpoint_addr)) < 0) {
	        perror("Tool socket bind error");
	        exit(-1);
        }

        if (tool_mode == TCP_MODE){
            PJ_LOG(1,(THIS_FILE, "Setting the listen on the tool socket"));
            if (listen(tool_sock, BACKLOG) < 0 ) {
                perror("Tool socket listen error");
                exit(1);
            }
        }
    }
    else {
        tool_endpoint_addr.sin_port = htons(tool_client_port); 
        if ((inet_pton(AF_INET, tool_client_address, &tool_endpoint_addr.sin_addr)) <= 0) {
	        perror("Address creation error");
	        exit(-1);
        }
    }
    
    
    if (pthread_mutex_init(&lock_on_ice_init, NULL) != 0)
    {
        printf("\n mutex init failed\n");
        exit(1);
    }
    pthread_mutex_lock(&lock_on_ice_init);
    
    PJ_LOG(1,(THIS_FILE, "Creating ICE instance"));
    icedemo_create_instance();
    
    PJ_LOG(1,(THIS_FILE, "Starting session initialization"));
    pthread_mutex_lock(&lock_on_ice_init);
    pthread_mutex_unlock(&lock_on_ice_init);
    icedemo_init_session();
    
    
    n = encode_session(tool_buffer, sizeof(tool_buffer));
    if (n < 0){
        printf("Buffer size error\n"); //TODO
        exit(1);
    }

    strncpy(buffer_data, tool_buffer, MAXLINE);
    pthread_mutex_unlock(&lock_on_buffer_data);
    
    pj_thread_join(icedemo.sdp_thread);
    pj_thread_destroy(icedemo.sdp_thread);
    icedemo_input_remote(recv_buff);
    pthread_mutex_lock(&lock_on_ice_init);
    
    PJ_LOG(1,(THIS_FILE, "Starting the ICE negotiation"));
    icedemo_start_nego();
    pthread_mutex_lock(&lock_on_ice_init);
    pthread_mutex_unlock(&lock_on_ice_init);
    
    addr_len = sizeof(tool_endpoint_addr);

    if (tool_mode == TCP_MODE) {
        while (1) {
            if (tool_control_mode == OFFERER) {
                PJ_LOG(1,(THIS_FILE, "Tool socket (TCP), invoking the accept call"));
                if ( (tool_sock_conn = accept(tool_sock, NULL, NULL)) < 0) {
                        perror("Accept error");
                        exit(1);
                }
                tool_conn_status = ESTABLISHED;
            }
            else {
                PJ_LOG(1,(THIS_FILE, "Tool socket (TCP), invoking the connect call"));
                while (( n = connect(tool_sock, (struct sockaddr *)&tool_endpoint_addr, addr_len)) < 0){
                    perror("Connection error");
                    sleep(1);
                }
                tool_sock_conn = tool_sock;
                tool_conn_status = ESTABLISHED;
            }

            PJ_LOG(1,(THIS_FILE, "Tool socket (TCP) connected, reading and forwarding data."));
            while ((n = socketRead(tool_sock_conn, tool_buffer, MAXLINE)) != 0) {
                icedemo_send_data(1, tool_buffer, n);
            }

            PJ_LOG(1,(THIS_FILE, "Tool socket (TCP) disconnected, closing connection"));
            close(tool_sock_conn);
            tool_conn_status = CLOSED;

            if (tool_control_mode == ANSWERER){
                PJ_LOG(1,(THIS_FILE, "Tool socket (TCP) reconnection: re-creation of socket"));
                if ((tool_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
                    perror("Tool Socket creation error");
                    exit(-1);
                }
            }
        }
        //TODO: Connection end?
    }
    else { // UDP mode
        PJ_LOG(1,(THIS_FILE, "Tool socket (UDP) ready to read and forward data."));
        while (1) {
            n = recvfrom(tool_sock, tool_buffer, MAXLINE, 0,
                    (struct sockaddr *)&tool_endpoint_addr, &addr_len);
            if (n < 0) {
                perror("recvfrom error");
                exit(-1);
            }

            icedemo_send_data(1, tool_buffer, n);
        }
    }
}



/*
 * Display program usage.
 */
static void icedemo_usage()
{
    puts("Usage: icedemo [options]");
    printf("icedemo v%s by pjsip.org\nModded version by Otacon22!\n", pj_get_version());
    puts("");
    puts("General options:");
    puts(" --comp-cnt, -c N      Component count (default=1)");
    puts(" --nameserver, -n IP   Configure nameserver to activate DNS SRV");
    puts("                       resolution");
    puts(" --max-host, -H N      Set max number of host candidates to N");
    puts(" --regular, -R         Use regular nomination (default aggressive)");
    puts(" --offerer, -o         Set the ICE mode as offerer (default behaviour)");
    puts(" --answerer, -a        Set the ICE mode as answerer");
    puts(" --sdp-tcp-port, -S N  Set the TCP server port to receive SDP information (default 7001)");
    puts(" --offer-port, -O N    Set the UDP server port of the offerer (default 7002)");
    puts(" --answ-port, -A N     Set the UDP client port of the answerer (default 7003)");
    puts(" --answ-addr, -C HOST  Set the UDP client address of the answerer (default 7004)");
    puts(" --tcp-mode, -P        Set the use of TCP instead of UDP for the tool client/server");
    puts(" --max-pkt-size, -Z N  Set the max packet size for the STUN messages (default 2000 bytes)");
    puts(" --verbose, -v         Verbose mode");
    puts(" --help, -h            Display this screen.");
    puts("");
    puts("STUN related options:");
    puts(" --stun-srv, -s HOSTDOM    Enable srflx candidate by resolving to STUN server.");
    puts("                           HOSTDOM may be a \"host_or_ip[:port]\" or a domain");
    puts("                           name if DNS SRV resolution is used.");
    puts("                           (example: stun.selbie.com or stunserver.org)");
    puts("");
}


/*
 * And here's the main()
 */
int main(int argc, char *argv[])
{
    struct pj_getopt_option long_options[] = {
	{ "comp-cnt",           1, 0, 'c'},
	{ "nameserver",	        1, 0, 'n'},
	{ "max-host",           1, 0, 'H'},
	{ "help",               0, 0, 'h'},
	{ "stun-srv",           1, 0, 's'},
	{ "regular",            0, 0, 'R'},
	{ "offerer",            0, 0, 'o'},
	{ "answerer",           0, 0, 'a'},
	{ "sdp-tcp-port",       1, 0, 'S'},
	{ "offer-port",         1, 0, 'O'},
	{ "answ-port",          1, 0, 'A'},
	{ "answ-addr",          1, 0, 'C'},
	{ "tcp-mode",           0, 0, 'P'},
	{ "max-pkt-size",       1, 0, 'Z'},
	{ "verbose",            0, 0, 'v'},
    };
    int c, opt_id;
    pj_status_t status;

    icedemo.opt.comp_cnt = 1;
    icedemo.opt.max_host = -1;
    icedemo.opt.max_pkt_size = 2000;

    while((c = pj_getopt_long(argc,argv, "c:n:s:H:S:O:A:C:Z:PhRoav",
            long_options, &opt_id)) != -1) {
	    switch (c) {
	        case 'c':
	            icedemo.opt.comp_cnt = atoi(pj_optarg);
	            if (icedemo.opt.comp_cnt < 1 ||
	                    icedemo.opt.comp_cnt >= PJ_ICE_MAX_COMP) {
                    puts("Invalid component count value");
                    return 1;
	            }
	            break;
	        case 'n':
	            icedemo.opt.ns = pj_str(pj_optarg);
	            break;
	        case 'H':
	            icedemo.opt.max_host = atoi(pj_optarg);
	            break;
	        case 'h':
	            icedemo_usage();
	            return 0;
	        case 's':
	            icedemo.opt.stun_srv = pj_str(pj_optarg);
	            break;
	        case 'R':
	            icedemo.opt.regular = PJ_TRUE;
	            break;
            case 'o':
                tool_control_mode = OFFERER;
                break;
            case 'a':
                tool_control_mode = ANSWERER;
                break;
            case 'S':
                sdp_tcp_server_port = atoi(pj_optarg);
                break;
            case 'O':
                tool_server_port = atoi(pj_optarg);
                break;
            case 'A':
                tool_client_port = atoi(pj_optarg);
                break;
            case 'C':
                tool_client_address = pj_optarg;
                break;
            case 'P':
                tool_mode = TCP_MODE;
                break;
            case 'Z':
                icedemo.opt.max_pkt_size = atoi(pj_optarg);
                break;
            case 'v':
                verbose++;
                break;
	        default:
	            printf("Argument \"%s\" is not valid. Use -h to see help\n",
		           argv[pj_optind]);
	            return 1;
        }
    }

    pj_log_set_level(verbose); /* We display only the verbose level choose by user */

    status = icedemo_init();
    if (status != PJ_SUCCESS)
	    return 1;
    
    if (pthread_mutex_init(&lock_on_buffer_data, NULL) != 0)
    {
        printf("Mutex init failed!\n");
        exit(1);
    }
    pthread_mutex_lock(&lock_on_buffer_data);
    
    CHECK( pj_thread_create(icedemo.pool, "sdp_tcp_server", &sdp_tcp_server,
                NULL, 0, 0, &icedemo.sdp_thread) );

    iceauto_toolsrv();
    
    err_exit("Quitting..", PJ_SUCCESS); //TODO: catch of Ctrl+C
    return 0;
}
