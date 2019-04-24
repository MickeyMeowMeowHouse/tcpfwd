//#include"config.h" // tired to configure

// These we could have
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<stdarg.h>
#include<errno.h>
#include<ctype.h>
#include<signal.h>
#include<string.h>
#include<time.h>

// There's something we have and there's something we didn't have
#ifdef WIN32
#include<WinSock2.h>
#include<ws2tcpip.h> // for using struct sockaddr_in6 ... but now it didn't support IPv6
#include<xmmintrin.h>
#else
#include<fcntl.h>
#include<unistd.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#endif

#define EXEC_NAME   "tcpfwd"			// program name
#define LOCK_FILE	"/tmp/tcpfwd.lock"	// PID file name
#define LOG_FILE	"tcpfwd.log"		// log file name
#define CFG_FILE	"tcpfwd.conf"		// configure file name

#define backlog_default 200				// default max connections
#define num_conn_alloc 32				// how much units allocated when RAM usage grows
#define fwd_buffer_size 8192			// forward buffer size
#define def_packet_size 1472			// mtu for splitting packets

#define MAX_BACKOFF_ITERS (RAND_MAX > 0x10000 ? 0x10000 : RAND_MAX)
#define MAX_BO_SLEEPS 20

typedef int bool_t, *bool_p;

// my address structure
typedef union address_u
{
    struct sockaddr sa;
    struct sockaddr_in sa_in;
    struct sockaddr_in6 sa_in6;
    struct sockaddr_storage sa_stor;
}address_t, *address_p;

#ifdef WIN32
#define cpu_relax() _mm_pause()
typedef INT_PTR ssize_t; // signed size_t in windows
typedef int socklen_t;
static void sleep_relax(unsigned sleeps)
{
	Sleep(sleeps); // In windows, Sleep(0) will die in win98
}
static int _socket_errno() // Translate error number
{
	int Err = WSAGetLastError();
	switch(Err)
	{
	case WSAEADDRINUSE:
		return EADDRINUSE;
	case WSAEADDRNOTAVAIL:
		return EADDRNOTAVAIL;
	case WSAEAFNOSUPPORT:
		return EAFNOSUPPORT;
	case WSAEALREADY:
		return EALREADY;
	case WSAECONNABORTED:
		return ECONNABORTED;
	case WSAECONNREFUSED:
		return ECONNREFUSED;
	case WSAECONNRESET:
		return ECONNRESET;
	case WSAEDESTADDRREQ:
		return EDESTADDRREQ;
	case WSAEHOSTUNREACH:
		return EHOSTUNREACH;
	case WSAEINPROGRESS:
		return EINPROGRESS;
	case WSAEISCONN:
		return EISCONN;
	case WSAELOOP:
		return ELOOP;
	case WSAEMSGSIZE:
		return EMSGSIZE;
	case WSAENETDOWN:
		return ENETDOWN;
	case WSAENETRESET:
		return ENETRESET;
	case WSAENETUNREACH:
		return ENETUNREACH;
	case WSAENOBUFS:
		return ENOBUFS;
	case WSAENOPROTOOPT:
		return ENOPROTOOPT;
	case WSAENOTCONN:
		return ENOTCONN;
	case WSAENOTSOCK:
		return ENOTSOCK;
	case WSAEOPNOTSUPP:
		return EOPNOTSUPP;
	case WSAEPROTONOSUPPORT:
		return EPROTONOSUPPORT;
	case WSAEPROTOTYPE:
		return EPROTOTYPE;
	case WSAETIMEDOUT:
		return ETIMEDOUT;
	case WSAEWOULDBLOCK:
		return EWOULDBLOCK;
	default:
		return Err;
	}
}
#define socket_errno _socket_errno() // pretend as a variable
#define MSG_NOSIGNAL 0 // Windows didn't have this, pretend as we have
#else // we don't think about what other systems, just for unix
#if __x86_64__ || i386
#define cpu_relax() __asm__ __volatile__("pause")
#elif __arm__ || __aarch64__
#define cpu_relax() __asm__ __volatile__("yield")
#elif __mips__
#define cpu_relax() __asm__ __volatile__(".word 0x00000140")
#else
#define cpu_relax() __asm__ __volatile__("pause")
#endif
static void sleep_relax(unsigned sleeps)
{
	if(sleeps)
		usleep(sleeps * 1000);
	else
		usleep(500);
}
#define socket_errno errno
static int closesocket(int sockfd) // sockets in linux is a file descriptor
{
	return close(sockfd);
}
#define _tzset tzset
static char*_strtime(char*timestr)
{
	time_t now;
	struct tm *l_time;
	static char _timestr[10] = {0};
	
	now = time(NULL);
	l_time = localtime(&now);
	sprintf(_timestr, "%.2d:%.2d:%.2d", l_time->tm_hour, l_time->tm_min, l_time->tm_sec);
	strncpy(timestr, _timestr, sizeof _timestr);
	return _timestr;
}
#endif

//=============================================================================
// socket connection
typedef struct fwdconn_struct
{
	int sockfd_src; // source
	int sockfd_dst; // destination
	bool_t connected; // was that connected?
	char buffer_src[fwd_buffer_size]; // data from source
	int cb_src; // data bytes
	char buffer_dst[fwd_buffer_size]; // data from destination
	int cb_dst; // data bytes
	address_t addr_from; // source address
	socklen_t addr_size; // source address length
}fwdconn_t, *fwdconn_p;

typedef struct fwdroute_struct
{
	int listen_socket; // a socket for accepting connections
	
	int import; // listening port
	int export; // output port
	unsigned packet_size_to_src; // mtu split size for source
	unsigned packet_size_to_dst; // mtu split size for destination
	int status_of_tcp_nodelay; // use nagle algorithm? 1 for no, 0 for yes
	
	address_t DestAddr; // destination address
	socklen_t cbDestAddr; // destination address length
	
	fwdconn_p fwd_conn; // active connection array
	size_t num_fwd_conn; // how many
	size_t max_fwd_conn; // array capacity
}fwdroute_t, *fwdroute_p;

typedef struct fwdinst_struct
{
	fwdroute_p	pRoute; // routers
	size_t		num_route; // how many
	size_t		max_route; // array capacity
	
	int			listen_backlog; // max connections
	bool_t		log_traffic; // do we log any packets?
}fwdinst_t, *fwdinst_p;

typedef struct bo_struct
{
	unsigned cr;
	unsigned sr;
	unsigned max_cr;
	unsigned max_sr;
}bo_t, *bo_p;

static void bo_reset(bo_p bo)
{
	memset(bo, 0, sizeof *bo);
	bo->max_cr = MAX_BACKOFF_ITERS;
	bo->max_sr = MAX_BO_SLEEPS;
}
static void bo_update(bo_p bo)
{
	int s = 0;
	
	if(bo->cr < bo->max_cr)
	{
		if(!bo->cr) bo->cr = 1;
		else bo->cr <<= 1;
	}
	else
	{
		bo->cr = bo->max_cr;
		s = 1;
	}
	
	if(s)
	{
		if(bo->sr < bo->max_sr)
		{
			if(!bo->sr) bo->sr = 1;
			else bo->sr <<= 1;
		}
		else bo->sr = bo->max_sr;
		sleep_relax(rand() % bo->sr);
	}
	else
	{
		int r = rand() % bo->cr + 1;
		while(r--) cpu_relax();
	}
}

static volatile bool_t _g_Term = 0; // global quitting?
static bool_t _g_LogToScreen = 1; // do we write log to screen 

void Inst_Log(char *message, ...);
fwdinst_p Inst_Create(bool_t DoDaemonize, const char *cfg_file);
int Inst_Run(fwdinst_p pInst);
void Inst_Term(fwdinst_p pInst);

static int _Inst_Daemonize();
static bool_t _SetSocketBlockingEnabled(int fd, int blocking);
static int _CreateNBIOTCPSocket();
static void _MakeIPv4Address(address_p pOut, uint32_t IP, uint16_t Port);
static bool_t _ListenPort(fwdinst_p pInst, int socket, int port);
static bool_t _Inst_LoadCFG(fwdinst_p pInst, const char*cfg_file);
static fwdroute_p _Inst_AddRoute
(
	fwdinst_p pInst,
	int import,
	uint32_t exportAddr,
	int exportPort,
	int status_of_tcp_nodelay,
	int packet_size_to_src,
	int packet_size_to_dst
);
static fwdconn_p _Inst_AddNewConnection
(
	fwdroute_p pRoute,
	int sockfd,
	address_p pAddr,
	socklen_t cbAddr
);
static void _Inst_BreakConnection(fwdroute_p pRoute, size_t ic);
static uint32_t _IpAddrV4ByNums(int n1, int n2, int n3, int n4);
static bool_t _Inst_LoadCFG(fwdinst_p pInst, const char*cfg_file);
static void _signal_handler(int sig);

//==============================================================================
//Func: _SetSocketBlockingEnabled
//Desc: make a socket works for polling
//------------------------------------------------------------------------------
static bool_t _SetSocketBlockingEnabled(int fd, int blocking)
{
	if (fd < 0)
		return 0;

#ifdef WIN32
	{
		unsigned long mode = blocking ? 0 : 1;
		if(ioctlsocket(fd, FIONBIO, &mode) == 0)
			return 1;
		else
		{
			Inst_Log("Set socket to non blocking I/O mode failed. %d\n",
				socket_errno);
			return 0;
		}
	}
#else
	int flags = fcntl(fd, F_GETFL, 0);
	if(flags < 0)return 0;
	flags = blocking ? (flags&~O_NONBLOCK) : (flags|O_NONBLOCK);
	if(!fcntl(fd, F_SETFL, flags))
		return 1;
	else
	{
		Inst_Log("Set socket to non blocking I/O mode failed.\n");
		return 0;
	}
#endif
}

//==============================================================================
//Func: _signal_handler
//Desc: signal handler
//------------------------------------------------------------------------------
static void _signal_handler(int sig)
{
	switch(sig)
	{
#ifndef WIN32
	case SIGHUP:
		break;
#endif
	case SIGTERM:
		Inst_Log("Terminate signal.\n");
		_g_Term = 1;
		break;
	}
}

void Inst_LogTime()
{
	char szTime[128] = {0};
	_strtime(szTime);
	Inst_Log("[%s]: ", szTime);
}

//==============================================================================
//Func: Inst_Log
//Desc: Print log to a specified file.
//------------------------------------------------------------------------------
void Inst_Log(char *format, ...)
{
	FILE *logfile = NULL;
	va_list ap;
	
	logfile=fopen(LOG_FILE,"a");
	if(logfile)
	{
		va_start(ap, format);
		vfprintf(logfile, format, ap);
		va_end(ap);
		fclose(logfile);
	}

	if(_g_LogToScreen)
	{
		va_start(ap, format);
		vprintf(format, ap);
		va_end(ap);
	}
}

//==============================================================================
//Func: Inst_LogAddrV4
//Desc: Print an IPv4 address to log
//------------------------------------------------------------------------------
void Inst_LogAddrV4(const address_p pAddr)
{
	char strIp[INET_ADDRSTRLEN + 1];

#ifdef WIN32
	sprintf(strIp, "%u.%u.%u.%u",
		pAddr->sa_in.sin_addr.S_un.S_un_b.s_b1,
		pAddr->sa_in.sin_addr.S_un.S_un_b.s_b2,
		pAddr->sa_in.sin_addr.S_un.S_un_b.s_b3,
		pAddr->sa_in.sin_addr.S_un.S_un_b.s_b4);
#else
	inet_ntop(AF_INET, &pAddr->sa_in.sin_addr,
		strIp, INET_ADDRSTRLEN);
#endif
		
	Inst_Log("%s:%u", strIp, htons(pAddr->sa_in.sin_port));
}

//==============================================================================
//Func: Inst_Create
//Desc: Create a new instance class
//------------------------------------------------------------------------------
fwdinst_p Inst_Create(bool_t DoDaemonize, const char*cfg_file)
{
	fwdinst_p pInst = NULL;

	_tzset();
	
	if(DoDaemonize && !_Inst_Daemonize())
		return NULL;
	
	pInst = malloc(sizeof(fwdinst_t));
	if(!pInst)
	{
		Inst_LogTime();
		Inst_Log("Out of memory.\n");
		return NULL;
	}
	memset(pInst, 0, sizeof(fwdinst_t));
	
	Inst_LogTime();
	Inst_Log("Starting "EXEC_NAME"\n");

	if(!_Inst_LoadCFG(pInst, cfg_file))
		goto ErrHandler;
	
	return pInst;
ErrHandler:
	Inst_Term(pInst);
	return NULL;
}

//==============================================================================
//Func: _CreateNBIOTCPSocket
//Desc: Create a new socket, and set it to non blocking I/O mode
//------------------------------------------------------------------------------
static int _CreateNBIOTCPSocket()
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(fd == -1)
	{
		Inst_LogTime();
		Inst_Log("Create socket failed. %d\n", socket_errno);
		return-1;
	}
	
	if(!_SetSocketBlockingEnabled(fd, 0))
	{
		closesocket(fd);
		return -1;
	}
	return fd;
}

//==============================================================================
//Func: _CreateNBIOTCPSocketWithConnection
//Desc: Create a new socket with connection, and set it to non blocking I/O mode
//------------------------------------------------------------------------------
static int _CreateNBIOTCPSocketWithConnection
(
	const address_p addr,
	socklen_t addrlen
)
{
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(fd == -1)
	{
		Inst_LogTime();
		Inst_Log("Create socket failed.\n");
		return-1;
	}
	
	if(!_SetSocketBlockingEnabled(fd, 0))
	{
		closesocket(fd);
		return -1;
	}
	
	Inst_LogTime();
	Inst_Log("Connecting ");
	Inst_LogAddrV4(addr);
	Inst_Log(" ...\n");

	if(connect(fd, &addr->sa, addrlen) < 0)
	{
		int Err = socket_errno;
		switch(Err)
		{
		case EINPROGRESS:
#if EWOULDBLOCK != EAGAIN
		case EWOULDBLOCK:
#endif
		case EAGAIN:
			break;
		default:
			Inst_LogTime();
			Inst_Log("Connect ");
			Inst_LogAddrV4(addr);
			Inst_Log(" failed: %d.\n", Err);
			closesocket(fd);
			return -1;
		}
	}
	
	return fd;
}

//==============================================================================
//Func: _MakeIPv4Address
//Desc: Make an IPv4 address by using given IP:Port
//------------------------------------------------------------------------------
static void _MakeIPv4Address(address_p pOut, uint32_t IP, uint16_t Port)
{
	memset(pOut, 0, sizeof(pOut->sa_in));
	
	pOut->sa_in.sin_family = AF_INET;
	pOut->sa_in.sin_port = htons(Port);
	pOut->sa_in.sin_addr.s_addr = htonl(IP);
}

//==============================================================================
//Func: _ListenPort
//Desc: Let a socket listen to a specified port.
//------------------------------------------------------------------------------
static bool_t _ListenPort(fwdinst_p pInst, int sockfd, int port)
{
	address_t Addr;
	int reuse_addr = 1;
	_MakeIPv4Address(&Addr, 0, port);

	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse_addr, sizeof(reuse_addr)) < 0)
	{
		Inst_LogTime();
		Inst_Log("Warning: set SO_REUSEADDR failed. %d\n", socket_errno);
		return 0;
	}

	if(bind(sockfd, &Addr.sa, sizeof(Addr.sa)) < 0)
	{
		Inst_LogTime();
		Inst_Log("Bind port %d failed. %d\n", port, socket_errno);
		return 0;
	}
	
	if(listen(sockfd, pInst->listen_backlog) < 0)
	{
		int Err = socket_errno;
		switch(Err)
		{
		case EADDRINUSE:
			Inst_LogTime();
			Inst_Log("Listen to port failed: port already in use.\n");
			return 0;
		default:
			Inst_LogTime();
			Inst_Log("Listen to port failed: %d\n", Err);
			return 0;
		}
	}
	
	Inst_LogTime();
	Inst_Log("Listening to port %d.\n", port);

	return 1;
}

//==============================================================================
//Func: _Inst_AddRoute
//Desc: Add a route rule for the instance
//------------------------------------------------------------------------------
static fwdroute_p _Inst_AddRoute
(
	fwdinst_p pInst,
	int import,
	uint32_t exportAddr,
	int exportPort,
	int status_of_tcp_nodelay, // Use nagle algorithm? 1=no, 0=yes
	int packet_size_to_src,
	int packet_size_to_dst
)
{
	size_t cur;
	if(pInst->num_route >= pInst->max_route)
	{
		fwdroute_p pnew = realloc(pInst->pRoute,
			(pInst->max_route + 16) * sizeof(fwdroute_t));
		if(!pnew)
		{
			Inst_LogTime();
			Inst_Log("Out of memory.\n");
			return NULL;
		}
		pInst->pRoute = pnew;
		pInst->max_route += 16;
	}
	
	cur = pInst->num_route;
	memset(&pInst->pRoute[cur], 0, sizeof(fwdroute_t));
	
	if(packet_size_to_src <= 0)
		packet_size_to_src = def_packet_size;
	if(packet_size_to_dst <= 0)
		packet_size_to_dst = def_packet_size;

	//Initialize
	pInst->pRoute[cur].import = import;
	pInst->pRoute[cur].export = exportPort;
	pInst->pRoute[cur].packet_size_to_src = packet_size_to_src;
	pInst->pRoute[cur].packet_size_to_dst = packet_size_to_dst;
	_MakeIPv4Address(&pInst->pRoute[cur].DestAddr, exportAddr, exportPort);
	pInst->pRoute[cur].cbDestAddr = sizeof(struct sockaddr);
	pInst->pRoute[cur].status_of_tcp_nodelay = status_of_tcp_nodelay;
	
	Inst_LogTime();
	Inst_Log("Redirect: localhost:%d -> ", import);
	Inst_LogAddrV4(&pInst->pRoute[cur].DestAddr);
	Inst_Log(", TCP_NODELAY = %d, packet_size_to_src = %d, packet_size_to_dst = %d\n",
		pInst->pRoute[cur].status_of_tcp_nodelay,
		pInst->pRoute[cur].packet_size_to_src,
		pInst->pRoute[cur].packet_size_to_dst);

	if(pInst->pRoute[cur].packet_size_to_src > 8192)
	{
		Inst_LogTime();
		Inst_Log("Warning: `packet to source' should not exceed 8192 bytes.\n");
		pInst->pRoute[cur].packet_size_to_src = 8192;
	}
	if(pInst->pRoute[cur].packet_size_to_dst > 8192)
	{
		Inst_LogTime();
		Inst_Log("Warning: `packet to dest' size should not exceed 8192 bytes.\n");
		pInst->pRoute[cur].packet_size_to_dst = 8192;
	}
	
	//Create the socket
	pInst->pRoute[cur].listen_socket = _CreateNBIOTCPSocket();
	if(pInst->pRoute[cur].listen_socket == -1)
		return NULL;
	
	if(!_ListenPort(pInst, pInst->pRoute[cur].listen_socket, import))
		return NULL;
	
	pInst->num_route++;
	return &pInst->pRoute[cur];
}

//==============================================================================
//Func: _Inst_AddNewConnection
//Desc: Add a socket to a route, called when accepted a new connection.
//------------------------------------------------------------------------------
static fwdconn_p _Inst_AddNewConnection
(
	fwdroute_p pRoute,
	int sockfd,
	address_p pAddr,
	socklen_t cbAddr
)
{
	int sockfd_out = _CreateNBIOTCPSocketWithConnection(&pRoute->DestAddr,
		pRoute->cbDestAddr);
	if(sockfd_out == -1)
		return NULL;

	if(setsockopt(sockfd_out, IPPROTO_TCP, TCP_NODELAY,
		(char*)&pRoute->status_of_tcp_nodelay,
		sizeof(pRoute->status_of_tcp_nodelay)) < 0)
	{
		Inst_LogTime();
		Inst_Log("Warning: setsockopt(TCP_NODELAY) failed:%d.\n", socket_errno);
	}
	
	if(pRoute->num_fwd_conn >= pRoute->max_fwd_conn)
	{
		fwdconn_p pnew = realloc(pRoute->fwd_conn,
			(pRoute->max_fwd_conn + num_conn_alloc) * sizeof(fwdconn_t));
		if(!pnew)
		{
			Inst_LogTime();
			Inst_Log("Out of memory.\n");
			return 0;
		}
		pRoute->fwd_conn = pnew;
		pRoute->max_fwd_conn += num_conn_alloc;
	}

	memset(&pRoute->fwd_conn[pRoute->num_fwd_conn], 0, sizeof(fwdconn_t));
	
	pRoute->fwd_conn[pRoute->num_fwd_conn].sockfd_src = sockfd;
	pRoute->fwd_conn[pRoute->num_fwd_conn].sockfd_dst = sockfd_out;
	pRoute->fwd_conn[pRoute->num_fwd_conn].addr_from = *pAddr;
	pRoute->fwd_conn[pRoute->num_fwd_conn].addr_size = cbAddr;
	return &pRoute->fwd_conn[pRoute->num_fwd_conn++];
}

//==============================================================================
//Func: _Inst_BreakConnection
//Desc: close a specific connection.
//------------------------------------------------------------------------------
static void _Inst_BreakConnection(fwdroute_p pRoute, size_t ic)
{
	if(ic >= pRoute->num_fwd_conn)
		return;

	Inst_LogTime();
	Inst_Log("Connection closed: from ");
	Inst_LogAddrV4(&pRoute->fwd_conn[ic].addr_from);
	Inst_Log(" to ");
	Inst_LogAddrV4(&pRoute->DestAddr);
	Inst_Log("\n");
	
	if(pRoute->fwd_conn[ic].sockfd_src != -1)
		closesocket(pRoute->fwd_conn[ic].sockfd_src);
	pRoute->fwd_conn[ic].sockfd_src = -1;
	
	if(pRoute->fwd_conn[ic].sockfd_dst != -1)
		closesocket(pRoute->fwd_conn[ic].sockfd_dst);
	pRoute->fwd_conn[ic].sockfd_dst = -1;
	
	if(pRoute->num_fwd_conn > 1)
	{
		pRoute->fwd_conn[ic] = pRoute->fwd_conn[--pRoute->num_fwd_conn];
		if(pRoute->num_fwd_conn + num_conn_alloc < pRoute->max_fwd_conn)
		{
			pRoute->max_fwd_conn -= num_conn_alloc;
			if(pRoute->max_fwd_conn)
			{
				fwdconn_p pshrink = realloc(pRoute->fwd_conn,
					pRoute->max_fwd_conn * sizeof(fwdconn_t));
				if(pshrink)
					pRoute->fwd_conn = pshrink;
			}
		}
	}
	else
		pRoute->num_fwd_conn = 0;
}

//==============================================================================
//Func: _IpAddrV4ByNums
//Desc: Combine 4 numbers to an ipv4 address
//------------------------------------------------------------------------------
static uint32_t _IpAddrV4ByNums(int n1, int n2, int n3, int n4)
{
	return
		((n4 & 0xFF)) |
		((n3 & 0xFF) << 8) |
		((n2 & 0xFF) << 16) |
		((n1 & 0xFF) << 24);
}

//==============================================================================
//Func: _Inst_LoadCFG
//Desc: Load configurations
//------------------------------------------------------------------------------
static bool_t _Inst_LoadCFG(fwdinst_p pInst, const char*cfg_file)
{
	FILE*cfgfile = NULL;
	char LineBuf[256] = {0};
	char*pChr;
	unsigned LineNo = 0;
	
	cfgfile = fopen(cfg_file, "r");
	if(!cfgfile)
	{
		Inst_LogTime();
		Inst_Log("Configure file not found: %s\nCreating DEMO configure file.\n",
			cfg_file);
		cfgfile = fopen(cfg_file, "w");
		if(!cfgfile)
		{
			Inst_LogTime();
			Inst_Log("Could not create config file %s\n", cfg_file);
			return 0;
		}
		
		fprintf(cfgfile,
"# Max acceptable connections\n"
"listen_backlog %u\n"
"\n"
"# Do we write any packet traffics to the log file?\n"
"# If yes, set it to 1, this may let the log file become very big.\n"
"log_traffic 0\n"
"\n"
"# Set a forwarding rule, the parameters is:\n"
"# redirect <port>, <destination ip>:<destination port>, [1|0 for set TCP_NODELAY], [source MTU], [destnation MTU]\n"
"# Default MTU is %u\n"
"# Here comes an example\n"
"redirect 80, 192.168.1.105:80, 1, 8192, 8192\n",
			backlog_default, def_packet_size);
		
		fclose(cfgfile);
		return 0;
	}
	
	pInst->listen_backlog = backlog_default;
	pInst->log_traffic = 0;
	do
	{
		int n1, n2, n3, n4, n5, n6, n7, n8, n9;
		int fields;
		if(!fgets(LineBuf, sizeof(LineBuf), cfgfile))
			break;
		LineNo++;
		pChr = LineBuf;
		while(isspace(*pChr))
			pChr++;
		if(*pChr == '#') // Comment
			continue;
		if(sscanf(pChr, "listen_backlog %d", &n1) == 1)
		{
			pInst->listen_backlog = n1;
			Inst_LogTime();
			Inst_Log("listen backlog = %d\n", n1);
		}
		else if(sscanf(pChr, "log_traffic %d", &n1) == 1)
		{
			pInst->log_traffic = n1;
			Inst_LogTime();
			Inst_Log("log traffic = %d\n", n1);
		}
		else
		{
			n7 = 0;
			n8 = n9 = def_packet_size;
			fields = sscanf(pChr, "redirect %d,%d.%d.%d.%d:%d,%d,%d,%d",
				&n1, &n2, &n3, &n4, &n5, &n6, &n7, &n8, &n9);

			if(fields >= 6)
			{
				fwdroute_p pnew = _Inst_AddRoute(pInst, n1,
					_IpAddrV4ByNums(n2, n3, n4, n5), n6, n7, n8, n9);
				if(!pnew)
				{
					Inst_LogTime();
					Inst_Log("Add redirect option failed at line %u\n", LineNo);
				}
			}
		}
	}while(!feof(cfgfile));
	
	fclose(cfgfile);
	
	if(!pInst->num_route)
	{
		Inst_LogTime();
		Inst_Log("No routes added. Quitting.\n");
		return 0;
	}
	return 1;
}

//==============================================================================
//Func: Inst_Term
//Desc: Terminate instance, clear memory
//------------------------------------------------------------------------------
void Inst_Term(fwdinst_p pInst)
{
	Inst_LogTime();
	Inst_Log(EXEC_NAME" stopped.\n\n");
	if(pInst)
	{
		size_t i;
		for(i = 0; i < pInst->num_route; i++)
		{
			size_t j;
			for(j = 0; j < pInst->pRoute[i].num_fwd_conn; j++)
			{
				_Inst_BreakConnection(&pInst->pRoute[i], j);
			}
			free(pInst->pRoute[i].fwd_conn);
		}
		free(pInst->pRoute);
		free(pInst);
	}
}

//==============================================================================
//Func: Inst_Run
//Desc: Run instance, do forwarding
//------------------------------------------------------------------------------
int Inst_Run(fwdinst_p pInst)
{
	size_t i;
	int rv = 0;

	if(pInst->max_route > pInst->num_route)
	{
		pInst->max_route = pInst->num_route;
		pInst->pRoute = realloc(pInst->pRoute,
			pInst->max_route * sizeof(fwdroute_t));
	}
	
	for(i = 0; i < pInst->num_route; i++)
	{
		fwdroute_p pRoute = &pInst->pRoute[i];
		address_t addr_from;
		socklen_t cb_addr_from = sizeof(addr_from.sa);
		int sockfd;
		size_t j;
		
		sockfd = accept(pRoute->listen_socket, &addr_from.sa, &cb_addr_from);
		if(sockfd == -1)
		{
			int Err = socket_errno;
			switch(Err)
			{
#if EWOULDBLOCK != EAGAIN
		case EWOULDBLOCK:
#endif
			case EAGAIN:
				break;
			case EPERM:
				Inst_LogTime();
				Inst_Log("Accept connection failed: firewall rules forbid connection.\n");
				break;
			default:
				Inst_LogTime();
				Inst_Log("Accept connection failed: %d.\n", Err);
				break;
			}
		}
		else
		{
			rv = 1;
			if(_SetSocketBlockingEnabled(sockfd, 0))
			{
				if(addr_from.sa.sa_family == AF_INET)
				{
					fwdconn_p pConn;
				
					Inst_LogTime();
					Inst_Log("Accepted new connection from ");
					Inst_LogAddrV4(&addr_from);
					Inst_Log("\n");
				
					pConn = _Inst_AddNewConnection(pRoute, sockfd, &addr_from, cb_addr_from);
					if(!pConn)
					{
						closesocket(sockfd);
						break;
					}
				}
				else
					;//TODO: Add IPv6 support
			}
		}
		
		for(j = 0; j < pRoute->num_fwd_conn; j++)
		{
			size_t cbSendSize;

			//=================================================================
			//Receive data from source
			//-----------------------------------------------------------------
			if(pRoute->fwd_conn[j].cb_src < fwd_buffer_size)
			{
				ssize_t cbRecv = recv(pRoute->fwd_conn[j].sockfd_src,
					(char*)pRoute->fwd_conn[j].buffer_src
					+ pRoute->fwd_conn[j].cb_src,
					fwd_buffer_size - pRoute->fwd_conn[j].cb_src, 0);
				if(cbRecv > 0)
				{
					rv = 1;
					pRoute->fwd_conn[j].cb_src += cbRecv;
					if(pInst->log_traffic)
					{
						Inst_LogTime();
						Inst_Log("Received %u bytes from source ", cbRecv);
						Inst_LogAddrV4(&pRoute->fwd_conn[j].addr_from);
						Inst_Log("\n"); 
					}
				}
				else if(cbRecv == 0)
				{
					Inst_LogTime();
					Inst_Log("Lost connection from source: ");
					Inst_LogAddrV4(&pRoute->fwd_conn[j].addr_from);
					Inst_Log("\n");
					_Inst_BreakConnection(pRoute, j);
					goto BreakLoop;
				}
				else if(cbRecv < 0)
				{
					int Err = socket_errno;
					switch(Err)
					{
					case EINPROGRESS:
#if EWOULDBLOCK != EAGAIN
					case EWOULDBLOCK:
#endif
					case EAGAIN:
						break;
					case ECONNABORTED:
					case ENOTCONN:
						Inst_LogTime();
						Inst_Log("Lost connection from source: ");
						Inst_LogAddrV4(&pRoute->fwd_conn[j].addr_from);
						Inst_Log("\n");
						_Inst_BreakConnection(pRoute, j);
						goto BreakLoop;
					case ECONNRESET:
						Inst_LogTime();
						Inst_Log("Connection reset by source: ");
						Inst_LogAddrV4(&pRoute->fwd_conn[j].addr_from);
						Inst_Log("\n");
						_Inst_BreakConnection(pRoute, j);
						goto BreakLoop;
					case ECONNREFUSED:
						Inst_LogTime();
						Inst_Log("Connection refused by source: ");
						Inst_LogAddrV4(&pRoute->fwd_conn[j].addr_from);
						Inst_Log("\n");
						_Inst_BreakConnection(pRoute, j);
						goto BreakLoop;
					default:
						Inst_LogTime();
						Inst_Log("An error occured (%d) while receiving data from "
							"source ", Err);
						Inst_LogAddrV4(&pRoute->fwd_conn[j].addr_from);
						Inst_Log("\n");
						_Inst_BreakConnection(pRoute, j);
						goto BreakLoop;
					}
				}
			}

			//=================================================================
			//Send data to destination
			//-----------------------------------------------------------------
			if(pRoute->fwd_conn[j].cb_src > 0 )
			{
				ssize_t cbSend;
				cbSendSize = pRoute->fwd_conn[j].cb_src;
				if(cbSendSize > pRoute->packet_size_to_dst)
					cbSendSize = pRoute->packet_size_to_dst;
				cbSend = send(pRoute->fwd_conn[j].sockfd_dst,
					pRoute->fwd_conn[j].buffer_src,
					cbSendSize, MSG_NOSIGNAL);
				if(cbSend > 0 && cbSend <= pRoute->fwd_conn[j].cb_src)
				{
					rv = 1;
					pRoute->fwd_conn[j].cb_src -= cbSend;
					if(pRoute->fwd_conn[j].cb_src)
					{
						memmove(pRoute->fwd_conn[j].buffer_src,
							(char*)pRoute->fwd_conn[j].buffer_src + cbSend,
							pRoute->fwd_conn[j].cb_src);
					}
					if(!pRoute->fwd_conn[j].connected)
					{
						Inst_LogTime();
						Inst_Log("Connected to destination: ");
						Inst_LogAddrV4(&pRoute->DestAddr);
						Inst_Log("\n");
						pRoute->fwd_conn[j].connected = 1;
					}
					if(pInst->log_traffic)
					{
						Inst_LogTime();
						Inst_Log("Sent %u bytes from source ", cbSend);
						Inst_LogAddrV4(&pRoute->fwd_conn[j].addr_from);
						Inst_Log(" to destination "); 
						Inst_LogAddrV4(&pRoute->DestAddr);
						Inst_Log("\n");
					}
				}
				else if(cbSend < 0)
				{
					int Err = socket_errno;
					switch(Err)
					{
					case EINPROGRESS:
					case ENOTCONN:
						// Inst_Log("c");
						pRoute->fwd_conn[j].connected = 0;
						break;
#if EWOULDBLOCK != EAGAIN
					case EWOULDBLOCK:
#endif
					case EAGAIN:
						break;
					case ECONNABORTED:
						Inst_LogTime();
						Inst_Log("Connection aborted by destination: ");
						Inst_LogAddrV4(&pRoute->DestAddr);
						Inst_Log("\n");
						_Inst_BreakConnection(pRoute, j);
						goto BreakLoop;
					case ECONNRESET:
						Inst_LogTime();
						Inst_Log("Connection reset by destination: ");
						Inst_LogAddrV4(&pRoute->DestAddr);
						Inst_Log("\n");
						_Inst_BreakConnection(pRoute, j);
						goto BreakLoop;
					case ECONNREFUSED:
						Inst_LogTime();
						Inst_Log("Connection refused by destination: ");
						Inst_LogAddrV4(&pRoute->fwd_conn[j].addr_from);
						Inst_Log("\n");
						_Inst_BreakConnection(pRoute, j);
						goto BreakLoop;
					default:
						Inst_LogTime();
						Inst_Log("An error occured (%d) while sending data to destination ", Err);
						Inst_LogAddrV4(&pRoute->DestAddr);
						Inst_Log("\n");
						_Inst_BreakConnection(pRoute, j);
						goto BreakLoop;
					}
				}
			}

			
			//=================================================================
			//Receive data from destination
			//-----------------------------------------------------------------
			if(pRoute->fwd_conn[j].cb_dst < fwd_buffer_size)
			{
				ssize_t cbRecv = recv(pRoute->fwd_conn[j].sockfd_dst,
					(char*)pRoute->fwd_conn[j].buffer_dst
					+ pRoute->fwd_conn[j].cb_dst,
					fwd_buffer_size - pRoute->fwd_conn[j].cb_dst, 0);
				if(cbRecv > 0)
				{
					rv = 1;
					pRoute->fwd_conn[j].cb_dst += cbRecv;
					if(pInst->log_traffic)
					{
						Inst_LogTime();
						Inst_Log("Received %u bytes from destination ", cbRecv);
						Inst_LogAddrV4(&pRoute->DestAddr);
						Inst_Log("\n"); 
					}
				}
				else if(cbRecv == 0)
				{
					Inst_LogTime();
					Inst_Log("Lost connection from source: ");
					Inst_LogAddrV4(&pRoute->fwd_conn[j].addr_from);
					Inst_Log("\n");
					_Inst_BreakConnection(pRoute, j);
					goto BreakLoop;
				}
				else if(cbRecv < 0)
				{
					int Err = socket_errno;
					switch(Err)
					{
					case EINPROGRESS:
					case ENOTCONN:
						pRoute->fwd_conn[j].connected = 0;
						break;
#if EWOULDBLOCK != EAGAIN
					case EWOULDBLOCK:
#endif
					case EAGAIN:
						break;
					case ECONNABORTED:
						Inst_LogTime();
						Inst_Log("Connection aborted by destination: ");
						Inst_LogAddrV4(&pRoute->fwd_conn[j].addr_from);
						Inst_Log("\n");
						_Inst_BreakConnection(pRoute, j);
						goto BreakLoop;
					case ECONNRESET:
						Inst_LogTime();
						Inst_Log("Connection reset by destination: ");
						Inst_LogAddrV4(&pRoute->fwd_conn[j].addr_from);
						Inst_Log("\n");
						_Inst_BreakConnection(pRoute, j);
						goto BreakLoop;
					case ECONNREFUSED:
						Inst_LogTime();
						Inst_Log("Connection refused by destination: ");
						Inst_LogAddrV4(&pRoute->fwd_conn[j].addr_from);
						Inst_Log("\n");
						_Inst_BreakConnection(pRoute, j);
						goto BreakLoop;
					default:
						Inst_LogTime();
						Inst_Log("An error occured (%d) while receiving data from destination ", Err);
						Inst_LogAddrV4(&pRoute->fwd_conn[j].addr_from);
						Inst_Log("\n");
						_Inst_BreakConnection(pRoute, j);
						goto BreakLoop;
					}
				}
			}
			

			//=================================================================
			//Send data to source
			//-----------------------------------------------------------------
			if(pRoute->fwd_conn[j].cb_dst > 0 )
			{
				ssize_t cbSend;
				cbSendSize = pRoute->fwd_conn[j].cb_dst;
				if(cbSendSize > pRoute->packet_size_to_src)
					cbSendSize = pRoute->packet_size_to_src;
				cbSend = send(pRoute->fwd_conn[j].sockfd_src,
					pRoute->fwd_conn[j].buffer_dst,
					cbSendSize, MSG_NOSIGNAL);
				if(cbSend > 0 && cbSend <= pRoute->fwd_conn[j].cb_dst)
				{
					rv = 1;
					pRoute->fwd_conn[j].cb_dst -= cbSend;
					if(pRoute->fwd_conn[j].cb_dst)
					{
						memmove(pRoute->fwd_conn[j].buffer_dst,
							(char*)pRoute->fwd_conn[j].buffer_dst + cbSend,
							pRoute->fwd_conn[j].cb_dst);
					}
					if(pInst->log_traffic)
					{
						Inst_LogTime();
						Inst_Log("Sent %u bytes from destination ", cbSend);
						Inst_LogAddrV4(&pRoute->DestAddr);
						Inst_Log(" to source "); 
						Inst_LogAddrV4(&pRoute->fwd_conn[j].addr_from);
						Inst_Log("\n");
					}
				}
				else if(cbSend < 0)
				{
					int Err = socket_errno;
					switch(Err)
					{
					case EINPROGRESS:
#if EWOULDBLOCK != EAGAIN
					case EWOULDBLOCK:
#endif
					case EAGAIN:
						break;
					case ENOTCONN:
					case ECONNABORTED:
						Inst_LogTime();
						Inst_Log("Connection aborted by source: ");
						Inst_LogAddrV4(&pRoute->DestAddr);
						Inst_Log("\n");
						_Inst_BreakConnection(pRoute, j);
						goto BreakLoop;
					case ECONNRESET:
						Inst_LogTime();
						Inst_Log("Connection reset by source: ");
						Inst_LogAddrV4(&pRoute->DestAddr);
						Inst_Log("\n");
						_Inst_BreakConnection(pRoute, j);
						goto BreakLoop;
					case ECONNREFUSED:
						Inst_LogTime();
						Inst_Log("Connection refused by source: ");
						Inst_LogAddrV4(&pRoute->fwd_conn[j].addr_from);
						Inst_Log("\n");
						_Inst_BreakConnection(pRoute, j);
						goto BreakLoop;
					default:
						Inst_LogTime();
						Inst_Log("An error occured (%d) while sending data to source ", Err);
						Inst_LogAddrV4(&pRoute->DestAddr);
						Inst_Log("\n");
						_Inst_BreakConnection(pRoute, j);
						goto BreakLoop;
					}
				}
			}

		}
	}
BreakLoop:
	return rv;
}

//==============================================================================
//Func: _Inst_Daemonize
//Desc: Make program run as a daemon
//------------------------------------------------------------------------------
static int _Inst_Daemonize()
{
#ifndef WIN32
	int i,lfp;
	char str[10];
	
	if(getppid() == 1)
	{
		fprintf(stderr, EXEC_NAME" was still running.\n");
		return 0;
	}
	
	i = fork();
	if(i < 0)
	{
		// fork error
		return 0;
	}
	if(i > 0)
	{
		// Parent exits, child (daemon) continues
		return 0;
	}
	
	setsid(); // obtain a new process group
	
	fclose(stdin);
	fclose(stdout);
	fclose(stderr);
	
	lfp=open(LOCK_FILE,O_RDWR|O_CREAT,0644);
	if(lfp<0)
	{
		// Could not open lock file.
		Inst_LogTime();
		Inst_Log("Open lock file failed.\n");
		return 0;
	}
	
	if(lockf(lfp, F_TLOCK, 0) < 0)
	{
		// can not lock
		Inst_LogTime();
		Inst_Log("Lock lock file failed.\n");
		return 0;
	}
	
	// first instance continues
	sprintf(str,"%d\n",getpid());
	write(lfp,str,strlen(str)); // record pid to lockfile
	
	signal(SIGCHLD,SIG_IGN); // ignore child
	signal(SIGTSTP,SIG_IGN); // ignore tty signals
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	signal(SIGPIPE,SIG_IGN);
	signal(SIGHUP,_signal_handler); // catch hangup signal
#endif
	signal(SIGTERM,_signal_handler); // catch kill signal
	
	return 1;
}

//==============================================================================
//Func: main
//Desc: Entry point
//------------------------------------------------------------------------------
int main(int argc, char**argv)
{
	fwdinst_p pInst;
	bool_t DoDaemonize = 0;
	char*sz_cfg_file = CFG_FILE;

#ifdef WIN32
	{
		WSADATA wsaData;
		WSAStartup(WINSOCK_VERSION, &wsaData);
	}
#else
	{
		int c;

		for(;;)
		{
			c = getopt(argc, argv, "c:dvh");
			if(c == -1)
				break;

			switch(c)
			{
			case'c'://Customize config file
				sz_cfg_file = optarg;
				break;
			case'd'://Run as a daemon
				DoDaemonize = 1;
				_g_LogToScreen = 0;
				break;
			default:
				fprintf(stderr, "Unknown option '%c'\n", c);
			case'h':
				fprintf(stderr, "Usage:\n"
					EXEC_NAME" [-c cfgfile][-d][-v][-h]\n"
					" -c: set config file"
					" -d: run as a daemon\n"
					" -h: show this help\n");
				break;
			}
		}
	}
#endif
	
	pInst = Inst_Create(DoDaemonize, sz_cfg_file);
	if(pInst)
	{
		bo_t bo;
		bo_reset(&bo);
		while(!_g_Term)
		{
			if(Inst_Run(pInst))
				bo_reset(&bo);
			else
				bo_update(&bo);
		}
		Inst_Term(pInst);
	}
#ifdef WIN32
	WSACleanup();
#endif
	return 0;
}

