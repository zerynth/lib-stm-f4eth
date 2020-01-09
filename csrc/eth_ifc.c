#include "lwip/netif.h"
#include "lwip/dns.h"
#include "lwip/sockets.h"
#include "lwip/api.h"
#include "lwip/tcpip.h"
#include "lwip/ip_addr.h"
#include "zerynth.h"
#include "zerynth_sockets.h"
#include "zerynth_ssl.h"


#undef printf
// #define printf(...) vbl_printf_stdout(__VA_ARGS__)
#define printf(...)


#define STATUS_IDLE 0
#define STATUS_LINKING 1
#define STATUS_UNLINKING 2



typedef struct _netnfo {
    ip4_addr_t ip;
    ip4_addr_t gw;
    ip4_addr_t mask;
    struct netif ethif;
    uint8_t mac[6];
    uint8_t is_up;
    uint8_t is_linked;
    uint8_t use_dhcp;
} NetInfo;

typedef struct _ethdrv {
    VSemaphore link_lock;
    VSemaphore ssl_lock;
    NetInfo net;
    ip_addr_t dns;
    uint8_t status;
    uint8_t error;
    uint8_t connected;
    uint8_t has_link_info;
} EthDrv;

static EthDrv drv;
SocketAPIPointers f4eth_api;

void init_socket_api_pointers(void) {
    f4eth_api.accept = lwip_accept;
    f4eth_api.bind   = lwip_bind;
    f4eth_api.shutdown = lwip_shutdown;
    f4eth_api.getpeername = lwip_getpeername;
    f4eth_api.getsockname = lwip_getsockname;
    f4eth_api.setsockopt = lwip_setsockopt;
    f4eth_api.close = lwip_close;
    f4eth_api.connect = lwip_connect;
    f4eth_api.listen = lwip_listen;
    f4eth_api.recv = lwip_recv;
    f4eth_api.read = lwip_read;
    f4eth_api.recvfrom = lwip_recvfrom;
    f4eth_api.send = lwip_send;
    f4eth_api.sendto = lwip_sendto;
    f4eth_api.socket = lwip_socket;
    f4eth_api.select = lwip_select;
    f4eth_api.ioctl = lwip_ioctl;
    f4eth_api.fcntl = lwip_fcntl;
    f4eth_api.write = lwip_write;

    f4eth_api.inet_addr = ipaddr_addr;
    f4eth_api.inet_ntoa = ip4addr_ntoa;
}



err_t ethernetif_init(struct netif *netif);

static int netif_config(int dhcp){
  ip_addr_t ipaddr;
  ip_addr_t netmask;
  ip_addr_t gw;

  memcpy(drv.net.ethif.hwaddr,drv.net.mac,6);
  drv.net.ethif.hwaddr[0]=drv.net.ethif.hwaddr[0]&0xfc; //remove unicast bit
  netif_add(&drv.net.ethif, &drv.net.ip, &drv.net.mask, &drv.net.gw, NULL, &ethernetif_init, &tcpip_input);

  /*  Registers the default network interface. */
  netif_set_default(&drv.net.ethif);

  if (netif_is_link_up(&drv.net.ethif))
  {
    /* When the netif is fully configured this function must be called.*/
    netif_set_up(&drv.net.ethif);
    drv.net.is_up = 1;
    printf("ETH UP\n");
    if (dhcp) {
        dhcp_start(&drv.net.ethif);
        int count;
        while (drv.net.ethif.ip_addr.addr==0 && count<100) {
            vosThSleep(TIME_U(100,MILLIS));
            count++;
            printf("-\n");
        }
        if (drv.net.ethif.ip_addr.addr==0) {
            return 1;
        }
        printf("GOT IP %x\n",drv.net.ethif.ip_addr.addr);
        drv.net.use_dhcp = 1;

    } else {
        drv.net.use_dhcp = 0;
    }
    //set dns
    if (drv.dns.addr!=0) {
        //a dns has been requested. Set it instead of the one given by dhcp
        dns_setserver(0,&drv.dns);
    }
    drv.net.is_linked = 1;
    return 0;
  }
  else
  {
    /* When the netif link is down this function must be called */
    netif_set_down(&drv.net.ethif);
    printf("ETH DN\n");
    drv.net.is_linked = 0;
    drv.net.is_up = 0;
  }
  return -1;
}

C_NATIVE(f4_eth_init)
{
    NATIVE_UNWARN();
    int err;
    uint8_t uid[32];
    vhalNfoGetUID(uid);
    memset(&drv, 0, sizeof(EthDrv));
    //set mac from uid
    //f4 ethernet has no mac -_-
    memcpy(drv.net.mac,uid,6);
    drv.ssl_lock = vosSemCreate(1);
    drv.link_lock = vosSemCreate(0);
    init_socket_api_pointers();
    gzsock_init(&f4eth_api);
    tcpip_init(NULL, NULL);

    *res = MAKE_NONE();

    return ERR_OK;
}




C_NATIVE(f4_eth_link)
{
    NATIVE_UNWARN();

    int32_t err=ERR_OK;
    int32_t sem_status;

    *res = MAKE_NONE();

    RELEASE_GIL();


    drv.status = STATUS_LINKING;
    printf("HAS LINK INFO %i\n",drv.has_link_info);
    if (drv.has_link_info) {
        //static address
        if(netif_config(0)!=0) err=ERR_HARDWARE_INITIALIZATION_ERROR;
    } else {
        //dhcp
        if(netif_config(1)!=0) err=ERR_HARDWARE_INITIALIZATION_ERROR;
    }
    drv.status = STATUS_IDLE;

    ACQUIRE_GIL();

    return err;
}


C_NATIVE(f4_eth_unlink)
{
    NATIVE_UNWARN();
    // *res = MAKE_NONE();

    // RELEASE_GIL();
    // drv.status = STATUS_UNLINKING;
    // // esp_err = esp_eth_disable();
    // // if (esp_err != ESP_OK) {
    // //     ACQUIRE_GIL();
    // //     drv.status = STATUS_IDLE;
    // //     return ERR_IOERROR_EXC;
    // // }
    // vosSemWait(drv.link_lock);
    // ACQUIRE_GIL();
    return ERR_UNSUPPORTED_EXC;
}

C_NATIVE(f4_eth_is_linked)
{
    NATIVE_UNWARN();
    if (netif_is_link_up(&drv.net.ethif)) {
        *res = PBOOL_TRUE();
    } else {
        *res = PBOOL_FALSE();
    }
    return ERR_OK;
}


C_NATIVE(f4_net_link_info)
{
    NATIVE_UNWARN();

    NetAddress addr;
    addr.port = 0;

    PTuple* tpl = psequence_new(PTUPLE, 5);

    addr.ip =drv.net.ethif.ip_addr.addr;
    PTUPLE_SET_ITEM(tpl, 0, netaddress_to_object(&addr));
    addr.ip = drv.net.ethif.netmask.addr;
    PTUPLE_SET_ITEM(tpl, 1, netaddress_to_object(&addr));
    addr.ip = drv.net.ethif.gw.addr;
    PTUPLE_SET_ITEM(tpl, 2, netaddress_to_object(&addr));
    addr.ip = dns_getserver(0)->addr; //esp_net_dns.addr;
    PTUPLE_SET_ITEM(tpl, 3, netaddress_to_object(&addr));

    PObject* mac = psequence_new(PBYTES, 6);
    memcpy(PSEQUENCE_BYTES(mac),drv.net.ethif.hwaddr,6);
    PTUPLE_SET_ITEM(tpl, 4, mac);
    *res = tpl;

    return ERR_OK;
}


C_NATIVE(f4_net_set_link_info)
{
    C_NATIVE_UNWARN();

    NetAddress ip;
    NetAddress mask;
    NetAddress gw;
    NetAddress dns;

    if (parse_py_args("nnnn", nargs, args,
            &ip,
            &mask,
            &gw,
            &dns)
        != 4)
        return ERR_TYPE_EXC;

    if (dns.ip == 0) {
        OAL_MAKE_IP(dns.ip, 0, 0, 0, 0);
    }
    if (mask.ip == 0) {
        OAL_MAKE_IP(mask.ip, 255, 255, 255, 0);
    }
    if (gw.ip == 0) {
        OAL_MAKE_IP(gw.ip, OAL_IP_AT(ip.ip, 0), OAL_IP_AT(ip.ip, 1), OAL_IP_AT(ip.ip, 2), 1);
    }

    drv.net.ip.addr = ip.ip;
    drv.net.gw.addr = gw.ip;
    drv.dns.addr = dns.ip;
    drv.net.mask.addr = mask.ip;
    if (ip.ip != 0)
        drv.has_link_info = 1;
    else
        drv.has_link_info = 0;

    *res = MAKE_NONE();
    return ERR_OK;
}

C_NATIVE(f4_net_resolve)
{
    C_NATIVE_UNWARN();
    uint8_t* url;
    uint32_t len;
    int32_t code;
    NetAddress addr;
    if (parse_py_args("s", nargs, args, &url, &len) != 1)
        return ERR_TYPE_EXC;
    addr.ip = 0;
    uint8_t* name = (uint8_t*)gc_malloc(len + 1);
    __memcpy(name, url, len);
    name[len] = 0;
    RELEASE_GIL();
    struct ip4_addr ares;
    code = netconn_gethostbyname(name, &ares);
    ACQUIRE_GIL();
    gc_free(name);
    if (code != ERR_OK)
        return ERR_IOERROR_EXC;
    addr.port = 0;
    addr.ip = ares.addr;
    *res = netaddress_to_object(&addr);
    return ERR_OK;
}

#define DRV_SOCK_DGRAM 1
#define DRV_SOCK_STREAM 0
#define DRV_AF_INET 0

typedef struct sockaddr_in sockaddr_t;

void f4_prepare_addr(sockaddr_t* vmSocketAddr, NetAddress* addr)
{
    vmSocketAddr->sin_family = AF_INET;
    vmSocketAddr->sin_port = addr->port;
    vmSocketAddr->sin_addr.s_addr = addr->ip;
}

C_NATIVE(f4_net_socket)
{
    C_NATIVE_UNWARN();
    int32_t family = DRV_AF_INET;
    int32_t type = DRV_SOCK_STREAM;
    int32_t proto = IPPROTO_TCP;
    int32_t sock;
    if (parse_py_args("III", nargs, args, DRV_AF_INET, &family, DRV_SOCK_STREAM, &type, IPPROTO_TCP, &proto) != 3)
        return ERR_TYPE_EXC;
    if (type != DRV_SOCK_DGRAM && type != DRV_SOCK_STREAM)
        return ERR_TYPE_EXC;
    if (family != DRV_AF_INET)
        return ERR_UNSUPPORTED_EXC;
    //printf("--CMD_SOCKET: %i %x\n", errno, (int)lwip_socket);
    RELEASE_GIL();
    // printf("-CMD_SOCKET: %i %x\n", errno, (int)lwip_socket);
    sock = gzsock_socket(AF_INET, (type == DRV_SOCK_DGRAM) ? SOCK_DGRAM : SOCK_STREAM,
        (type == DRV_SOCK_DGRAM) ? IPPROTO_UDP : IPPROTO_TCP, NULL);
    ACQUIRE_GIL();
    //printf("CMD_SOCKET: %i %i\n", sock, errno);
    if (sock < 0)
        return ERR_IOERROR_EXC;
    *res = PSMALLINT_NEW(sock);
    return ERR_OK;
}

C_NATIVE(f4_net_connect)
{
    C_NATIVE_UNWARN();
    int32_t sock;
    NetAddress addr;

    if (parse_py_args("in", nargs, args, &sock, &addr) != 2)
        return ERR_TYPE_EXC;
    sockaddr_t vmSocketAddr;
    f4_prepare_addr(&vmSocketAddr, &addr);
    RELEASE_GIL();
    sock = gzsock_connect(sock, &vmSocketAddr, sizeof(vmSocketAddr));
    ACQUIRE_GIL();
    printf("CMD_OPEN: %i %i\r\n", sock, 0);
    if (sock < 0) {
        return ERR_IOERROR_EXC;
    }
    *res = PSMALLINT_NEW(sock);
    return ERR_OK;
}

C_NATIVE(f4_net_close)
{
    C_NATIVE_UNWARN();
    int32_t sock;
    int rr;
    if (parse_py_args("i", nargs, args, &sock) != 1)
        return ERR_TYPE_EXC;
    RELEASE_GIL();
    rr = gzsock_close(sock);
    printf("closing sock - result %i\n", rr);
    ACQUIRE_GIL();
    *res = PSMALLINT_NEW(sock);
    return ERR_OK;
}

C_NATIVE(f4_net_send)
{
    C_NATIVE_UNWARN();
    uint8_t* buf;
    int32_t len;
    int32_t flags;
    int32_t sock;
    if (parse_py_args("isi", nargs, args,
            &sock,
            &buf, &len,
            &flags)
        != 3)
        return ERR_TYPE_EXC;
    RELEASE_GIL();
    printf("SEND %i %i\n", sock, len);
    sock = gzsock_send(sock, buf, len, flags);
    ACQUIRE_GIL();
    if (sock < 0) {
        return ERR_IOERROR_EXC;
    }
    *res = PSMALLINT_NEW(sock);
    return ERR_OK;
}

C_NATIVE(f4_net_send_all)
{
    C_NATIVE_UNWARN();
    uint8_t* buf;
    int32_t len;
    int32_t flags;
    int32_t sock;
    int32_t wrt;
    int32_t w;
    if (parse_py_args("isi", nargs, args,
            &sock,
            &buf, &len,
            &flags)
        != 3)
        return ERR_TYPE_EXC;
    RELEASE_GIL();
    wrt = 0;
    while (wrt < len) {
        // printf("sending all to %i %i %i\n",sock,wrt,len);
        w = gzsock_send(sock, buf + wrt, len - wrt, flags);
        if (w < 0)
            break;
        wrt += w;
    }
    // printf("exit sendall %i\n",wrt);
    ACQUIRE_GIL();
    if (w < 0) {
        return ERR_IOERROR_EXC;
    }
    *res = MAKE_NONE();
    return ERR_OK;
}

C_NATIVE(f4_net_sendto)
{
    C_NATIVE_UNWARN();
    uint8_t* buf;
    int32_t len;
    int32_t flags;
    int32_t sock;
    NetAddress addr;
    if (parse_py_args("isni", nargs, args,
            &sock,
            &buf, &len,
            &addr,
            &flags)
        != 4)
        return ERR_TYPE_EXC;

    RELEASE_GIL();
    sockaddr_t vmSocketAddr;
    f4_prepare_addr(&vmSocketAddr, &addr);
    sock = gzsock_sendto(sock, buf, len, flags, &vmSocketAddr, sizeof(sockaddr_t));
    ACQUIRE_GIL();

    if (sock < 0) {
        return ERR_IOERROR_EXC;
    }
    *res = PSMALLINT_NEW(sock);
    return ERR_OK;
}

C_NATIVE(f4_net_recv_into)
{
    C_NATIVE_UNWARN();
    uint8_t* buf;
    int32_t len;
    int32_t sz;
    int32_t flags;
    int32_t ofs;
    int32_t sock;
    //printf("sock %i, buf %s, len %i, sz %i, flag %i, ofs %i\n",args[0],args[1],args[2],args[3],args[4],args[5]);
    if (parse_py_args("isiiI", nargs, args,
            &sock,
            &buf, &len,
            &sz,
            &flags,
            0,
            &ofs)
        != 5)
        return ERR_TYPE_EXC;
    buf += ofs;
    len -= ofs;
    len = (sz < len) ? sz : len;
    RELEASE_GIL();
    int rb = 0;
    int r;
    //printf("sock %i, buf %s, len %i, sz %i, flag %i, ofs %i\n",sock,buf,len,sz,flags,ofs);
    while (rb < len) {
        r = gzsock_recv(sock, buf + rb, len - rb, flags);
        if (r <= 0)
            break;
        rb += r;
    }
    ACQUIRE_GIL();
    //printf("err %i\n",r);
    if (r <= 0) {
       if (r != 0){
            if (r == ERR_TIMEOUT /*|| *__errno() == EAGAIN || *__errno() == ETIMEDOUT*/)
                return ERR_TIMEOUT_EXC;
            return ERR_IOERROR_EXC;
        }
    }
    *res = PSMALLINT_NEW(rb);

    return ERR_OK;
}

C_NATIVE(f4_net_recvfrom_into)
{
    C_NATIVE_UNWARN();
    uint8_t* buf;
    int32_t len;
    int32_t sz;
    int32_t flags;
    int32_t ofs;
    int32_t sock;
    NetAddress addr;
    if (parse_py_args("isiiI", nargs, args,
            &sock,
            &buf, &len,
            &sz,
            &flags,
            0,
            &ofs)
        != 5)
        return ERR_TYPE_EXC;
    buf += ofs;
    len -= ofs;
    len = (sz < len) ? sz : len;

    RELEASE_GIL();
    addr.ip = 0;
    int r;
    sockaddr_t vmSocketAddr;
    socklen_t tlen = sizeof(vmSocketAddr);
    r = gzsock_recvfrom(sock, buf, len, flags, &vmSocketAddr, &tlen);
    ACQUIRE_GIL();
    addr.ip = vmSocketAddr.sin_addr.s_addr;
    addr.port = vmSocketAddr.sin_port;
    if (r < 0) {
        if (r == ETIMEDOUT)
            return ERR_TIMEOUT_EXC;
        return ERR_IOERROR_EXC;
    }
    PTuple* tpl = (PTuple*)psequence_new(PTUPLE, 2);
    PTUPLE_SET_ITEM(tpl, 0, PSMALLINT_NEW(r));
    PObject* ipo = netaddress_to_object(&addr);
    PTUPLE_SET_ITEM(tpl, 1, ipo);
    *res = tpl;
    return ERR_OK;
}

C_NATIVE(f4_net_setsockopt)
{
    C_NATIVE_UNWARN();
    int32_t sock;
    int32_t level;
    int32_t optname;
    int32_t optvalue;

    if (parse_py_args("iiii", nargs, args, &sock, &level, &optname, &optvalue) != 4)
        return ERR_TYPE_EXC;

    if (level == 0xffff)
        level = SOL_SOCKET;

    // SO_RCVTIMEO zerynth value
    if (optname == 1) {
        optname = SO_RCVTIMEO;
    }

    RELEASE_GIL();
    if (optname == SO_RCVTIMEO) {
        struct timeval tms;
        tms.tv_sec = optvalue / 1000;
        tms.tv_usec = (optvalue % 1000) * 1000;
        sock = gzsock_setsockopt(sock, level, optname, &tms, sizeof(struct timeval));
    }
    else {
        sock = gzsock_setsockopt(sock, level, optname, &optvalue, sizeof(optvalue));
    }
    ACQUIRE_GIL();
    if (sock < 0)
        return ERR_IOERROR_EXC;

    *res = MAKE_NONE();
    return ERR_OK;
}

C_NATIVE(f4_net_bind)
{
    C_NATIVE_UNWARN();
    int32_t sock;
    NetAddress addr;
    if (parse_py_args("in", nargs, args, &sock, &addr) != 2)
        return ERR_TYPE_EXC;
    sockaddr_t serverSocketAddr;
    //addr.ip = bcm_net_ip.addr;
    f4_prepare_addr(&serverSocketAddr, &addr);
    RELEASE_GIL();
    sock = gzsock_bind(sock, &serverSocketAddr, sizeof(sockaddr_t));
    ACQUIRE_GIL();
    if (sock < 0)
        return ERR_IOERROR_EXC;
    *res = MAKE_NONE();
    return ERR_OK;
}

C_NATIVE(f4_net_listen)
{
    C_NATIVE_UNWARN();
    int32_t maxlog;
    int32_t sock;
    if (parse_py_args("ii", nargs, args, &sock, &maxlog) != 2)
        return ERR_TYPE_EXC;
    RELEASE_GIL();
    maxlog = gzsock_listen(sock, maxlog);
    ACQUIRE_GIL();
    if (maxlog)
        return ERR_IOERROR_EXC;
    *res = MAKE_NONE();
    return ERR_OK;
}

C_NATIVE(f4_net_accept)
{
    C_NATIVE_UNWARN();
    int32_t sock;
    NetAddress addr;
    if (parse_py_args("i", nargs, args, &sock) != 1)
        return ERR_TYPE_EXC;
    sockaddr_t clientaddr;
    socklen_t addrlen;
    memset(&clientaddr, 0, sizeof(sockaddr_t));
    addrlen = sizeof(sockaddr_t);
    RELEASE_GIL();
    sock = gzsock_accept(sock, &clientaddr, &addrlen);
    ACQUIRE_GIL();
    if (sock < 0)
        return ERR_IOERROR_EXC;
    addr.port = clientaddr.sin_port;
    addr.ip = clientaddr.sin_addr.s_addr;

    PTuple* tpl = (PTuple*)psequence_new(PTUPLE, 2);
    PTUPLE_SET_ITEM(tpl, 0, PSMALLINT_NEW(sock));
    PObject* ipo = netaddress_to_object(&addr);
    PTUPLE_SET_ITEM(tpl, 1, ipo);
    *res = tpl;
    return ERR_OK;
}

C_NATIVE(f4_net_select)
{
    C_NATIVE_UNWARN();
    int32_t timeout;
    int32_t tmp, i, j, sock = -1;

    if (nargs < 4)
        return ERR_TYPE_EXC;

    fd_set rfd;
    fd_set wfd;
    fd_set xfd;
    struct timeval tms;
    struct timeval* ptm;
    PObject* rlist = args[0];
    PObject* wlist = args[1];
    PObject* xlist = args[2];
    fd_set* fdsets[3] = { &rfd, &wfd, &xfd };
    PObject* slist[3] = { rlist, wlist, xlist };
    PObject* tm = args[3];

    if (tm == MAKE_NONE()) {
        ptm = NULL;
    }
    else if (IS_PSMALLINT(tm)) {
        timeout = PSMALLINT_VALUE(tm);
        if (timeout < 0)
            return ERR_TYPE_EXC;
        tms.tv_sec = timeout / 1000;
        tms.tv_usec = (timeout % 1000) * 1000;
        ptm = &tms;
    }
    else
        return ERR_TYPE_EXC;

    for (j = 0; j < 3; j++) {
        tmp = PTYPE(slist[j]);
        if (!IS_OBJ_PSEQUENCE_TYPE(tmp))
            return ERR_TYPE_EXC;
        FD_ZERO(fdsets[j]);
        for (i = 0; i < PSEQUENCE_ELEMENTS(slist[j]); i++) {
            PObject* fd = PSEQUENCE_OBJECTS(slist[j])[i];
            if (IS_PSMALLINT(fd)) {
                //printf("%i -> %i\n",j,PSMALLINT_VALUE(fd));
                FD_SET(PSMALLINT_VALUE(fd), fdsets[j]);
                if (PSMALLINT_VALUE(fd) > sock)
                    sock = PSMALLINT_VALUE(fd);
            }
            else
                return ERR_TYPE_EXC;
        }
    }

    printf("maxsock %i\n", sock);
    RELEASE_GIL();
    tmp = gzsock_select((sock + 1), fdsets[0], fdsets[1], fdsets[2], ptm);
    ACQUIRE_GIL();

    printf("result: %i\n", tmp);

    if (tmp < 0) {
        return ERR_IOERROR_EXC;
    }

    PTuple* tpl = (PTuple*)psequence_new(PTUPLE, 3);
    for (j = 0; j < 3; j++) {
        tmp = 0;
        for (i = 0; i <= sock; i++) {
            if (FD_ISSET(i, fdsets[j]))
                tmp++;
        }
        PTuple* rtpl = psequence_new(PTUPLE, tmp);
        tmp = 0;
        for (i = 0; i <= sock; i++) {
            //printf("sock %i in %i = %i\n",i,j,FD_ISSET(i, fdsets[j]));
            if (FD_ISSET(i, fdsets[j])) {
                PTUPLE_SET_ITEM(rtpl, tmp, PSMALLINT_NEW(i));
                tmp++;
            }
        }
        PTUPLE_SET_ITEM(tpl, j, rtpl);
    }
    *res = tpl;
    return ERR_OK;
}


#define _CERT_NONE 1
#define _CERT_OPTIONAL 2
#define _CERT_REQUIRED 4
#define _CLIENT_AUTH 8
#define _SERVER_AUTH 16


C_NATIVE(f4_secure_socket)
{
    C_NATIVE_UNWARN();
    int32_t err = ERR_OK;
    int32_t family = DRV_AF_INET;
    int32_t type = DRV_SOCK_STREAM;
    int32_t proto = IPPROTO_TCP;
    int32_t sock;
    int32_t i;
    SSLInfo nfo;

    int32_t ssocknum = 0;
    int32_t ctxlen;
    uint8_t* certbuf = NULL;
    uint16_t certlen = 0;
    uint8_t* clibuf = NULL;
    uint16_t clilen = 0;
    uint8_t* pkeybuf = NULL;
    uint16_t pkeylen = 0;
    uint32_t options = _CLIENT_AUTH | _CERT_NONE;
    uint8_t* hostbuf = NULL;
    uint16_t hostlen = 0;

    PTuple* ctx;
    memset(&nfo,0,sizeof(nfo));
    ctx = (PTuple*)args[nargs - 1];
    nargs--;
    if (parse_py_args("III", nargs, args, DRV_AF_INET, &family, DRV_SOCK_STREAM, &type, IPPROTO_TCP, &proto) != 3){
        printf("G\n");
        return ERR_TYPE_EXC;
    }
    if (type != DRV_SOCK_DGRAM && type != DRV_SOCK_STREAM){
        printf("GG\n");
        return ERR_TYPE_EXC;
    }
    if (family != DRV_AF_INET)
        return ERR_UNSUPPORTED_EXC;

    ctxlen = PSEQUENCE_ELEMENTS(ctx);
    if (ctxlen && ctxlen != 5)
        return ERR_TYPE_EXC;

    if (ctxlen) {
        //ssl context passed
        PObject* cacert = PTUPLE_ITEM(ctx, 0);
        PObject* clicert = PTUPLE_ITEM(ctx, 1);
        PObject* ppkey = PTUPLE_ITEM(ctx, 2);
        PObject* host = PTUPLE_ITEM(ctx, 3);
        PObject* iopts = PTUPLE_ITEM(ctx, 4);

        nfo.cacert = PSEQUENCE_BYTES(cacert);
        nfo.cacert_len = PSEQUENCE_ELEMENTS(cacert);
        nfo.clicert = PSEQUENCE_BYTES(clicert);
        nfo.clicert_len = PSEQUENCE_ELEMENTS(clicert);
        nfo.hostname = PSEQUENCE_BYTES(host);
        nfo.hostname_len = PSEQUENCE_ELEMENTS(host);
        nfo.pvkey = PSEQUENCE_BYTES(ppkey);
        nfo.pvkey_len = PSEQUENCE_ELEMENTS(ppkey);
        nfo.options = PSMALLINT_VALUE(iopts);
    }
    RELEASE_GIL();
    printf("%x\n",gzsock_socket);
    sock = gzsock_socket(
          AF_INET,
          (type == DRV_SOCK_DGRAM) ? SOCK_DGRAM : SOCK_STREAM,
          (type == DRV_SOCK_DGRAM) ? IPPROTO_UDP : IPPROTO_TCP,
          (ctxlen) ? &nfo:NULL);
    ACQUIRE_GIL();
    printf("CMD_SOCKET: %i %i\n", sock, errno);
    if (sock < 0)
        return ERR_IOERROR_EXC;
    *res = PSMALLINT_NEW(sock);
    return ERR_OK;
}

