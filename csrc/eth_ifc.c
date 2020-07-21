#include "lwip/opt.h"
#include "lwip/icmp.h"
#include "lwip/inet_chksum.h"
#include "lwip/mem.h"
#include "lwip/inet.h"
#include "netif/etharp.h"
#include "lwip/tcpip.h"
#include "lwip/prot/dhcp.h"
#include "lwip/dhcp.h"

#include "zerynth.h"
#include "zerynth_sockets.h"

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
    f4eth_api.getsockopt = lwip_getsockopt;
    f4eth_api.close = lwip_close;
    f4eth_api.connect = lwip_connect;
    f4eth_api.listen = lwip_listen;
    f4eth_api.recv = lwip_recv;
    f4eth_api.read = lwip_read;
    f4eth_api.recvfrom = lwip_recvfrom;
    f4eth_api.send = lwip_send;
    f4eth_api.sendto = lwip_sendto;
    f4eth_api.socket = lwip_socket;
    f4eth_api.write = lwip_write;
    f4eth_api.select = lwip_select;
    f4eth_api.ioctl = lwip_ioctl;
    f4eth_api.fcntl = lwip_fcntl;
    f4eth_api.getaddrinfo = lwip_getaddrinfo;
    f4eth_api.freeaddrinfo = lwip_freeaddrinfo; 
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
    addr.ip = dns_getserver(0); //esp_net_dns.addr;
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

