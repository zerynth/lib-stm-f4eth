"""
.. module:: f4eth

******************************
STM32F4 Native Ethernet Module
******************************

This module implements the Zerynth driver for the STM32 F4 family Ethernet.
This module supports SSL/TLS

To use it: ::

    import streams
    from stm.f4eth import f4eth as eth

    streams.serial()

    print("...")

    eth.auto_init()
    eth.link()
    print(eth.link_info())


    """




@native_c("f4_eth_init",
    [
        "#csrc/misc/zstdlib.c",
        "#csrc/misc/snprintf.c",
        "#csrc/zsockets/*",
        #-if ZERYNTH_SSL
        "#csrc/tls/mbedtls/library/*",
        #-endif
        "csrc/eth_ifc.c",
        "csrc/eth/ethernetif.c",
        "csrc/eth/src/stm32f4xx_hal_eth.c",
        "csrc/eth/src/stm32f4xx_hal_gpio.c",
        "csrc/lwip/api/*",
        "csrc/lwip/core/*",
        "csrc/lwip/core/ipv4/*",
        "csrc/lwip/netif/ethernet.c",
        "csrc/lwip/system/OS/*"
    ],
    [
        "VHAL_ETH"
    ],
    [
        "-I.../csrc",
        "-I.../csrc/eth",
        "-I.../csrc/eth/inc",
        "-I.../csrc/lwip/include",
        "-I.../csrc/lwip/system",
        "-I.../csrc/lwip",
        "-I#csrc/zsockets",
        "-I#csrc/misc",
        #-if ZERYNTH_SSL
        "-I#csrc/tls/mbedtls/include"
        #-endif
    ]
)
def _hwinit():
    pass

def auto_init():
    init()

def init():
    """
..  function:: init()

    Initializes the Ethernet chip connected to the device.

    The Ethernet chip is setup and can be managed using the :ref:`Ethernet Module <stdlib_eth>` of the Zerynth Standard Library.
    """
    _hwinit()
    __builtins__.__default_net["eth"] = __module__
    __builtins__.__default_net["sock"][0] = __module__ #AF_INET
    __builtins__.__default_net["ssl"] = __module__


@native_c("f4_eth_link",[],[])
def link():
    pass

@native_c("f4_eth_is_linked",[],[])
def is_linked():
    pass


@native_c("f4_eth_unlink",["csrc/*"])
def unlink():
    pass


@native_c("f4_net_link_info",[])
def link_info():
    pass

@native_c("f4_net_set_link_info",[])
def set_link_info(ip,mask,gw,dns):
    pass

@native_c("f4_net_resolve",["csrc/*"])
def gethostbyname(hostname):
    pass


@native_c("f4_net_socket",["csrc/*"])
def socket(family,type,proto):
    pass

@native_c("f4_net_setsockopt",["csrc/*"])
def setsockopt(sock,level,optname,value):
    pass


@native_c("f4_net_close",["csrc/*"])
def close(sock):
    pass


@native_c("f4_net_sendto",["csrc/*"])
def sendto(sock,buf,addr,flags=0):
    pass

@native_c("f4_net_send",["csrc/*"])
def send(sock,buf,flags=0):
    pass

@native_c("f4_net_send_all",["csrc/*"])
def sendall(sock,buf,flags=0):
    pass


@native_c("f4_net_recv_into",["csrc/*"])
def recv_into(sock,buf,bufsize,flags=0,ofs=0):
    pass


@native_c("f4_net_recvfrom_into",["csrc/*"])
def recvfrom_into(sock,buf,bufsize,flags=0):
    pass


@native_c("f4_net_bind",["csrc/*"])
def bind(sock,addr):
    pass

@native_c("f4_net_listen",["csrc/*"])
def listen(sock,maxlog=2):
    pass

@native_c("f4_net_accept",["csrc/*"])
def accept(sock):
    pass

@native_c("f4_net_connect",["csrc/*"])
def connect(sock,addr):
    pass

@native_c("f4_net_select",[])
def select(rlist,wist,xlist,timeout):
    pass

@native_c("f4_secure_socket",[],[])
def secure_socket(family, type, proto, ctx):
    pass
