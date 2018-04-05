/**
* copyright (c) 2018, James Flynn
* SPDX-License-Identifier: Apache-2.0
*/

/* 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
 
/**----------------------------------------------------------
*   @file   BG96Interface.cpp
*   @brief  BG96 NetworkInterfaceAPI implementation for Mbed OS v5.x
*
*   @author James Flynn
*
*   @date   1-April-2018
*/

#include <ctype.h>
#include "mbed.h"
#include "BG96.h"
#include "BG96Interface.h"

#if MBED_CONF_APP_BG96_DEBUG == true
#define debugOutput(...)      _dbOut(__VA_ARGS__)
#define debugDump_arry(...)   _dbDump_arry(__VA_ARGS__)
#else
#define debugOutput(...)      {/* __VA_ARGS__ */}
#define debugDump_arry(...)   {/* __VA_ARGS__ */}
#endif
                              
#define BG96_READ_TIMEOUTMS    2000                     //read timeout in MS
#define EQ_FREQ                200                      //frequency in ms to check for Tx/Rx data
#define EQ_FREQ_SLOW           2000                     //frequency in ms to check when in slow monitor mode

/** functions to output debug data---------------------------
*
*  @author James Flynn
*  @param  data    pointer to the data array to dump
*  @param  size    number of bytes to dump
*  @return void
*  @date 1-Feb-2018
*/
#if MBED_CONF_APP_BG96_DEBUG == true

#define dbgIO_lock    dbgout_mutex.lock();
#define dbgIO_unlock  dbgout_mutex.unlock();

void BG96Interface::_dbDump_arry( const uint8_t* data, unsigned int size )
{
    unsigned int i, k;

    dbgIO_lock;
    if( g_debug & DBGMSG_ARRY ) {
        for (i=0; i<size; i+=16) {
            printf("[BG96 Driver]:0x%04X: ",i);
            for (k=0; k<16; k++) {
                if( (i+k)<size )
                    printf("%02X ", data[i+k]);
                else
                    printf("   ");
                }
            printf("    ");
            for (k=0; k<16; k++) {
                if( (i+k)<size )
                    printf("%c", isprint(data[i+k])? data[i+k]:'.');
                }
            printf("\n\r");
            }
        }
    dbgIO_unlock;
}

void BG96Interface::_dbOut(int who, const char* format, ...)
{
    char buffer[256];
    dbgIO_lock;
    if( who & (g_debug & (DBGMSG_DRV|DBGMSG_EQ)) ) {
        va_list args;
        va_start (args, format);
        printf("[BG96 Driver]: ");
        vsnprintf(buffer, sizeof(buffer), format, args);
        printf("%s",buffer);
        printf("\n");
        va_end (args);
        }
    dbgIO_unlock;
}
#else
#define dbgIO_lock    
#define dbgIO_unlock  
#endif  //MBED_CONF_APP_BG96_DEBUG == true


/** --------------------------------------------------------
*  @brief  BG96Interface constructor         
*  @param  none
*  @retval none
*/
BG96Interface::BG96Interface(void) : 
    g_isInitialized(false),
    g_bg96_queue_id(-1),
    _BG96(false)
{
    for( int i=0; i<BG96_SOCKET_COUNT; i++ ) {
        g_sock[i].id = -1;
        g_sock[i].disTO = false;
        g_sock[i].connected   = false;
        g_socRx[i].m_rx_state = READ_START;
        g_socRx[i].m_rx_disTO = false;
        g_socTx[i].m_tx_state = TX_IDLE;
        }
    #if MBED_CONF_APP_BG96_DEBUG == true
    g_debug=0;
    #endif
}

/** ----------------------------------------------------------
* @brief  BG96Interface destructor         
* @param  none
* @retval none
*/
BG96Interface::~BG96Interface()
{
}

/** ----------------------------------------------------------
* @brief  network connect
*         connects to Access Point, can be called with no argument
*         or arguments.  If none, use default APN.
* @param  ap: Access Point Name (APN) Name String  
*         pass_word: Password String for AP
*         username:  username to use for AP
* @retval NSAPI Error Type
*/
nsapi_error_t BG96Interface::connect(void)
{
    debugOutput(DBGMSG_DRV,"BG96Interface::connect(void) ENTER.");
    return connect(DEFAULT_APN, NULL, NULL);
}

nsapi_error_t BG96Interface::connect(const char *apn, const char *username, const char *password)
{
    Timer t;

    debugOutput(DBGMSG_DRV,"BG96Interface::connect(%s,%s,%s) ENTER",apn,username,password);
    if( !g_isInitialized ) {
        t.start();
        dbgIO_lock;
        while(t.read_ms() < BG96_MISC_TIMEOUT && !g_isInitialized) 
            g_isInitialized= _BG96.startup();
        dbgIO_unlock;
        }

    if( g_isInitialized && g_bg96_queue_id == -1) 
        g_bg96_queue_id = _bg96_monitor.start(callback(&_bg96_queue, &EventQueue::dispatch_forever));

    debugOutput(DBGMSG_DRV,"BG96Interface::connect EXIT");

    return g_isInitialized? set_credentials(apn, username, password) : NSAPI_ERROR_DEVICE_ERROR;
}

/** Set the cellular network credentials --------------------
*
*  @param apn      Optional, APN of network
*  @param user     Optional, username --not used--
*  @param pass     Optional, password --not used--
*  @return         nsapi_error_t
*/
nsapi_error_t BG96Interface::set_credentials(const char *apn, const char *username, const char *password)
{
    nsapi_error_t ret;

    debugOutput(DBGMSG_DRV,"BG96Interface::set_credentials ENTER/EXIT, APN=%s, USER=%s, PASS=%s",apn,username,password);
    ret = _BG96.connect((char*)apn, (char*)username, (char*)password);
    return ret;
}
 
/**----------------------------------------------------------
*  @brief  network disconnect
*          disconnects from APN
*  @param  none
*  @return nsapi_error_t
*/
int BG96Interface::disconnect(void)
{    
    nsapi_error_t ret;

    debugOutput(DBGMSG_DRV,"BG96Interface::disconnect ENTER");
    _bg96_queue.cancel(g_bg96_queue_id);
    g_bg96_queue_id = -1; 
    dbgIO_lock;
    ret = _BG96.disconnect();
    dbgIO_unlock;
    debugOutput(DBGMSG_DRV,"BG96Interface::disconnect EXIT");
    return ret? NSAPI_ERROR_OK:NSAPI_ERROR_DEVICE_ERROR;
}

/**----------------------------------------------------------
* @brief  Get the local IP address
* @param  none
* @retval Null-terminated representation of the local IP address
*         or null if not yet connected
*/
const char *BG96Interface::get_ip_address()
{
    static char ip[25];
    debugOutput(DBGMSG_DRV,"BG96Interface::get_ip_address ENTER");
    dbgIO_lock;
    const char* ptr = _BG96.getIPAddress(ip);
    dbgIO_unlock;
    debugOutput(DBGMSG_DRV,"BG96Interface::get_ip_address EXIT");
    return ptr;
}

/**---------------------------------------------------------- 
* @brief  Get the MAC address
* @param  none
* @retval Null-terminated representation of the MAC address
*         or null if not yet connected
*/
const char *BG96Interface::get_mac_address()
{
    static char mac[25];
    debugOutput(DBGMSG_DRV,"BG96Interface::get_mac_address ENTER");
    dbgIO_lock;
    const char* ptr = _BG96.getMACAddress(mac);
    dbgIO_unlock;
    debugOutput(DBGMSG_DRV,"BG96Interface::get_mac_address EXIT");
    return ptr;
}

/**---------------------------------------------------------- 
* @brief  Get Module Firmware Information
* @param  none
* @retval Null-terminated representation of the MAC address
*         or null if error
*/
const char* BG96Interface::getRevision(void)
{
    static char str[40];
    dbgIO_lock;
    const char* ptr = _BG96.getRev(str);
    dbgIO_unlock;
    return ptr;
}

/**----------------------------------------------------------
* @brief  attach function/callback to the socket
*         Not used
* @param  handle: Pointer to handle
*         callback: callback function pointer
*         data: pointer to data
* @retval none
*/
void BG96Interface::socket_attach(void *handle, void (*callback)(void *), void *data)
{
    BG96SOCKET *sock = (BG96SOCKET*)handle;
    debugOutput(DBGMSG_DRV,"ENTER/EXIT socket_attach(), socket %d attached",sock->id);
    sock->_callback = callback;
    sock->_data  = data;
}


/**----------------------------------------------------------
*  @brief  bind to a port number and address
*  @param  handle: Pointer to socket handle
*          proto: address to bind to
*  @return nsapi_error_t
*/
int BG96Interface::socket_bind(void *handle, const SocketAddress &address)
{
    debugOutput(DBGMSG_DRV,"BG96Interface::socket_bind ENTER/EXIT");
    return socket_listen(handle, 1);
}

/**----------------------------------------------------------
*  @brief  start listening on a port and address
*  @param  handle: Pointer to handle
*          backlog: not used (always value is 1)
*  @return nsapi_error_t
*/
int BG96Interface::socket_listen(void *handle, int backlog)
{      
    BG96SOCKET *socket = (BG96SOCKET *)handle;    
    nsapi_error_t ret = NSAPI_ERROR_OK;

    backlog = backlog;  //avoid unused error from compiler
    debugOutput(DBGMSG_DRV,"BG96Interface::socket_listen, socket %d listening %s ENTER", 
                 socket->id, socket->connected? "YES":"NO");
    if( !socket->connected ) {
        socket->disTO   = true; 
        _bg96_queue.call_in(EQ_FREQ,mbed::Callback<void()>((BG96Interface*)this,&BG96Interface::g_eq_event));
        }
    else
        ret = NSAPI_ERROR_NO_CONNECTION;
            
    debugOutput(DBGMSG_DRV,"BG96Interface::socket_listen EXIT");
    return ret;
}

/**----------------------------------------------------------
*  @brief  Set the socket options
*          Not used
*  @param  handle: Pointer to handle         
*          level:  SOL_SOCKET
*          optname: option name
*          optval:  pointer to option value
*          optlen:  option length
*  @return nsapi_error_t
*/
int BG96Interface::setsockopt(void *handle, int level, int optname, const void *optval, unsigned optlen)
{
    BG96SOCKET *sock = (BG96SOCKET *)handle;

    debugOutput(DBGMSG_DRV,"BG96Interface::setsockopt ENTER/EXIT");
    if (!optlen || !sock) {
        return NSAPI_ERROR_PARAMETER;
        }

    if (level == NSAPI_SOCKET && sock->proto == NSAPI_TCP) {
        switch (optname) {
            case NSAPI_REUSEADDR:
            case NSAPI_KEEPIDLE:
            case NSAPI_KEEPINTVL:
            case NSAPI_LINGER:
            case NSAPI_SNDBUF:
            case NSAPI_ADD_MEMBERSHIP:
            case NSAPI_DROP_MEMBERSHIP:
            case NSAPI_KEEPALIVE: 
                return NSAPI_ERROR_UNSUPPORTED;

            case NSAPI_RCVBUF:
                if (optlen == sizeof(void *)) {
                    sock->dptr_last = (void*)optval;
                    sock->dptr_size = (unsigned)optlen;
                    return NSAPI_ERROR_OK;
                    }
                return NSAPI_ERROR_PARAMETER;
            }
        }
    return NSAPI_ERROR_UNSUPPORTED;
}
    
/**----------------------------------------------------------
*  @brief  Get the socket options
*          Not used
*  @param  handle: Pointer to handle         
*          level: SOL_SOCKET
*          optname: option name
*          optval:  pointer to option value
*          optlen:  pointer to option length
*  @return nsapi_error_t
*/
int BG96Interface::getsockopt(void *handle, int level, int optname, void *optval, unsigned *optlen)    
{
    BG96SOCKET *sock = (BG96SOCKET *)handle;

    debugOutput(DBGMSG_DRV,"BG96Interface::getsockopt ENTER/EXIT");
    if (!optval || !optlen || !sock) {
        return NSAPI_ERROR_PARAMETER;
    }

    if (level == NSAPI_SOCKET && sock->proto == NSAPI_TCP) {
        switch (optname) {
            case NSAPI_REUSEADDR:
            case NSAPI_KEEPALIVE:
            case NSAPI_KEEPIDLE:
            case NSAPI_KEEPINTVL:
            case NSAPI_LINGER:
            case NSAPI_SNDBUF:
            case NSAPI_ADD_MEMBERSHIP:
            case NSAPI_DROP_MEMBERSHIP:
                return NSAPI_ERROR_UNSUPPORTED;

            case NSAPI_RCVBUF:
                optval = sock->dptr_last;
                *optlen = sock->dptr_size;
                return NSAPI_ERROR_OK;
            }
        }
    return NSAPI_ERROR_UNSUPPORTED;
}

/**----------------------------------------------------------
*  @brief  helpe function to set debug levels. Only enabled
*          if debug flag set during compilation
*  @param  int = value to set debug flag to
*  @retval none
*/
void BG96Interface::doDebug( int v )
{
    #if MBED_CONF_APP_BG96_DEBUG == true
    gvupdate_mutex.lock();
    _BG96.doDebug(v);
    g_debug= v;
    gvupdate_mutex.unlock();
    debugOutput(DBGMSG_DRV,"SET debug flag to 0x%02X",v);
    #endif
}

/**----------------------------------------------------------
*  @brief  open a socket handle
*  @param  handle: Pointer to handle
*          proto: TCP/UDP protocol
*  @return nsapi_error_t
*/
int BG96Interface::socket_open(void **handle, nsapi_protocol_t proto)
{
    int           i;
    nsapi_error_t ret=NSAPI_ERROR_OK;

    debugOutput(DBGMSG_DRV,"ENTER socket_open(), protocol=%s", (proto==NSAPI_TCP)?"TCP":"UDP");
    gvupdate_mutex.lock();
    //find the next available socket...
    for( i=0; i<BG96_SOCKET_COUNT; i++ )
        if( g_sock[i].id == -1  )
            break;

    if( i == BG96_SOCKET_COUNT ) {
        ret = NSAPI_ERROR_NO_SOCKET;
        debugOutput(DBGMSG_DRV,"EXIT socket_open; NO SOCKET AVAILABLE (%d)",i);
        }
    else{
        debugOutput(DBGMSG_DRV,"socket_open using socket %d", i);

        g_socTx[i].m_tx_state = TX_IDLE;
        g_socRx[i].m_rx_state = READ_START;

        g_sock[i].id          = i;
        g_sock[i].disTO       = false;
        g_sock[i].proto       = proto;
        g_sock[i].connected   = false;
        g_sock[i]._callback   = NULL;
        g_sock[i]._data       = NULL;
        *handle = &g_sock[i];
        debugOutput(DBGMSG_DRV,"EXIT socket_open; Socket=%d, protocol =%s",
                i, (g_sock[i].proto==NSAPI_UDP)?"UDP":"TCP");
        }
    gvupdate_mutex.unlock();

    return ret;
}

/**----------------------------------------------------------
*  @brief  close a socket
*  @param  handle: Pointer to handle
*  @return nsapi_error_t
*/
int BG96Interface::socket_close(void *handle)
{
    BG96SOCKET    *sock = (BG96SOCKET*)handle;
    nsapi_error_t ret =NSAPI_ERROR_DEVICE_ERROR;
    RXEVENT       *rxsock;
    TXEVENT       *txsock;
    int           i = sock->id;

    debugOutput(DBGMSG_DRV,"ENTER socket_close(); Socket=%d", i);

    if(i >= 0) {
        txsock = &g_socTx[i];
        rxsock = &g_socRx[i];

        txsock->m_tx_state = TX_IDLE;               //reset TX state
        if( rxsock->m_rx_state != READ_START ) {    //reset RX state
            rxsock->m_rx_disTO=false;
            while( rxsock->m_rx_state !=  DATA_AVAILABLE ) 
                wait(1);  //someone called close while a read was happening
            }

        dbgIO_lock;
        if( sock->connected ) 
            _BG96.close(sock->id);
        dbgIO_unlock;

        sock->id    = -1;
        sock->disTO    = false;
        sock->proto    = NSAPI_TCP;
        sock->connected= false;
        sock->_callback= NULL;
        sock->_data    = NULL;
        ret = NSAPI_ERROR_OK;
        debugOutput(DBGMSG_DRV,"EXIT socket_close(), socket %d - success",i);
        }
    else
        debugOutput(DBGMSG_DRV,"EXIT socket_close() - fail");
    return ret;
}

/**----------------------------------------------------------
*  @brief  accept connections from remote sockets
*  @param  handle: Pointer to handle of client socket (connecting)
*          proto: handle of server socket which will accept connections
*  @return nsapi_error_t
*/
int BG96Interface::socket_accept(nsapi_socket_t server,nsapi_socket_t *handle, SocketAddress *address)
{    
    return NSAPI_ERROR_UNSUPPORTED;
}

/**----------------------------------------------------------
*  @brief  connect to a remote socket
*  @param  handle: Pointer to socket handle
*          addr: Address to connect to
*  @return nsapi_error_t
*/
int BG96Interface::socket_connect(void *handle, const SocketAddress &addr)
{
    BG96SOCKET    *sock = (BG96SOCKET *)handle;
    nsapi_error_t ret=NSAPI_ERROR_OK;
    const char    proto = (sock->proto == NSAPI_UDP) ? 'u' : 't';
    bool          k;
    int           cnt;


    debugOutput(DBGMSG_DRV,"ENTER socket_connect(); Socket=%d; IP=%s; PORT=%d;", 
                 sock->id, addr.get_ip_address(), addr.get_port());
    dbgIO_lock;
    for( k=true, cnt=0; cnt<3 && k; cnt++ ) {
        k = !_BG96.open(proto, sock->id, addr.get_ip_address(), addr.get_port()); 
        if( k ) 
            _BG96.close(sock->id);
        }
    dbgIO_unlock;

    if( cnt<3 ) {
        sock->addr = addr;
        sock->connected = true;

        if( sock->_callback != NULL )
            sock->_callback(sock->_data);
        }
    else 
        ret = NSAPI_ERROR_DEVICE_ERROR;

    debugOutput(DBGMSG_DRV,"EXIT socket_connect(), Socket %d",sock->id);
    return ret;
}

/**----------------------------------------------------------
*  @brief  return the address of this object
*  @param  none
*  @retval pointer to this class object
*/
NetworkStack *BG96Interface::get_stack()
{
    return this;
}

/**----------------------------------------------------------
*  @brief  return IP address after looking up the URL name
*  @param  name = URL string
*          address = address to store IP in
*          version = not used
*  @return nsapi_error_t
*/
nsapi_error_t BG96Interface::gethostbyname(const char* name, SocketAddress *address, nsapi_version_t version)
{
    char          ipstr[25];
    bool          ok;
    nsapi_error_t ret=NSAPI_ERROR_OK;

    debugOutput(DBGMSG_DRV,"ENTER gethostbyname(); IP=%s; PORT=%d; URL=%s;", address->get_ip_address(), address->get_port(), name);

    dbgIO_lock;
    ok=_BG96.resolveUrl(name,ipstr);
    dbgIO_unlock;

    if( !ok ) {
        ret = NSAPI_ERROR_DEVICE_ERROR;
        debugOutput(DBGMSG_DRV,"EXIT gethostbyname() -- failed to get DNS");
        }
    else{
        address->set_ip_address(ipstr);
        debugOutput(DBGMSG_DRV,"EXIT gethostbyname(); IP=%s; PORT=%d; URL=%s;", address->get_ip_address(), address->get_port(), name);
        }
    return ret;
}

/**----------------------------------------------------------
*  @brief  periodic event(EventQueu thread) to check for RX and TX data. If checking for RX data with TO disabled
*          slow down event checking after a while.
*  @param  none
*  @retval none
*/
//check any sockets that have socket->disTO set to see if any messages have arrived.
void BG96Interface::g_eq_event(void)
{
    int done = 0;
    bool goSlow = true;

    txrx_mutex.lock();
    for( unsigned int i=0; i<BG96_SOCKET_COUNT; i++ ) {
        if( g_socRx[i].m_rx_state == READ_ACTIVE || g_socRx[i].m_rx_disTO) {
            done += rx_event(&g_socRx[i]);
            goSlow &= ( g_socRx[i].m_rx_timer > ((BG96_READ_TIMEOUTMS/EQ_FREQ)*(EQ_FREQ_SLOW/EQ_FREQ)) );
   
            if( goSlow ) 
                g_socRx[i].m_rx_timer = (BG96_READ_TIMEOUTMS/EQ_FREQ)*(EQ_FREQ_SLOW/EQ_FREQ);
            }

        if( g_socTx[i].m_tx_state == TX_ACTIVE ) {
            goSlow = false;
            done += tx_event(&g_socTx[i]);
            }
        }
    txrx_mutex.unlock();
    if( done>0 )  
        _bg96_queue.call_in((goSlow?EQ_FREQ_SLOW:EQ_FREQ),mbed::Callback<void()>((BG96Interface*)this,&BG96Interface::g_eq_event));
}

/**----------------------------------------------------------
* @brief  send data to a udp socket
* @param  handle: Pointer to handle
*         addr: address of udp socket
*         data: pointer to data
*         size: size of data
* @retval no of bytes sent
*/
int BG96Interface::socket_sendto(void *handle, const SocketAddress &addr, const void *data, unsigned size)
{
    BG96SOCKET *sock = (BG96SOCKET *)handle;
    int err=NSAPI_ERROR_OK;

    if (!sock->connected) 
        err = socket_connect(sock, addr);

    if( err != NSAPI_ERROR_OK )
        return err;
    else
        return socket_send(sock, data, size);
}


/**----------------------------------------------------------
* @brief  write to a socket
* @param  handle: Pointer to handle
*         data: pointer to data
*         size: size of data
* @retval no of bytes sent
*/
int BG96Interface::socket_send(void *handle, const void *data, unsigned size)
{    
    BG96SOCKET *sock = (BG96SOCKET *)handle;
    TXEVENT *txsock;
    
    txrx_mutex.lock();
    debugOutput(DBGMSG_DRV,"ENTER socket_send(),socket %d, send %d bytes",sock->id,size);
    txsock = &g_socTx[sock->id];

    if( size < 1 || data == NULL )  // should never happen but have seen it
        return 0; 

    switch( txsock->m_tx_state ) {
        case TX_IDLE:
            txsock->m_tx_socketID  = sock->id;
            txsock->m_tx_state     = TX_STARTING;
            txsock->m_tx_dptr      = (uint8_t*)data;
            txsock->m_tx_orig_size = size;
            txsock->m_tx_req_size  = (uint32_t)size;
            txsock->m_tx_total_sent= 0;
            txsock->m_tx_callback  = sock->_callback;
            txsock->m_tx_cb_data   = sock->_data;
            debugDump_arry((const uint8_t*)data,size);

            if( txsock->m_tx_req_size > BG96::BG96_BUFF_SIZE ) 
                txsock->m_tx_req_size= BG96::BG96_BUFF_SIZE;

            if( tx_event(txsock) ) {   //if we didn't sent all the data, schedule background send the rest
                txsock->m_tx_state = TX_ACTIVE;
                _bg96_queue.call_in(EQ_FREQ,mbed::Callback<void()>((BG96Interface*)this,&BG96Interface::g_eq_event));
                txrx_mutex.unlock();
                return NSAPI_ERROR_WOULD_BLOCK;
                }
            //all data sent so fall through to TX_COMPLETE

        case TX_COMPLETE:
            debugOutput(DBGMSG_DRV,"EXIT socket_send(), socket %d, sent %d bytes", txsock->m_tx_socketID,txsock->m_tx_total_sent);
            txsock->m_tx_state = TX_IDLE;
            txrx_mutex.unlock();
            return txsock->m_tx_total_sent;

        case TX_ACTIVE:
        case TX_STARTING:
            txrx_mutex.unlock();
            return NSAPI_ERROR_WOULD_BLOCK;

        default:
            debugOutput(DBGMSG_DRV,"EXIT socket_send(), NSAPI_ERROR_DEVICE_ERROR");
            txrx_mutex.unlock();
            return NSAPI_ERROR_DEVICE_ERROR;
        }
}


/**----------------------------------------------------------
*  @brief  send data, if more data than BG96 can handle at one
*          send as much as possible, and schedule another event
*  @param  pointer to TXEVENT structure
*  @retval 1 if need to schedule another event, 0 if data sent
*/
int BG96Interface::tx_event(TXEVENT *ptr)
{
    debugOutput(DBGMSG_EQ,"ENTER tx_event(), socket id %d",ptr->m_tx_socketID);

    dbgIO_lock;
    bool done =_BG96.send(ptr->m_tx_socketID, ptr->m_tx_dptr, ptr->m_tx_req_size);
    dbgIO_unlock;

    if( done )
        ptr->m_tx_total_sent += ptr->m_tx_req_size;
    else{
        debugOutput(DBGMSG_EQ,"EXIT tx_event(), socket id %d, sent no data!",ptr->m_tx_socketID);
        return 1;
        }
    
    if( ptr->m_tx_total_sent < ptr->m_tx_orig_size ) {
        ptr->m_tx_dptr += ptr->m_tx_req_size;
        ptr->m_tx_req_size = ptr->m_tx_orig_size-ptr->m_tx_total_sent;

        if( ptr->m_tx_req_size > BG96::BG96_BUFF_SIZE) 
            ptr->m_tx_req_size= BG96::BG96_BUFF_SIZE;

        debugOutput(DBGMSG_EQ,"EXIT tx_event(), need to send %d more bytes.",ptr->m_tx_req_size);
        return 1;
        }
    debugOutput(DBGMSG_EQ,"EXIT tx_event, socket id %d, sent %d bytes",ptr->m_tx_socketID,ptr->m_tx_total_sent);
    ptr->m_tx_state = TX_COMPLETE;
    if( ptr->m_tx_callback != NULL ) 
        ptr->m_tx_callback( ptr->m_tx_cb_data );
    ptr->m_tx_cb_data = NULL; 
    ptr->m_tx_callback = NULL;

    return 0;
}

/**----------------------------------------------------------
* @brief  receive data on a udp socket
* @param  handle: Pointer to handle
*         addr: address of udp socket
*         data: pointer to data
*         size: size of data
* @retval no of bytes read
*/
int BG96Interface::socket_recvfrom(void *handle, SocketAddress *addr, void *data, unsigned size)
{
    BG96SOCKET *sock = (BG96SOCKET *)handle;

    if (!sock->connected) 
        return NSAPI_ERROR_NO_CONNECTION;
    *addr = sock->addr;
    return socket_recv(sock, data, size);
}

/**----------------------------------------------------------
* @brief  receive data on a socket
* @param  handle: Pointer to socket handle
*         data: pointer to data
*         size: size of data
* @retval no of bytes read
*/
int BG96Interface::socket_recv(void *handle, void *data, unsigned size) 
{
    BG96SOCKET *sock = (BG96SOCKET *)handle;
    RXEVENT *rxsock;

    txrx_mutex.lock();
        
    rxsock = &g_socRx[sock->id];
    debugOutput(DBGMSG_DRV,"ENTER socket_recv(), socket %d, request %d bytes",sock->id, size);

    if( size < 1 || data == NULL ) { // should never happen
        return 0;
        }

    switch( rxsock->m_rx_state ) {
        case READ_START:  //need to start a read sequence of events
            rxsock->m_rx_disTO     = sock->disTO;
            rxsock->m_rx_socketID  = sock->id;
            rxsock->m_rx_state     = READ_INIT;
            rxsock->m_rx_dptr      = (uint8_t*)data;
            rxsock->m_rx_req_size  = (uint32_t)size;
            rxsock->m_rx_total_cnt = 0;
            rxsock->m_rx_timer     = 0;
            rxsock->m_rx_return_cnt=0;

            if( rxsock->m_rx_req_size > BG96::BG96_BUFF_SIZE) 
                rxsock->m_rx_req_size= BG96::BG96_BUFF_SIZE;
                
            rxsock->m_rx_callback = sock->_callback;
            rxsock->m_rx_cb_data  = sock->_data;

            if( rx_event(rxsock) ){
                rxsock->m_rx_state = READ_ACTIVE;
                _bg96_queue.call_in(EQ_FREQ,mbed::Callback<void()>((BG96Interface*)this,&BG96Interface::g_eq_event));
                txrx_mutex.unlock();
                return NSAPI_ERROR_WOULD_BLOCK;
                }
            //got data, fall thru and finish. no need to schedule the background task
        case DATA_AVAILABLE:
            debugOutput(DBGMSG_DRV,"EXIT socket_recv(),socket %d, return %d bytes",sock->id, rxsock->m_rx_return_cnt);
            debugDump_arry((const uint8_t*)data,rxsock->m_rx_return_cnt);
            rxsock->m_rx_state = READ_START;
            txrx_mutex.unlock();
            return rxsock->m_rx_return_cnt;

        case READ_ACTIVE:
        case READ_INIT:
            debugOutput(DBGMSG_DRV,"EXIT socket_recv(), socket id %d, READ_ACTIVE/INIT", sock->id);
            rxsock->m_rx_timer    = 0;  //reset the time-out timer
            txrx_mutex.unlock();
            return NSAPI_ERROR_WOULD_BLOCK;

        default:
            debugOutput(DBGMSG_DRV,"EXIT socket_recv(), NSAPI_ERROR_DEVICE_ERROR");
            txrx_mutex.unlock();
            return NSAPI_ERROR_DEVICE_ERROR;
        }
}

/**----------------------------------------------------------
*  @brief  check for and retrieve data user requested. Time out
*          after TO period unless socket has TO disabled.
*  @param  pointer to an RXEVENT 
*  @retval 1 if need to schedule another check, 0 if data received or Timed Out
*/
int BG96Interface::rx_event(RXEVENT *ptr)
{
    debugOutput(DBGMSG_EQ,"ENTER rx_event() for socket id %d, size=%d", ptr->m_rx_socketID, ptr->m_rx_req_size);
    dbgIO_lock;
    int cnt = _BG96.recv(ptr->m_rx_socketID, ptr->m_rx_dptr, ptr->m_rx_req_size);
    dbgIO_unlock;

    if( cnt>0 ) {  //got data, return it to the caller
        debugOutput(DBGMSG_EQ,"data received on socket id %d, cnt=%d", ptr->m_rx_socketID, cnt);
        ptr->m_rx_return_cnt += cnt;
        ptr->m_rx_state = DATA_AVAILABLE;
        if( ptr->m_rx_callback != NULL ) 
            ptr->m_rx_callback( ptr->m_rx_cb_data );
        ptr->m_rx_cb_data = NULL; 
        ptr->m_rx_callback = NULL;
        return 0;
        }
    if( ++ptr->m_rx_timer > (BG96_READ_TIMEOUTMS/EQ_FREQ) && !ptr->m_rx_disTO ) {  //timed out waiting, return 0 to caller
        debugOutput(DBGMSG_EQ,"EXIT rx_event(), socket id %d, rx data TIME-OUT!",ptr->m_rx_socketID);
        ptr->m_rx_state = DATA_AVAILABLE;
        ptr->m_rx_return_cnt = 0;
        if( ptr->m_rx_callback != NULL ) 
            ptr->m_rx_callback( ptr->m_rx_cb_data );
        ptr->m_rx_cb_data = NULL; 
        ptr->m_rx_callback = NULL;
        return 0;
        }

    debugOutput(DBGMSG_EQ,"EXIT rx_event(), socket id %d, sechedule for more.",ptr->m_rx_socketID);
    return 1;
}
