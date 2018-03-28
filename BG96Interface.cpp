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

static Thread _bg96_monitor;
static EventQueue _bg96_queue;

#if MBED_CONF_APP_BG96_DEBUG == true
#define debugOutput(...)      _dbOut(__VA_ARGS__)
#define debugDump_arry(...)   _dbDump_arry(__VA_ARGS__)
#else
#define debugOutput(...)      {/* __VA_ARGS__ */}
#define debugDump_arry(...)   {/* __VA_ARGS__ */}
#endif
                              
BG96 _BG96(false);                                      //create the BG96 HW interface object
Mutex _bg96_mutex;                                      //ensure it is used exclusively

#define BG96_READ_TIMEOUTMS    1000                     //read timeout in MS
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
void BG96Interface::_dbDump_arry( const uint8_t* data, unsigned int size )
{
    unsigned int i, k;

    if( m_debug & DBGMSG_ARRY ) {
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
}

void BG96Interface::_dbOut(const char* format, ...)
{
    char buffer[256];
    if( m_debug & (DBGMSG_DRV|DBGMSG_EQ|DBGMSG_SMS) ) {
        va_list args;
        va_start (args, format);
        printf("[BG96 Driver]: ");
        if( m_debug & DBGMSG_DRV )
            vsnprintf(buffer, sizeof(buffer), format, args);
        else if( m_debug & DBGMSG_EQ )
            vsnprintf(buffer, sizeof(buffer), format, args);
        else if( m_debug & DBGMSG_SMS )
            vsnprintf(buffer, sizeof(buffer), format, args);
        printf("%s",buffer);
        printf("\n");
        va_end (args);
        }
}
#endif  //MBED_CONF_APP_BG96_DEBUG == true


/** --------------------------------------------------------
*  @brief  BG96Interface constructor         
*  @param  none
*  @retval none
*/
BG96Interface::BG96Interface(void) 
{
    for( int i=0; i<BG96_SOCKET_COUNT; i++ ) {
        _sock[i].id = -1;
        _sock[i].index = -1;
        _sock[i].disTO = false;
        _sock[i].connected   = false;
        _socRx[i].m_rx_state = READ_START;
        _socRx[i].m_rx_disTO = false;
        _socTx[i].m_tx_state = TX_IDLE;
        }
    isInitialized = false;
    _bg96_queue_id = -1;
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
    debugOutput("BG96Interface::connect(void) ENTER.");
        
    return connect(DEFAULT_APN, NULL, NULL);
}

nsapi_error_t BG96Interface::connect(const char *apn, const char *username, const char *password)
{
    debugOutput("BG96Interface::connect(%s,%s,%s) ENTER",apn,username,password);
 
    Timer t;

    t.start();
    isInitialized=false;
    _bg96_mutex.lock();
    while(t.read_ms() < BG96_MISC_TIMEOUT && !isInitialized) 
        isInitialized= _BG96.startup();
    _bg96_mutex.unlock();
    t.stop();

    if( !isInitialized )
        return NSAPI_ERROR_DEVICE_ERROR;

    _bg96_queue_id = _bg96_monitor.start(callback(&_bg96_queue, &EventQueue::dispatch_forever));

    debugOutput("BG96Interface::connect EXIT");
    return set_credentials(apn, username, password);
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

    debugOutput("BG96Interface::set_credentials ENTER/EXIT, APN=%s, USER=%s, PASS=%s",apn,username,password);
    _bg96_mutex.lock();
    ret = _BG96.connect((char*)apn, (char*)username, (char*)password);
    _bg96_mutex.unlock();
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

    debugOutput("BG96Interface::disconnect ENTER");
    _bg96_queue.cancel(_bg96_queue_id);

    _bg96_mutex.lock();
    ret = _BG96.disconnect();
    _bg96_mutex.unlock();
    debugOutput("BG96Interface::disconnect EXIT");
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
    debugOutput("BG96Interface::get_ip_address ENTER");
    _bg96_mutex.lock();
    const char* ptr = _BG96.getIPAddress();
    _bg96_mutex.unlock();
    debugOutput("BG96Interface::get_ip_address EXIT");
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
    debugOutput("BG96Interface::get_mac_address ENTER");
    _bg96_mutex.lock();
    const char* ptr = _BG96.getMACAddress();
    _bg96_mutex.unlock();
    debugOutput("BG96Interface::get_mac_address EXIT");
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
    return _BG96.getRev();
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
    BG96SOCKET *_sock = (BG96SOCKET*)handle;

    debugOutput("ENTER/EXIT socket_attach(), connect using socket %d",_sock->index);
    _sock->_callback = callback;
    _sock->_data  = data;
}


/**----------------------------------------------------------
*  @brief  bind to a port number and address
*  @param  handle: Pointer to socket handle
*          proto: address to bind to
*  @return nsapi_error_t
*/
int BG96Interface::socket_bind(void *handle, const SocketAddress &address)
{
    debugOutput("BG96Interface::socket_bind ENTER/EXIT");
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

    debugOutput("BG96Interface::socket_listen, socket %d, connected %s ENTER", 
                 socket->index, socket->connected? "YES":"NO");
    backlog = backlog;  //avoid unused error from compiler

    if( !socket->connected )
        return NSAPI_ERROR_NO_SOCKET;
            
    socket->disTO   = true; 
    
    _bg96_queue.call_in(EQ_FREQ,mbed::Callback<void()>((BG96Interface*)this,&BG96Interface::_eq_event));
    debugOutput("BG96Interface::socket_listen EXIT");
    return NSAPI_ERROR_OK;
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
    BG96SOCKET *_sock = (BG96SOCKET *)handle;

    debugOutput("BG96Interface::setsockopt ENTER/EXIT");
    if (!optlen || !_sock) {
        return NSAPI_ERROR_PARAMETER;
        }

    if (level == NSAPI_SOCKET && _sock->proto == NSAPI_TCP) {
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
                    _sock->dptr_last = (void*)optval;
                    _sock->dptr_size = (unsigned)optlen;
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
    BG96SOCKET *_sock = (BG96SOCKET *)handle;

    debugOutput("BG96Interface::getsockopt ENTER/EXIT");
    if (!optval || !optlen || !_sock) {
        return NSAPI_ERROR_PARAMETER;
    }

    if (level == NSAPI_SOCKET && _sock->proto == NSAPI_TCP) {
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
                optval = _sock->dptr_last;
                *optlen = _sock->dptr_size;
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
    _BG96.doDebug(v);
    m_debug= v;
    debugOutput("SET debug flag to 0x%02X",v);
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
    int i;
    debugOutput("ENTER socket_open(), protocol=%s", (proto==NSAPI_TCP)?"TCP":"UDP");

    //find the next available socket...
    for( i=0; i<BG96_SOCKET_COUNT; i++ )
        if( _sock[i].index == -1  )
            break;

    if( i == BG96_SOCKET_COUNT ) 
        return NSAPI_ERROR_NO_SOCKET;

    _socTx[i].m_tx_state = TX_IDLE;
    _socRx[i].m_rx_state = READ_START;

    _sock[i].index       = i;
    _sock[i].id          = -1;
    _sock[i].disTO       = false;
    _sock[i].proto       = proto;
    _sock[i].connected   = false;
    _sock[i]._callback   = NULL;
    _sock[i]._data       = NULL;
    *handle = &_sock[i];

    debugOutput("EXIT socket_open; Socket=%d, protocol =%s",
                i, (_sock[i].proto==NSAPI_UDP)?"UDP":"TCP");

    return NSAPI_ERROR_OK;
}

/**----------------------------------------------------------
*  @brief  close a socket
*  @param  handle: Pointer to handle
*  @return nsapi_error_t
*/
int BG96Interface::socket_close(void *handle)
{
    BG96SOCKET *_sock = (BG96SOCKET*)handle;
    RXEVENT *rxsock;
    TXEVENT *txsock;
    int i = _sock->index;

    debugOutput("ENTER socket_close(); Socket=%d", i);

    if(i >= 0) {
        rxsock = &_socRx[i];
        txsock = &_socTx[i];

        txsock->m_tx_state = TX_IDLE;               //reset TX state
        if( rxsock->m_rx_state != READ_START ) {    //reset RX state
            rxsock->m_rx_disTO=false;
            while( rxsock->m_rx_state !=  DATA_AVAILABLE ) 
                wait(1);  //someone called close while a read was happening
            }

        if( _sock[i].connected ) {
            _bg96_mutex.lock();
            _BG96.close(_sock->id);
            _bg96_mutex.unlock();
            }

        _sock[i].id       = -1;
        _sock[i].index    = -1;
        _sock[i].disTO = false;
        _sock[i].proto    = NSAPI_TCP;
        _sock[i].connected= false;
        _sock[i]._callback= NULL;
        _sock[i]._data    = NULL;
        debugOutput("EXIT socket_close() - success");
        return NSAPI_ERROR_OK;
        }

    debugOutput("EXIT socket_close() - fail");
    return NSAPI_ERROR_DEVICE_ERROR;
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
    BG96SOCKET    *_sock = (BG96SOCKET *)handle;
    const char    proto = (_sock->proto == NSAPI_UDP) ? 'u' : 't';
    int           id, k;

    debugOutput("ENTER socket_connect(); Socket=%d; IP=%s; PORT=%d;", _sock->index, addr.get_ip_address(), addr.get_port());

    _bg96_mutex.lock();
    k = !_BG96.open(proto, &id, addr.get_ip_address(), addr.get_port()); 
    _bg96_mutex.unlock();
    if( k )
        return NSAPI_ERROR_DEVICE_ERROR;

    _sock->id = id;
    _sock->addr = addr;
    _sock->connected = true;
    if( _sock->_callback != NULL )
        _sock->_callback(_sock->_data);

    debugOutput("EXIT socket_connect(), Socket %d (id=%d)",_sock->index, _sock->id);
    return NSAPI_ERROR_OK;
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
    const char *str;

    debugOutput("ENTER gethostbyname(); IP=%s; PORT=%d; URL=%s;", address->get_ip_address(), address->get_port(), name);

    _bg96_mutex.lock();
    str=_BG96.resolveUrl(name);
    _bg96_mutex.unlock();

    if( str == NULL )
        return NSAPI_ERROR_DEVICE_ERROR;

    address->set_ip_address(str);

    debugOutput("EXIT gethostbyname(); IP=%s; PORT=%d; URL=%s;", address->get_ip_address(), address->get_port(), name);
    return NSAPI_ERROR_OK;
}

/**----------------------------------------------------------
*  @brief  periodic event(EventQueu thread) to check for RX and TX data. If checking for RX data with TO disabled
*          slow down event checking after a while.
*  @param  none
*  @retval none
*/
//check any sockets that have socket->disTO set to see if any messages have arrived.
void BG96Interface::_eq_event(void)
{
    int done = 1;
    bool goSlow = true;

    for( unsigned int i=0; i<BG96_SOCKET_COUNT; i++ ) {
        if( _socRx[i].m_rx_state == READ_ACTIVE || _socRx[i].m_rx_disTO) {
            done &= rx_event(&_socRx[i]);
            goSlow &= ( _socRx[i].m_rx_timer > ((BG96_READ_TIMEOUTMS/EQ_FREQ)*(EQ_FREQ_SLOW/EQ_FREQ)) );

            if( goSlow ) 
                _socRx[i].m_rx_timer = (BG96_READ_TIMEOUTMS/EQ_FREQ)*(EQ_FREQ_SLOW/EQ_FREQ);
            }

        if( _socTx[i].m_tx_state == TX_ACTIVE ) {
            goSlow = false;
            debugOutput("CALL TX_event() for socket %d", i);
            done &= tx_event(&_socTx[i]);
            }
        }

    if( !done )  
        _bg96_queue.call_in((goSlow?EQ_FREQ_SLOW:EQ_FREQ),mbed::Callback<void()>((BG96Interface*)this,&BG96Interface::_eq_event));
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
    BG96SOCKET *_sock = (BG96SOCKET *)handle;
    int err=NSAPI_ERROR_OK;

    if (!_sock->connected) 
        err = socket_connect(_sock, addr);

    if( err != NSAPI_ERROR_OK )
        return err;
    else
        return socket_send(_sock, data, size);
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
    BG96SOCKET *_sock = (BG96SOCKET *)handle;
    TXEVENT *txsock;

    debugOutput("ENTER socket_send(),socket %d/%d, send %d bytes",_sock->index,_sock->id,size);
    txsock = &_socTx[_sock->index];

    if( size < 1 || data == NULL )  // should never happen but have seen it
        return 0; 

    switch( txsock->m_tx_state ) {
        case TX_IDLE:
            txsock->m_tx_socketID  = _sock->id;
            txsock->m_tx_state     = TX_STARTING;
            txsock->m_tx_dptr      = (uint8_t*)data;
            txsock->m_tx_orig_size = size;
            txsock->m_tx_req_size  = (uint32_t)size;
            txsock->m_tx_total_sent= 0;
            txsock->m_tx_callback  = _sock->_callback;
            txsock->m_tx_cb_data   = _sock->_data;
            debugDump_arry((const uint8_t*)data,size);

            if( txsock->m_tx_req_size > BG96::BG96_BUFF_SIZE ) 
                txsock->m_tx_req_size= BG96::BG96_BUFF_SIZE;

            if( !tx_event(txsock) ) {   //if we didn't sent all the data, schedule background send
                txsock->m_tx_state = TX_ACTIVE;
                _bg96_queue.call_in(EQ_FREQ,mbed::Callback<void()>((BG96Interface*)this,&BG96Interface::_eq_event));
                return NSAPI_ERROR_WOULD_BLOCK;
                }
            //all data sent so fall through to TX_COMPLETE

        case TX_COMPLETE:
            debugOutput("EXIT socket_send(), sent %d bytes", txsock->m_tx_total_sent);
            txsock->m_tx_state = TX_IDLE;
            return txsock->m_tx_total_sent;

        case TX_ACTIVE:
        case TX_STARTING:
            return NSAPI_ERROR_WOULD_BLOCK;

        default:
            debugOutput("EXIT socket_send(), NSAPI_ERROR_DEVICE_ERROR");
            return NSAPI_ERROR_DEVICE_ERROR;
        }
}


/**----------------------------------------------------------
*  @brief  send data, if more data than BG96 can handle at one
*          send as much as possible, and schedule another event
*  @param  pointer to TXEVENT structure
*  @retval 0 if need to schedule another event, 1 if data sent
*/
int BG96Interface::tx_event(TXEVENT *ptr)
{
    debugOutput("ENTER tx_event(), socket id %d",ptr->m_tx_socketID);

    _bg96_mutex.lock();
    bool done =_BG96.send(ptr->m_tx_socketID, ptr->m_tx_dptr, ptr->m_tx_req_size);
    _bg96_mutex.unlock();

    if( done )
        ptr->m_tx_total_sent += ptr->m_tx_req_size;
    else
        return 0;
    
    if( ptr->m_tx_total_sent < ptr->m_tx_orig_size ) {
        ptr->m_tx_dptr += ptr->m_tx_req_size;
        ptr->m_tx_req_size = ptr->m_tx_orig_size-ptr->m_tx_total_sent;

        if( ptr->m_tx_req_size > BG96::BG96_BUFF_SIZE) 
            ptr->m_tx_req_size= BG96::BG96_BUFF_SIZE;

        debugOutput("EXIT tx_event(), need to send %d more bytes.",ptr->m_tx_req_size);
        return 0;
        }
    debugOutput("EXIT tx_event, socket id %d, sent %d bytes",ptr->m_tx_socketID,ptr->m_tx_total_sent);
    ptr->m_tx_state = TX_COMPLETE;
    if( ptr->m_tx_callback != NULL ) 
        ptr->m_tx_callback( ptr->m_tx_cb_data );
    ptr->m_tx_cb_data = NULL; 
    ptr->m_tx_callback = NULL;

    return 1;
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
    BG96SOCKET *_sock = (BG96SOCKET *)handle;

    if (!_sock->connected) 
        return NSAPI_ERROR_NO_CONNECTION;
    *addr = _sock->addr;
    return socket_recv(_sock, data, size);
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
    BG96SOCKET *_sock = (BG96SOCKET *)handle;
    RXEVENT *rxsock;

    rxsock = &_socRx[_sock->index];
    debugOutput("ENTER socket_recv(), socket %d/%d, request %d bytes",_sock->index,_sock->id, size);

    if( size < 1 || data == NULL ) { // should never happen
        return 0;
        }

    switch( rxsock->m_rx_state ) {
        case READ_START:  //need to start a read sequence of events
            rxsock->m_rx_disTO    = _sock->disTO;
            rxsock->m_rx_socketID = _sock->id;
            rxsock->m_rx_state    = READ_INIT;
            rxsock->m_rx_dptr     = (uint8_t*)data;
            rxsock->m_rx_req_size = (uint32_t)size;
            rxsock->m_rx_total_cnt= 0;
            rxsock->m_rx_timer    = 0;
            rxsock->m_rx_return_cnt=0;

            if( rxsock->m_rx_req_size > BG96::BG96_BUFF_SIZE) 
                rxsock->m_rx_req_size= BG96::BG96_BUFF_SIZE;
                
            rxsock->m_rx_callback = _sock->_callback;
            rxsock->m_rx_cb_data  = _sock->_data;

            if( !rx_event(rxsock) ){
                rxsock->m_rx_state = READ_ACTIVE;
                _bg96_queue.call_in(EQ_FREQ,mbed::Callback<void()>((BG96Interface*)this,&BG96Interface::_eq_event));
                return NSAPI_ERROR_WOULD_BLOCK;
                }
            //got data, fall thru and finish. no need to schedule the background task
        case DATA_AVAILABLE:
            debugOutput("EXIT socket_recv(),socket %d, return %d bytes",_sock->index, rxsock->m_rx_return_cnt);
            debugDump_arry((const uint8_t*)data,rxsock->m_rx_return_cnt);
            rxsock->m_rx_state = READ_START;
            return rxsock->m_rx_return_cnt;

        case READ_ACTIVE:
        case READ_INIT:
            debugOutput("EXIT socket_recv(), socked id %d, READ_ACTIVE/INIT", _sock->index);
            rxsock->m_rx_timer    = 0;  //reset the time-out timer
            return NSAPI_ERROR_WOULD_BLOCK;

        default:
            debugOutput("EXIT socket_recv(), NSAPI_ERROR_DEVICE_ERROR");
            return NSAPI_ERROR_DEVICE_ERROR;
        }
}

/**----------------------------------------------------------
*  @brief  check for and retrieve data user requested. Time out
*          after TO period unless socket has TO disabled.
*  @param  pointer to an RXEVENT 
*  @retval 0 if need to schedule another check, 1 if data received or Timed Out
*/
int BG96Interface::rx_event(RXEVENT *ptr)
{
    debugOutput("ENTER rx_event() for socket id %d, size=%d", ptr->m_rx_socketID, ptr->m_rx_req_size);
    _bg96_mutex.lock();
    int cnt = _BG96.recv(ptr->m_rx_socketID, ptr->m_rx_dptr, ptr->m_rx_req_size);
    _bg96_mutex.unlock();

    if( cnt>0 ) {  //got data, return it to the caller
        debugOutput("data received on socket id %d, cnt=%d", ptr->m_rx_socketID, cnt);
        ptr->m_rx_state = DATA_AVAILABLE;
        ptr->m_rx_return_cnt = cnt;
        if( ptr->m_rx_callback != NULL ) 
            ptr->m_rx_callback( ptr->m_rx_cb_data );
        ptr->m_rx_cb_data = NULL; 
        ptr->m_rx_callback = NULL;
        return 1;
        }
    if( ++ptr->m_rx_timer > (BG96_READ_TIMEOUTMS/EQ_FREQ) && !ptr->m_rx_disTO ) {  //timed out waiting, return 0 to caller
        debugOutput("EXIT rx_event(), socket id %d, rx data TIME-OUT!",ptr->m_rx_socketID);
        ptr->m_rx_state = DATA_AVAILABLE;
        ptr->m_rx_return_cnt = 0;
        if( ptr->m_rx_callback != NULL ) 
            ptr->m_rx_callback( ptr->m_rx_cb_data );
        ptr->m_rx_cb_data = NULL; 
        ptr->m_rx_callback = NULL;
        return 1;
        }

    debugOutput("EXIT rx_event(), socket id %d, sechedule for more.",ptr->m_rx_socketID);
    return 0;
}
