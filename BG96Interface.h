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
 
/**
*   @file   BG96Interface.h
*   @brief  Implements NetworkInterface class for use with the Quectel BG96
*           data module running MBed OS v5.x
*
*   @author James Flynn
*
*   @date   1-April-2018
*/

#ifndef __BG96Interface_H__
#define __BG96Interface_H__

#include <stdint.h>

#include "mbed.h"
#include "Callback.h"

#include "BG96.h"

#define APN_DEFAULT          "m2m.com.attz"
#define BG96_MISC_TIMEOUT    15000
#define BG96_SOCKET_COUNT    5

#define DBGMSG_DRV           0x04
#define DBGMSG_EQ            0x08
#define DBGMSG_ARRY          0x20

#define FIRMWARE_REV(x)      (((BG96Interface*)x)->getRevision())
#define BG96_RSSI(x)         ((BG96Interface*)x)->get_rssi()

typedef struct rx_event_t {
    int      m_rx_state;            //state of the socket receive 
    int      m_rx_socketID;         //which socket is being rcvd on
    uint8_t *m_rx_dptr;             //pointer to the users data buffer
    uint32_t m_rx_req_size;         //Requested number of bytes to receive
    uint32_t m_rx_asked_size;
    uint32_t m_rx_total_cnt;        //Total number of bytes received
    int      m_rx_timer;            //Rx Timeout Timer
    int      m_rx_disTO;            //Flag to disable Timeout Timer
    void    (*m_rx_callback)(void*);//callback used with attach
    void     *m_rx_cb_data;         //callback data to be returned
    uint32_t m_rx_return_cnt;       //number of bytes the Event Queue is returning
    } RXEVENT;

typedef struct tx_event_t {
    int      m_tx_state;
    int      m_tx_socketID;
    uint8_t *m_tx_dptr;
    unsigned m_tx_orig_size;
    uint32_t m_tx_req_size;
    uint32_t m_tx_total_sent;
    void    (*m_tx_callback)(void*);
    void     *m_tx_cb_data;
    } TXEVENT;


/** BG96_socket class
 *  Implementation of BG96 socket structure
 */
typedef struct _socket_t {
    int              id;                   //nbr given by BG96 driver or -1 if not used
    SocketAddress    addr;                 //address this socket is attached to
    bool             disTO;                //true of socket is listening for incomming data
    nsapi_protocol_t proto;                //TCP or UDP
    bool             connected;            //true if socket is connected
    void             (*_callback)(void*);  //callback used with attach
    void             *_data;               //callback data to be returned
    void             *dptr_last;           //pointer to the last data buffer used
    unsigned         dptr_size;            //the size of the last user data buffer
    } BG96SOCKET;


class BG96Interface : public NetworkStack, public NetworkInterface
{
public:
    BG96Interface();
    virtual ~BG96Interface();

    /** Connect to the network (no parameters)
     *
     *  @return         nsapi_error_t
     */
    virtual nsapi_error_t connect(void);

    /** Connect to the network
     *
     *  @param apn      Optional, APN of network
     *  @param user     Optional, username --not used--
     *  @param pass     Optional, password --not used--
     *  @return         nsapi_error_t
     */
    virtual nsapi_error_t connect(const char *apn, const char *username = 0, const char *password = 0);
 
    /** Set the cellular network credentials
     *
     *  @param apn      Optional, APN of network
     *  @param user     Optional, username --not used--
     *  @param pass     Optional, password --not used--
     *  @return         nsapi_error_t
     */
    virtual nsapi_error_t set_credentials(const char *apn = 0,
            const char *username = 0, const char *password = 0);
 
    /** disconnect from the network
     *
     *  @return         nsapi_error_t
     */
    virtual nsapi_error_t disconnect();

    /** Get the IP address of WNC device. From NetworkStack Class
     *
     *  @return         IP address string or null 
     */
    virtual const char *get_ip_address();
 
    /** Get the MAC address of the WNC device.  
     *
     *  @return         MAC address of the interface
     */
    virtual const char *get_mac_address();
 
   /** Query Module RSSI
     *
     * @return          RSSI value
     */
    int get_rssi(void);

   /** Query Module SW revision
     *
     *  @return         SW Revision string
     */
    const char* getRevision(void);

   /** Query registered state 
     *
     *  @return         true if registerd, false if not 
     */
    bool registered();

    /** Set the level of Debug output
     *
     *  @param             bit field
     *  mbed driver info     = 0x04
     *  dump buffers         = 0x20
     *  AT command tracing   = 0x80
     */
    void doDebug( int v );
    

protected:

    /** Get Host IP by name. 
     *
     *  @return         nsapi_error_t
     */
    virtual nsapi_error_t gethostbyname(const char* name, SocketAddress *address, nsapi_version_t version);


    /** return a pointer to the NetworkStack object
     *
     *  @return          The underlying NetworkStack object
     */
    virtual NetworkStack *get_stack(void);

    /** Open a socket. 
     *
     *  @param handle       Handle in which to store new socket
     *  @param proto        Type of socket to open, NSAPI_TCP or NSAPI_UDP
     *  @return             nsapi_error_t
     */
    virtual int socket_open(void **handle, nsapi_protocol_t proto);
 

    /*  setsockopt allows applications to pass stack-specific hints
     *  to the underlying stack. For unsupported options,
     *  NSAPI_ERROR_UNSUPPORTED is returned and the socket is unmodified.
     *
     *  @param handle   Socket handle
     *  @param level    Stack-specific protocol level
     *  @param optname  Stack-specific option identifier
     *  @param optval   Option value
     *  @param optlen   Length of the option value
     *  @return         nsapi_error_t
     */
     virtual nsapi_error_t setsockopt(nsapi_socket_t handle, int level, int optname, const void *optval, unsigned optlen);
    

    /*  getsockopt retrieves stack-specific options.
     *
     *  unsupported options return NSAPI_ERROR_UNSUPPORTED
     *
     *  @param level    Stack-specific protocol level or nsapi_socket_level_t
     *  @param optname  Level-specific option name
     *  @param optval   Destination for option value
     *  @param optlen   Length of the option value
     *  @return         nsapi_error_t
     */
     virtual nsapi_error_t getsockopt(nsapi_socket_t handle, int level, int optname, void *optval, unsigned *optlen);


    /** Close the socket. 
     *
     *  @param handle       Socket handle
     *  @return             0 on success, negative on failure
     */
    virtual int socket_close(void *handle);
 
    /** Bind a server socket to a specific port.
     *
     *  @brief              Bind the socket to a specific port
     *  @param handle       Socket handle
     *  @param address      address to listen for 
     *  @return             0;
     */
    virtual int socket_bind(void *handle, const SocketAddress &address);
 
    /** Start listening for incoming connections.
     *
     *  @brief              NOT SUPPORTED
     *  @param handle       Socket handle
     *  @param backlog      Number of pending connections that can be queued up at any
     *                      one time [Default: 1]
     *  @return             nsapi_error_t
     */
    virtual nsapi_error_t socket_listen(void *handle, int backlog);
 
    /** Accept a new connection.
     *
     *  @brief              NOT SUPPORTED
     *  @return             NSAPI_ERROR_UNSUPPORTED;
     */
    virtual int socket_accept(nsapi_socket_t server,
            nsapi_socket_t *handle, SocketAddress *address=0);
 
    /** Connects this socket to the server.
     *
     *  @param handle       Socket handle
     *  @param address      SocketAddress 
     *  @return             nsapi_error_t
     */
    virtual int socket_connect(void *handle, const SocketAddress &address);
 
    /** Send data to the remote host.
     *
     *  @param handle       Socket handle
     *  @param data         buffer to send
     *  @param size         length of buffer
     *  @return             Number of bytes written or negative on failure
     *
     *  @note This call is non-blocking. 
     */
    virtual int socket_send(void *handle, const void *data, unsigned size);
 
    /** Receive data from the remote host.
     *
     *  @param handle       Socket handle
     *  @param data         buffer to store the recived data
     *  @param size         bytes to receive
     *  @return             received bytes received, negative on failure
     *
     *  @note This call is non-blocking. 
     */
    virtual int socket_recv(void *handle, void *data, unsigned size);
 
    /** Send a packet to a remote endpoint.
     *
     *  @param handle       Socket handle
     *  @param address      SocketAddress
     *  @param data         data to send
     *  @param size         number of bytes to send
     *  @return the         number of bytes sent or negative on failure
     *
     *  @note This call is non-blocking 
     */
    virtual int socket_sendto(void *handle, const SocketAddress &address, const void *data, unsigned size);
 
    /** Receive packet remote endpoint
     *
     *  @param handle       Socket handle
     *  @param address      SocketAddress 
     *  @param buffer       buffer to store data to
     *  @param size         number of bytes to receive
     *  @return the         number bytes received or negative on failure
     *
     *  @note This call is non-blocking 
     */
    virtual int socket_recvfrom(void *handle, SocketAddress *address, void *buffer, unsigned size);
 
    /** Register a callback on state change of the socket
     *
     *  @param handle       Socket handle
     *  @param callback     Function to call on state change
     *  @param data         Argument to pass to callback
     *
     *  @note Callback may be called in an interrupt context.
     */
    virtual void socket_attach(void *handle, void (*callback)(void *), void *data);

private:
    
    int        tx_event(TXEVENT *ptr);                  //called to TX data
    int        rx_event(RXEVENT *ptr);                  //called to RX data
    void       g_eq_event(void);                        //event queue to tx/rx
    void       _eq_schedule(void);

    nsapi_error_t g_isInitialized;                      //TRUE if the BG96Interface is connected to the network
    int        g_bg96_queue_id;                         //the ID of the EventQueue used by the driver
    uint32_t   scheduled_events;

    BG96SOCKET g_sock[BG96_SOCKET_COUNT];               //
    TXEVENT    g_socTx[BG96_SOCKET_COUNT];              //
    RXEVENT    g_socRx[BG96_SOCKET_COUNT];              //

    Thread     _bg96_monitor;                           //event queue thread
    EventQueue _bg96_queue;

    Mutex      gvupdate_mutex;                          //protect global variable updates
    Mutex      txrx_mutex;                              //protect RX/TX event queue activities
    BG96       _BG96;                                   //create the BG96 HW interface object

    #if MBED_CONF_APP_BG96_DEBUG == true
    Mutex      dbgout_mutex;
    int        g_debug;                                 //flag for debug settings
    void       _dbDump_arry( const uint8_t* data, unsigned int size );
    void       _dbOut(int, const char *format, ...);
    #endif
    
};

#endif /* __BG96Interface_H__ */

