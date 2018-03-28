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
*   @file   BG96.h
*   @brief  Implements NetworkInterface class for use with the Quectel BG96
*           data module running MBed OS v5.x
*
*   @author James Flynn
*
*   @date   1-April-2018
*/

#ifndef __BG96_H__
#define __BG96_H__

#include "mbed.h"
 

/** BG96Interface class.
    Interface to a BG96 module.
 */

class BG96
{
public:
    static const unsigned BG96_BUFF_SIZE = 1460;  //max size BG96 TX buffer can handle
    
    BG96(bool debug=false);

    /**
    * Init the BG96
    *
    * @param mode mode in which to startup
    * @return true only if BG96 has started up correctly
    */
    bool startup(void);
 
    /**
    * Wait for 'RDY' signal or timeout waiting...
    *
    * @return none.
    */
    void waitBG96Ready(void);

    /**
    * Reset BG96
    *
    * @return true if BG96 resets successfully
    */
    void reset(void);
    
    /**
    * Connect BG96 to APN
    *
    * @param apn the name of the APN
    * @param username (not used)
    * @param password (not used)
    * @return nsapi_error_t
    */
    nsapi_error_t connect(const char *apn, const char *username, const char *password);
 
    /**
    * Disconnect BG96 from AP
    *
    * @return true if BG96 is disconnected successfully
    */
    bool disconnect(void);
 
    /**
    * Get the IP address of BG96
    *
    * @return null-teriminated IP address or null if no IP address is assigned
    */
    const char *getIPAddress(void);
 
    /**
    * Get the MAC address of BG96
    *
    * @return null-terminated MAC address or null if no MAC address is assigned
    */
    const char *getMACAddress(void);
 
    /**
    * Check if BG96 is conenected
    *
    * @return true only if the chip has an IP address
    */
    bool isConnected(void);
 
    /**
    * Open a socketed connection
    *
    * @param type the type of socket to open "u" (UDP) or "t" (TCP)
    * @param id for saving socket number to (returned by BG96)
    * @param port port to open connection with
    * @param addr the IP address of the destination
    * @return true only if socket opened successfully
    */
    bool open(const char type, int* id, const char* addr, int port);
 
    /**
    * Sends data to an open socket
    *
    * @param id of socket to send to
    * @param data to be sent
    * @param amount of data to be sent 
    * @return true only if data sent successfully
    */
    bool send(int id, const void *data, uint32_t amount);
 
    /**
    * Receives data from an open socket
    *
    * @param id to receive from
    * @param pointer to data for returned information
    * @param amount number of bytes to be received
    * @return the number of bytes received
    */
    int32_t recv(int, void *, uint32_t);
 
    /**
    * Closes a socket
    *
    * @param id id of socket to close, valid only 0-4
    * @return true only if socket is closed successfully
    */
    bool close(int id);
 
    /**
    * Checks if data is available
    */
    bool readable();
 
    /**
    * Checks if data can be written
    */
    bool writeable();
    
    /**
    * Resolves a URL name to IP address
    */
    const char *resolveUrl(const char *name);
 
    /*
    * Obtain or set the current BG96 active context
    */
    int setContext( int i );
    
    /*
    * enable/disable AT command tracing
    */
    void doDebug(int f);
    
    /** Return the BG96 revision info
     *
     *  @param          none.
     */
    const char* getRev(void);

private:
    bool     tx2bg96(char* cmd);

    bool     BG96Ready(void);
    bool     hw_reset(void);
    int      rxAvail(int id);
    int      _contextActive;
};
 
#endif  //__BG96_H__

