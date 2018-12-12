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
 
// If target board does not support Arduino pins, define pins as Not Connected
#if defined(TARGET_FF_ARDUINO)
#if !defined(MBED_CONF_BG96_LIBRARY_BG96_TX)
#define MBED_CONF_BG96_LIBRARY_BG96_TX               D8
#endif
#if !defined(MBED_CONF_BG96_LIBRARY_BG96_RX)
#define MBED_CONF_BG96_LIBRARY_BG96_RX               D2
#endif
#if !defined(MBED_CONF_BG96_LIBRARY_BG96_RESET)
#define MBED_CONF_BG96_LIBRARY_BG96_RESET            D7
#endif
#if !defined(MBED_CONF_BG96_LIBRARY_BG96_WAKE)
#define MBED_CONF_BG96_LIBRARY_BG96_WAKE             D11
#endif
#if !defined(MBED_CONF_BG96_LIBRARY_BG96_PWRKEY)
#define MBED_CONF_BG96_LIBRARY_BG96_PWRKEY           D10
#endif
#else // !defined(TARGET_FF_ARDUINO)
#define MBED_CONF_BG96_LIBRARY_BG96_TX                NC
#define MBED_CONF_BG96_LIBRARY_BG96_RX                NC
#define MBED_CONF_BG96_LIBRARY_BG96_RESET             NC
#define MBED_CONF_BG96_LIBRARY_BG96_WAKE              NC
#define MBED_CONF_BG96_LIBRARY_BG96_PWRKEY            NC
#endif // !defined(TARGET_FF_ARDUINO)

typedef struct gps_data_t {
    float utc;      //hhmmss.sss
    float lat;      //latitude. (-)dd.ddddd
    float lon;      //longitude. (-)dd.ddddd
    float hdop;     // Horizontal precision: 0.5-99.9
    float altitude; //altitude of antenna from sea level (meters) 
    int fix;        //GNSS position mode 2=2D, 3=3D
    float cog;      //Course Over Ground ddd.mm
    float spkm;     //Speed over ground (Km/h) xxxx.x
    float spkn;     //Speed over ground (knots) xxxx.x
    char date[7];   //data: ddmmyy
    int nsat;       //number of satellites 0-12
    } gps_data;

/** BG96Interface class.
    Interface to a BG96 module.
 */

class BG96
{
public:
    static const unsigned BG96_BUFF_SIZE = 1500;  
    
    BG96(bool debug=false);
    ~BG96();

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
    * Get the RSSI of the BG96
    *
    * @retval integet representing the RSSI, 1=poor,2=weak,3=mid-level,4=good,5=strong; 
    *         0=not available 
    */
    int getRSSI(void);

    /**
    * Get the IP address of BG96
    *
    * @return null-teriminated IP address or null if no IP address is assigned
    */
    const char *getIPAddress(char*);
 
    /**
    * Get the MAC address of BG96
    *
    * @return null-terminated MAC address or null if no MAC address is assigned
    */
    const char *getMACAddress(char*);
 
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
    bool open(const char type, int id, const char* addr, int port);
 
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
    bool resolveUrl(const char *name, char* str);
 
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
    const char* getRev(char*);

    /** Return the last error to occur
     *
     *  @param          char* [at least 40 long]
     */
    bool getError(char *);

    /** Return the amount a data available
     *
     *  @param          char* [at least 40 long]
     */
    int rxAvail(int);

    /** Return true/false if rx data is available 
     *
     *  @param          socket to check
     */
    bool        chkRxAvail(int id);

private:
    bool        tx2bg96(char* cmd);
    bool        BG96Ready(void);
    bool        hw_reset(void);

    int         _contextID;
    Mutex       _bg96_mutex;

    UARTSerial  _serial;
    ATCmdParser _parser;

    DigitalOut _bg96_reset;
    DigitalOut _vbat_3v8_en;
    DigitalOut _bg96_pwrkey;
    
};
 
#endif  //__BG96_H__

