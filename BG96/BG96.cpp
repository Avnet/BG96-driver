/**
* copyright (c) 2018-2019, James Flynn
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
*/

/**
*  @file BG96.cpp
*  @brief Implements a standard NetworkInterface class for use with Quicktel BG96
*
*  @author James Flynn
* 
*  @date 19-Mar-2018
*  
*/

#include <ctype.h>

#include "mbed.h"
#include "mbed_debug.h"
#include "BG96.h"

#define BG96_60s_TO             60000
#define BG96_150s_TO            150000
#define BG96_1s_WAIT            1000 //will wait for 1 second for startup
#define BG96_TX_TIMEOUT         250
#define BG96_WAIT4READY         15000 
#define BG96_AT_TIMEOUT         1000
#define BG96_WRK_CONTEXT        1     //we will only use context 1 in driver

#define TOSTR(x) #x
#define INTSTR(x) TOSTR(x)
#define DUMP_LOC (char*)(__FILE__ ":" INTSTR(__LINE__))

//
// if DEBUG is enabled, this macro can be used to dump data arrays
//
#if MBED_CONF_APP_BG96_DEBUG == true
#define DUMP_ARRAY(x,s)	{\
    int i, k;\
    for (i=0; i<s; i+=16) {\
        printf("[%s]:0x%04X: ",DUMP_LOC,i);\
        for (k=0; k<16; k++) {\
            if( (i+k)<s )\
                printf("%02X ", x[i+k]);\
            else\
                printf("   ");\
            }\
        printf("    ");\
        for (k=0; k<16; k++) {\
            if( (i+k)<s )\
                printf("%c", isprint(x[i+k])? x[i+k]:'.');\
            }\
        printf("\n\r");\
        }\
    }
#else
#define DUMP_ARRAY(x,s) /* not used */
#endif

DigitalOut BG96_reset(MBED_CONF_BG96_LIBRARY_BG96_RESET); 
DigitalOut VBAT_3V8_EN(MBED_CONF_BG96_LIBRARY_BG96_WAKE);
DigitalOut BG96_PWRKEY(MBED_CONF_BG96_LIBRARY_BG96_PWRKEY);
    
static UARTSerial  _serial(MBED_CONF_BG96_LIBRARY_BG96_TX, MBED_CONF_BG96_LIBRARY_BG96_RX);
static ATCmdParser _parser(&_serial);

/** ----------------------------------------------------------
* @brief  get BG96 SW version
* @param  none
* @retval string containing SW version
*/
const char* BG96::getRev(void)
{
    static char combined[40];
    char        buf1[20], buf2[20];

    if( !tx2bg96((char*)"AT+CGMM") )
        return NULL;
    if( !( _parser.recv("%s\n",buf1) && _parser.recv("OK")) )
        return NULL;
    if( !(_parser.send("AT+CGMR") && _parser.recv("%s\n",buf2) && _parser.recv("OK")) )
        return NULL;

    sprintf(combined,"%s Rev:%s",buf1,buf2);
    return (const char*) combined;
}

/** ----------------------------------------------------------
* @brief  constructor
* @param  none
* @retval none
*/
BG96::BG96(bool debug) : _contextActive(1)
{
    _serial.set_baud(115200);
    _parser.debug_on(debug);
    _parser.set_timeout(BG96_AT_TIMEOUT);
    _parser.set_delimiter("\r\n");
}

/** ----------------------------------------------------------
* @brief  enable AT command tracing
* @param  integer, if msb is set, tracing enabled
* @retval none
*/
void BG96::doDebug(int f)
{
    _parser.debug_on(f&0x80);
}
    
/** ----------------------------------------------------------
* @brief  Tx a string to the BG96 and wait for an OK response
* @param  none
* @retval true if OK received, false otherwise
*/
bool BG96::tx2bg96(char* cmd) {
    return (_parser.send(cmd) && _parser.recv("OK"));
}

/** ----------------------------------------------------------
* @brief  set the contextID for the BG96. This context will
*         be used for all subsequent operations
* @param  int of desired context. if <1, return the current context
* @retval current context
*/
/*
* Context can be 1-16
*/
int BG96::setContext( int i )
{
    if( i >  16 )
        return -1;

    if( i < 1 )
        return _contextActive;

    return _contextActive = i;
}

/** ----------------------------------------------------------
* @brief  perform a HW reset of the BG96
* @param  none
* @retval none
*/
void BG96::reset(void)
{
    BG96_reset = 0;
    BG96_PWRKEY = 0;
    VBAT_3V8_EN = 0;
    wait_ms(300);

    BG96_reset = 1;
    VBAT_3V8_EN = 1;
    BG96_PWRKEY = 1;
    wait_ms(400);

    BG96_reset = 0;
    wait_ms(10);
}

/** ----------------------------------------------------------
* @brief  wait for 'RDY' response from BG96
* @param  none
* @retval true if 'RDY' received, false otherwise
*/
bool BG96::BG96Ready(void)
{
    Timer t;
    int   done=false;
    
    reset();
    t.start();
    while( !done && t.read_ms() < BG96_WAIT4READY )
        done = _parser.recv("RDY");
    return done;
}


/** ----------------------------------------------------------
* @brief  startup BG96 module
* @param  none
* @retval true if successful, false otherwise
*/
bool BG96::startup(void)
{
    Timer t;
    int   done=false;
    
    if( !BG96Ready() )
        return false;
        
    _parser.set_timeout(BG96_AT_TIMEOUT*2);
    if( !tx2bg96((char*)"ATE0") )
        return false; 
    t.start();
    while( t.read_ms() < BG96_1s_WAIT && !done ) 
        done = tx2bg96((char*)"AT+COPS?");
    _parser.set_timeout(BG96_AT_TIMEOUT);
    return done;
 }


/** ----------------------------------------------------------
* @brief  connect to APN
* @param  apn string 
* @param  username (not used)
* @param  password (not used)
* @retval nsapi_error_t
*/
nsapi_error_t BG96::connect(const char *apn, const char *username, const char *password)
{
    char cmd[100],_apn[50];
    bool done = false;
    Timer t;
    int   cntx;
    
    t.start();
    do {
        _parser.send("AT+QICSGP=%d",_contextActive);
        done = _parser.recv("+QICSGP: %d, \"%50[^\"]\"",&cntx, _apn);
        wait_ms(2);
        }
    while( !done && t.read_ms() < BG96_60s_TO );

    if( !done )
        return NSAPI_ERROR_DEVICE_ERROR;

    _parser.flush();    
    if( strcmp(_apn,apn) ) {
        sprintf(cmd,"AT+QICSGP=%d,1,\"%s\",\"%s\",\"%s\",0", _contextActive, &apn[0], &username[0], &password[0]);
        if( !tx2bg96(cmd) )  
            return NSAPI_ERROR_DEVICE_ERROR;
        }

    sprintf(cmd,"AT+QIACT=%d", _contextActive);
    t.reset();
    done=false;
    while( !done && t.read_ms() < BG96_150s_TO ) 
        done = tx2bg96(cmd);
    
    return done? NSAPI_ERROR_OK : NSAPI_ERROR_DEVICE_ERROR;
}

/** ----------------------------------------------------------
* @brief  disconnect from an APN
* @param  none
* @retval true/false if disconnect was successful or not
*/
bool BG96::disconnect(void)
{
    char buff[15];
    sprintf(buff,"AT+QIDEACT=%d\r",_contextActive);
    return tx2bg96(buff);
}

/** ----------------------------------------------------------
* @brief  perform DNS lookup of URL to determine IP address
* @param  string containing the URL 
* @retval string containing the IP results from the URL DNS
*/
const char* BG96::resolveUrl(const char *name)
{
    static char buf[25], buf2[25];
    int  err, ipcount, dnsttl;
    
    if( !_parser.send("AT+QIDNSGIP=%d,\"%s\"",_contextActive,name) && !_parser.recv("OK") )
        return NULL;

    if( !_parser.send("+QIURC: \"recv\",%d",_contextActive) && !_parser.recv("OK") )
        return NULL;
        
    if( !_parser.recv("+QIURC: \"dnsgip\",%d,%d,%d",&err, &ipcount, &dnsttl) )
        return NULL;
        
    if( err || ipcount < 1 )
        return NULL;

    _parser.recv("+QIURC: \"dnsgip\",\"%[^\"]\"",buf);
            
    for( int i=0; i<ipcount-1; i++ )
        _parser.recv("+QIURC: \"dnsgip\",\"%[^\"]\"",buf2);    
        
    return buf;
}

/** ----------------------------------------------------------
* @brief  determine if BG96 is readable
* @param  none
* @retval true/false
*/
bool BG96::readable()
{
    return _serial.readable();
}

/** ----------------------------------------------------------
* @brief  determine if BG96 is writable
* @param  none
* @retval true/false
*/
bool BG96::writeable()
{
    return _serial.writable();
}


/** ----------------------------------------------------------
* @brief  obtain the IP address socket is using
* @param  none
* @retval string containing IP or NULL on failure
*/
const char *BG96::getIPAddress(void)
{
    static char ipstr[17];
    Timer t;
    int   cs, ct;
    bool  done=false;

    t.start();
    for( int times=0; times<3 && !done; times++ ) {
        done = !_parser.send("AT+QIACT?");
        t.reset();
        while( !done && t.read_ms() < BG96_60s_TO )
            done = _parser.recv("+QIACT: 1, %d,%d,\"%16[^\"]\"",&cs,&ct,ipstr);
        }

    return done? ipstr:NULL;
}

/** ----------------------------------------------------------
* @brief  return the MAC
* @param  none
* @retval string containing the MAC or NULL on failure
*         MAC is created using the ICCID of the SIM
*/
const char *BG96::getMACAddress(void)
{
    static char sn[27];
 
    memset(sn,':',sizeof(sn));    
    if( !_parser.send("AT+QCCID") )
        return NULL;
    _parser.recv("+QCCID: %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",
            &sn[26], &sn[25], &sn[24],&sn[23],&sn[22],
            &sn[21], &sn[19], &sn[18],&sn[16],&sn[15],
            &sn[13], &sn[12], &sn[10],&sn[9], &sn[7],
            &sn[6],  &sn[4],  &sn[3], &sn[1], &sn[0]); 
    sn[20] = 0x00; 

    return (const char*)sn;
}

/** ----------------------------------------------------------
* @brief  determine if BG96 is connected to an APN
* @param  none
* @retval true or false
*/
bool BG96::isConnected(void)
{
    return getIPAddress() != NULL;
}

/** ----------------------------------------------------------
* @brief  open a BG96 socket
* @param  type of socket to open ('u' or 't')
* @param  id of BG96 socket
* @param  address (IP)
* @param  port of the socket
* @retval true if successful, else false on failure
*/
bool BG96::open(const char type, int* id, const char* addr, int port)
{
    char* stype = (char*)"TCP";
    int   conId = 0;  //connection type is TCP
    int   err=1;
      
    if( type == 'u' ) {
      stype = (char*)"UDP";
      conId = 2;  //connection type is UDP
      }
      
    if( !_parser.send("AT+QIOPEN=%d,%d,\"%s\",\"%s\",%d,0,0\r", _contextActive, conId, stype, addr, port) )
        return false;

    if( !_parser.recv("+QIOPEN: %d,%d", id, &err) )
        return false;
    return !err;
}

/** ----------------------------------------------------------
* @brief  close the BG96 socket
* @param  id of BG96 socket
* @retval true of close successful false on failure. <0 if error
*/
bool BG96::close(int id)
{
    Timer t;
    bool  done=false;
    int   rxcnt=0;
    void* data = NULL;

    _parser.flush();
    rxcnt = rxAvail(id);     /* flush BG96 buffer... */

    if (rxcnt>0) {
        data = malloc (rxcnt+4);
        if(!((_parser.read((char*)data, rxcnt) >0) && _parser.recv("OK"))) {
            free (data);
            return -4;
            }
        free (data);
        }

    t.start();
    while( !done && t.read_ms() < BG96_150s_TO ) {
        done = (_parser.send("AT+QICLOSE=%d", id) && _parser.recv("OK"));
        wait_ms(25);
        }
    return done;
}

/** ----------------------------------------------------------
* @brief  check for the amount of data available in RX buffer
* @param  id of BG96 socket
* @retval number of bytes in RX buffer or 0
*/
int BG96::rxAvail(int id)
{
    int   rcvd;
    char  cmd[20];

    sprintf(cmd, "+QIURC: \"recv\",%d", id);
    if( _parser.recv(cmd) && _parser.send("AT+QIRD=%d,%d\r", id, BG96_BUFF_SIZE) && _parser.recv("+QIRD: %d\r\n", &rcvd) ) 
        return rcvd;

    return 0;
}

/** ----------------------------------------------------------
* @brief  send data to the BG96
* @param  id of BG96 socket
* @param  pointer to the data to send
* @param  number of bytes to send
* @retval true if send successfull false otherwise
*/
bool BG96::send(int id, const void *data, uint32_t amount)
{
    Timer t;
    bool done=false;
     
    if( !_parser.send("AT+QISEND=%d,%ld", id, amount) )
        return false;

    if( !_parser.recv(">") )
        return false;

    if( _parser.write((char*)data, (int)amount) < 0 )
        return false;

    t.start();
    while( !done && t.read_ms() < BG96_TX_TIMEOUT ) 
        done = _parser.recv("SEND OK");

    return done;
}

/** ----------------------------------------------------------
* @brief  receive data from BG96
* @param  id of BG96 socket
* @param  pointer to location to store returned data
* @param  count of the number of bytes to get
* @retval number of bytes returned or 0
*/
int32_t BG96::recv(int id, void *data, uint32_t cnt)
{
    int  rxCount, ret_cnt=0;

    if( _parser.send("AT+QIRD=%d,%d",id,(int)cnt) && _parser.recv("+QIRD:%d\r\n",&rxCount) ) {
        _parser.getc(); //for some reason BG96 always outputs a 0x0A before the data
        _parser.read((char*)data, rxCount);

        if( !_parser.recv("OK") )
            return -6;
        DUMP_ARRAY(((char*)data),rxCount);
        ret_cnt = rxCount;
        }

    return ret_cnt;
}

