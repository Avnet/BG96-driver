
#include "mbed.h"
#include "easy-connect.h"

#include "BG96Interface.h"

BG96Interface bg96;

NetworkInterface* easy_connect(bool log_messages) {
    NetworkInterface* network_interface = NULL;
    int connect_success = -1;

    if (log_messages) {
        printf("[EasyConnect] Using BG96\n");
        printf("[EasyConnect] IPv4 mode\n");
    }

#   if MBED_CONF_APP_BG96_DEBUG == true
    printf("[EasyConnect] With BG96 debug output set to 0x%02X\n",MBED_CONF_APP_BG96_DEBUG_SETTING);
    bg96.doDebug(MBED_CONF_APP_BG96_DEBUG_SETTING);
#   endif

    network_interface = &bg96;
    connect_success = bg96.connect();

    if(connect_success == 0) {
        if (log_messages) {
            printf("[EasyConnect] Connected to Network successfully\n");
            print_MAC(network_interface, log_messages);
        }
    } else {
        if (log_messages) {
            print_MAC(network_interface, log_messages);
            printf("[EasyConnect] Connection to Network Failed %d!\n", connect_success);
        }
        return NULL;
    }
    const char *ip_addr  = network_interface->get_ip_address();
    if (ip_addr == NULL) {
        if (log_messages) {
            printf("[EasyConnect] ERROR - No IP address\n");
        }
        return NULL;
    }

    if (log_messages) {
        printf("[EasyConnect] IP address %s\n", ip_addr);
    }
    return network_interface;
}

/* \brief print_MAC - print_MAC  - helper function to print out MAC address
 * in: network_interface - pointer to network i/f
 *     bool log-messages   print out logs or not
 * MAC address is printed, if it can be acquired & log_messages is true.
 *
 */
void print_MAC(NetworkInterface* network_interface, bool log_messages) {
    const char *mac_addr = network_interface->get_mac_address();
    if (mac_addr == NULL) {
        if (log_messages) {
            printf("[EasyConnect] ERROR - No MAC address\n");
        }
        return;
    }
    if (log_messages) {
        printf("[EasyConnect] MAC address %s\n", mac_addr);
    }
}

