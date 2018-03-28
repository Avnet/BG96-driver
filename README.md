# Mbed OS v5.x Network Interface driver for Quectel BG96

## Specifying library configuration and settings

The following settings configure the I/O settings for the BG96 Driver.  The
current settings are for the AVNET RSR1157 NbIOT BG96 expansion board. If you
use a different board, the settings maydiffer.

```json
{
    "name": "BG96_library",
    "config": {
       "bg96_reset": {
           "help": "RESET pin for the BG96",
           "value": "D7"
       },
       "bg96_wake": {
           "help": "Wake pin to BG96",
           "value": "D11"
       },
       "bg96_pwrkey": {
           "help": "pwr key input to BG96",
           "value": "D10"
       },
       "bg96_tx": {
           "help": "TX pin for serial connection to BG96",
           "value": "D8"
       },
       "bg96_rx": {
           "help": "RX pin for serial connection to BG96",
           "value": "D2"
       }
    }
}
```

## Specifing the application configuration settings

In the mbed_app.json file that is used with this driver, the following settings are 
needed.

```json
{
    "macros": ["DEFAULT_APN=\"m2m.com.attz\""
              ],
    "config": {
       "bg96_debug": {
           "help" : "enable or disable WNC debug messages.",
           "value": 0
       },
       "bg96-debug-setting": {
           "help" : "bit value 1 and/or 2 enable WncController debug output, bit value 4 enables mbed driver debug output.",
           "value": "0x84"
       }
    },
    "target_overrides": {
        "*": {
            "platform.stdio-baud-rate": 115200,
            "platform.stdio-convert-newlines": true
        }
    }
}
```
### Default APN

The macro DEFAULT_APN is the APN that will be used when the connect method is called with no argments (if you 
don't specify an APN in your code).

### Debug settings

The bg96_debug setting enables or disabled debug output from the driver.

The bg96-debug-settings allow you to select various types of debug output.  It is a bit-field with the following settings:

     0x04 - Driver Enter/Exit debug information
     0x08 - Driver Event Queue debug information
     0x20 - Dump Driver Arrays
     0x80 - Trace AT command execution

### Overriding settings

The driver is designed to use a baud rater of 115200 so this must be specified (it will default to 9600 otherwise).  The 
convert-newlines helps terminal output format by removing the requirment to modify the terminal program settings. 

