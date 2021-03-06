/*
* Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef __TETHERING_PRIVATE_H__
#define __TETHERING_PRIVATE_H__

#define LOG_TAG	"tethering"

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <dlog.h>

#include "tethering.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef API
#define API __attribute__ ((visibility("default")))
#endif

#ifndef DEPRECATED_API
#  define DEPRECATED_API __attribute__ ((deprecated))
#endif

#define DBG(fmt, args...) LOGD("[%s()][Ln:%d] "fmt, __func__, __LINE__, ##args)
#define WARN(fmt, args...) LOGW("[%s()][Ln:%d] "fmt, __func__, __LINE__, ##args)
#define ERR(fmt, args...) LOGE("[%s()][Ln:%d] "fmt, __func__, __LINE__, ##args)

#define _warn_if(expr, fmt, arg...) do { \
		if (expr) { \
			WARN(fmt, ##arg); \
		} \
	} while (0)

#define _ret_if(expr) do { \
		if (expr) { \
			return; \
		} \
	} while (0)

#define _retv_if(expr, val) do { \
		if (expr) { \
			return (val); \
		} \
	} while (0)

#define _retm_if(expr, fmt, arg...) do { \
		if (expr) { \
			ERR(fmt, ##arg); \
			return; \
		} \
	} while (0)

#define _retvm_if(expr, val, fmt, arg...) do { \
		if (expr) { \
			ERR(fmt, ##arg); \
			return (val); \
		} \
	} while (0)

/**
* Start of mobileap-agent common values
* When these values are changed, mobileap-agent should be also changed.
* But some of those will be removed.
*/

/*
* from mobileap_lib.h
*/

/**
* WiFi tethering configuration
*/
#define TETHERING_WIFI_CHANNEL		7	/**< Channel number */
#define TETHERING_WIFI_BSSID_LEN	6	/**< BSSID Length */
#define TETHERING_WIFI_PASSPHRASE_MIN_LEN	8	/**< Minimum length of wifi key */
#define TETHERING_WIFI_PASSPHRASE_MAX_LEN	63	/**< Maximum length of wifi key */

/**
* Common configuration
*/
#define TETHERING_MAX_WIFI_STA		8
#define TETHERING_MAX_BT_STA		7
#define TETHERING_MAX_USB_STA		1
#define TETHERING_MAX_CONNECTED_STA	16	/**< Maximum connected station. 8(Wi-Fi) + 7(BT) + 1(USB) */

#define TETHERING_NAME_UNKNOWN		"UNKNOWN"

#define TETHERING_TYPE_MAX		4	/**< All, USB, Wi-Fi, BT */
#define TETHERING_STR_INFO_LEN		20	/**< length of the ip or mac address */
#define TETHERING_STR_HOSTNAME_LEN	32	/**< length of the hostname */

/**
* Mobile AP error code
*/
typedef enum {
	MOBILE_AP_ERROR_NONE,			/**< No error */
	MOBILE_AP_ERROR_RESOURCE,		/**< Socket creation error, file open error */
	MOBILE_AP_ERROR_INTERNAL,		/**< Driver related error */
	MOBILE_AP_ERROR_INVALID_PARAM,		/**< Invalid parameter */
	MOBILE_AP_ERROR_ALREADY_ENABLED,	/**< Mobile AP is already ON */
	MOBILE_AP_ERROR_NOT_ENABLED,		/**< Mobile AP is not ON, so cannot be disabled */
	MOBILE_AP_ERROR_NET_OPEN,		/**< PDP network open error */
	MOBILE_AP_ERROR_NET_CLOSE,		/**< PDP network close error */
	MOBILE_AP_ERROR_DHCP,			/**< DHCP error */
	MOBILE_AP_ERROR_IN_PROGRESS,		/**< Request is in progress */
	MOBILE_AP_ERROR_NOT_PERMITTED,		/**< Operation is not permitted */

	MOBILE_AP_ERROR_MAX
} mobile_ap_error_code_e;

/**
* Event type on callback
*/
typedef enum {
	MOBILE_AP_ENABLE_CFM,
	MOBILE_AP_DISABLE_CFM,

	MOBILE_AP_ENABLE_WIFI_TETHERING_CFM,
	MOBILE_AP_DISABLE_WIFI_TETHERING_CFM,
	MOBILE_AP_CHANGE_WIFI_CONFIG_CFM,

	MOBILE_AP_ENABLE_USB_TETHERING_CFM,
	MOBILE_AP_DISABLE_USB_TETHERING_CFM,

	MOBILE_AP_ENABLE_BT_TETHERING_CFM,
	MOBILE_AP_DISABLE_BT_TETHERING_CFM,

	MOBILE_AP_GET_STATION_INFO_CFM,
	MOBILE_AP_GET_DATA_PACKET_USAGE_CFM
} mobile_ap_event_e;

typedef enum {
	MOBILE_AP_TYPE_WIFI,
	MOBILE_AP_TYPE_USB,
	MOBILE_AP_TYPE_BT,
	MOBILE_AP_TYPE_MAX,
} mobile_ap_type_e;


/*
* from mobileap_internal.h
*/
#define DBUS_STRUCT_UINT_STRING (dbus_g_type_get_struct ("GValueArray", \
			G_TYPE_UINT, G_TYPE_STRING, G_TYPE_INVALID))

#define DBUS_STRUCT_STATIONS (dbus_g_type_get_struct ("GValueArray", \
			G_TYPE_UINT, G_TYPE_STRING, G_TYPE_STRING, \
			G_TYPE_STRING, G_TYPE_INVALID))

#define DBUS_STRUCT_STATION (dbus_g_type_get_struct ("GValueArray", \
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, \
			G_TYPE_INVALID))

#define DBUS_STRUCT_INTERFACE (dbus_g_type_get_struct ("GValueArray", \
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, \
			G_TYPE_STRING, G_TYPE_INVALID))

#define TETHERING_SERVICE_OBJECT_PATH	"/MobileAP"
#define TETHERING_SERVICE_NAME		"com.samsung.mobileap"
#define TETHERING_SERVICE_INTERFACE	"com.samsung.mobileap"

#define TETHERING_SIGNAL_NAME_LEN	64

#define SIGNAL_NAME_NET_CLOSED		"net_closed"
#define SIGNAL_NAME_STA_CONNECT		"sta_connected"
#define SIGNAL_NAME_STA_DISCONNECT	"sta_disconnected"
#define SIGNAL_NAME_WIFI_TETHER_ON	"wifi_on"
#define SIGNAL_NAME_WIFI_TETHER_OFF	"wifi_off"
#define SIGNAL_NAME_USB_TETHER_ON	"usb_on"
#define SIGNAL_NAME_USB_TETHER_OFF	"usb_off"
#define SIGNAL_NAME_BT_TETHER_ON	"bluetooth_on"
#define SIGNAL_NAME_BT_TETHER_OFF	"bluetooth_off"
#define SIGNAL_NAME_NO_DATA_TIMEOUT	"no_data_timeout"
#define SIGNAL_NAME_LOW_BATTERY_MODE	"low_batt_mode"
#define SIGNAL_NAME_FLIGHT_MODE		"flight_mode"
#define SIGNAL_NAME_DHCP_STATUS		"dhcp_status"

#define SIGNAL_MSG_NOT_AVAIL_INTERFACE	"Interface is not available"

/* Network Interface */
#define TETHERING_SUBNET_MASK		"255.255.255.0"

#define TETHERING_USB_IF		"usb0"
#define TETHERING_USB_GATEWAY		"192.168.129.1"

#define TETHERING_WIFI_IF		"wlan0"
#define TETHERING_WIFI_GATEWAY		"192.168.61.1"

#define TETHERING_BT_IF			"bnep0"
#define TETHERING_BT_GATEWAY		"192.168.130.1"
/**
* End of mobileap-agent common values
*/

#define TETHERING_DEFAULT_SSID				"Redwood"
#define TETHERING_DEFAULT_PASSPHRASE			"eoiugkl!"
#define TETHERING_WIFI_SECURITY_TYPE_OPEN_STR		"open"
#define TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK_STR	"wpa2-psk"


typedef void (*__handle_cb_t)(DBusGProxy *proxy, const char *name, gpointer data);
typedef struct {
	char name[TETHERING_SIGNAL_NAME_LEN];
	__handle_cb_t cb;
} __tethering_sig_t;

typedef struct {
        DBusGConnection *client_bus;
        DBusGProxy *client_bus_proxy;

	tethering_enabled_cb enabled_cb[TETHERING_TYPE_MAX];
	void *enabled_user_data[TETHERING_TYPE_MAX];
	tethering_disabled_cb disabled_cb[TETHERING_TYPE_MAX];
	void *disabled_user_data[TETHERING_TYPE_MAX];
	tethering_connection_state_changed_cb changed_cb[TETHERING_TYPE_MAX];
	void *changed_user_data[TETHERING_TYPE_MAX];
	tethering_data_usage_cb data_usage_cb;
	void *data_usage_user_data;
} __tethering_h;

typedef struct {
	tethering_type_e interface;			/**< interface type */
	char ip[TETHERING_STR_INFO_LEN];		/**< assigned IP address */
	char mac[TETHERING_STR_INFO_LEN];		/**< MAC Address */
	char hostname[TETHERING_STR_HOSTNAME_LEN];	/**< alphanumeric name */
} __tethering_client_h;

typedef struct {
	tethering_type_e interface;			/**< interface type */
	char interface_name[TETHERING_STR_INFO_LEN];	/**< interface alphanumeric name */
	char ip_address[TETHERING_STR_INFO_LEN];	/**< assigned ip addresss to interface */
	char gateway_address[TETHERING_STR_INFO_LEN];	/**< gateway address of interface */
	char subnet_mask[TETHERING_STR_INFO_LEN];	/**< subnet mask of interface */
} __tethering_interface_t;

#ifdef __cplusplus
}
#endif

#endif /* __TETHERING_PRIVATE_H__ */
