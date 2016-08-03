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

#ifndef __TIZEN_NETWORK_TETHERING_H__
#define __TIZEN_NETWORK_TETHERING_H__

#include <tizen.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file tethering.h
 */

/**
 * @addtogroup CAPI_NETWORK_TETHERING_MANAGER_MODULE
 * @{
 */

/**
 * @brief The tethering handle.
 * @since_tizen 2.3
 */
typedef void * tethering_h;

/**
 * @brief Enumeration for the tethering.
 * @since_tizen 2.3
 */
typedef enum {
    TETHERING_ERROR_NONE = TIZEN_ERROR_NONE,  /**< Successful */
    TETHERING_ERROR_NOT_PERMITTED = TIZEN_ERROR_NOT_PERMITTED,  /**< Operation not permitted */
    TETHERING_ERROR_INVALID_PARAMETER = TIZEN_ERROR_INVALID_PARAMETER,  /**< Invalid parameter */
    TETHERING_ERROR_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY,  /**< Out of memory */
    TETHERING_ERROR_RESOURCE_BUSY = TIZEN_ERROR_RESOURCE_BUSY,  /**< Resource busy */
    TETHERING_ERROR_NOT_ENABLED = TIZEN_ERROR_TETHERING | 0x0501,  /**< Not enabled */
    TETHERING_ERROR_OPERATION_FAILED = TIZEN_ERROR_TETHERING | 0x0502,  /**< Operation failed */
    TETHERING_ERROR_INVALID_OPERATION = TIZEN_ERROR_INVALID_OPERATION, /**< Invalid operation */
    TETHERING_ERROR_NOT_SUPPORT_API = TIZEN_ERROR_NOT_SUPPORTED, /**< API is not supported */
    TETHERING_ERROR_PERMISSION_DENIED = TIZEN_ERROR_PERMISSION_DENIED,  /**< Permission denied */
} tethering_error_e;

/**
 * @brief Enumeration for the type of tethering.
 * @since_tizen 2.3
 */
typedef enum {
    TETHERING_TYPE_ALL = 0,  /**< All type */
    TETHERING_TYPE_USB,  /**< USB type */
    TETHERING_TYPE_WIFI,  /**< Wi-Fi type */
    TETHERING_TYPE_BT,  /**< BT type */
} tethering_type_e;

/**
 * @brief Enumeration for the cause of disabling the tethering.
 * @since_tizen 2.3
 */
typedef enum
{
    TETHERING_DISABLED_BY_USB_DISCONNECTION = 0,  /**< Disabled due to usb disconnection */
    TETHERING_DISABLED_BY_FLIGHT_MODE,  /**< Disabled due to flight mode */
    TETHERING_DISABLED_BY_LOW_BATTERY,  /**< Disabled due to low battery */
    TETHERING_DISABLED_BY_NETWORK_CLOSE,  /**< Disabled due to pdp network close */
    TETHERING_DISABLED_BY_TIMEOUT,  /**< Disabled due to timeout */
    TETHERING_DISABLED_BY_OTHERS,  /**< Disabled by other apps */
    TETHERING_DISABLED_BY_REQUEST,  /**< Disabled by your request */
    TETHERING_DISABLED_BY_WIFI_ON,  /**< Disabled due to Wi-Fi on */
    TETHERING_DISABLED_BY_BT_OFF,  /**< Disabled due to Bluetooth off */
} tethering_disabled_cause_e;

/**
 * @}
 */


/**
 * @addtogroup CAPI_NETWORK_TETHERING_WIFI_MODULE
 * @{
 */

/**
 * @brief Enumeration for the Wi-Fi security.
 * @since_tizen 2.3
 */
typedef enum {
    TETHERING_WIFI_SECURITY_TYPE_NONE = 0,  /**< No Security type */
    TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK,  /**< WPA2_PSK */
	TETHERING_WIFI_SECURITY_TYPE_WPS,  /**< WPA2_PSK */
} tethering_wifi_security_type_e;

/**
  * @brief Enumeration for the Wi-Fi mode
  * @since_tizen 3.0
  */
typedef enum {
	TETHERING_WIFI_MODE_TYPE_B = 0,  /**< mode b */
	TETHERING_WIFI_MODE_TYPE_G,  /**< mode g */
	TETHERING_WIFI_MODE_TYPE_A,  /**< mode a */
	TETHERING_WIFI_MODE_TYPE_AD, /**< mode ad */
} tethering_wifi_mode_type_e;

typedef enum {
	TETHERING_TYPE_IPSEC_PASSTHROUGH = 0,  /**< IPSEC */
	TETHERING_TYPE_PPTP_PASSTHROUGH,  /**< PPTP type */
	TETHERING_TYPE_L2TP_PASSTHROUGH,  /**< L2TP type */
} tethering_vpn_passthrough_type_e;

/**
 * @}
 */


/**
 * @addtogroup CAPI_NETWORK_TETHERING_CLIENT_MODULE
 * @{
 */

/**
 * @brief The tethering client handle.
 * @since_tizen 2.3
 */
typedef void * tethering_client_h;

/**
 * @brief Enumeration for address family.
 * @since_tizen 2.3
 */
typedef enum {
    TETHERING_ADDRESS_FAMILY_IPV4 = 0,  /**< IPV4 Address type */
} tethering_address_family_e;

/**
 * @}
 */


/**
 * @addtogroup CAPI_NETWORK_TETHERING_MANAGER_MODULE
 * @{
 */

/**
 * @brief Called when the tethering is enabled.
 * @since_tizen 2.3
 * @param[in]  result  The result of enabling the tethering
 * @param[in]  type  The tethering type
 * @param[in]  is_requested  Indicates whether this change is requested
 * @param[in]  user_data  The user data passed from tethering_set_enabled_cb()
 * @pre  If you register callback function using tethering_set_enabled_cb(), this will be invoked when the tethering is enabled.
 * @see	tethering_enable()
 * @see	tethering_unset_enabled_cb()
 */
typedef void (*tethering_enabled_cb)(tethering_error_e result, tethering_type_e type, bool is_requested, void *user_data);

/**
 * @brief Called when the tethering is disabled.
 * @since_tizen 2.3
 * @param[in]  result  The result of disabling the tethering
 * @param[in]  type  The tethering type
 * @param[in]  cause  The cause of disabling
 * @param[in]  user_data  The user data passed from tethering_set_disabled_cb()
 * @pre  If you register callback function using tethering_set_disabled_cb(), this will be invoked when the tethering is disabled.
 * @see	tethering_set_disabled_cb()
 * @see	tethering_unset_disabled_cb()
 */
typedef void (*tethering_disabled_cb)(tethering_error_e result, tethering_type_e type, tethering_disabled_cause_e cause, void *user_data);

/**
 * @brief Called when the connection state is changed.
 * @since_tizen 2.3
 * @remarks @a client is valid only in this function. In order to use it outside this function, a user must copy the client with tethering_client_clone().
 * @param[in]  client  The client of which connection state is changed
 * @param[in]  opened  @c true when connection is opened, otherwise false
 * @param[in]  user_data  The user data passed from tethering_set_connection_state_changed_cb()
 * @pre  If you register callback function using tethering_set_connection_state_changed_cb(), this will be invoked when the connection state is changed.
 * @see	tethering_set_connection_state_changed_cb()
 * @see	tethering_unset_connection_state_changed_cb()
 */
typedef void (*tethering_connection_state_changed_cb)(tethering_client_h client, bool opened, void *user_data);

/**
 * @brief Called when you get the connected client repeatedly.
 * @since_tizen 2.3
 * @remarks @a client is valid only in this function. In order to use the client outside this function, a user must copy the client with tethering_client_clone().
 * @param[in]  client  The connected client
 * @param[in]  user_data  The user data passed from the request function
 * @return  @c true to continue with the next iteration of the loop, \n @c false to break out of the loop
 * @pre  tethering_foreach_connected_clients() will invoke this callback.
 * @see  tethering_foreach_connected_clients()
 */
typedef bool(*tethering_connected_client_cb)(tethering_client_h client, void *user_data);

/**
 * @brief Called when you get the data usage.
 * @since_tizen 2.3
 * @param[in]  result  The result of getting the data usage
 * @param[in]  received_data  The usage of received data
 * @param[in]  sent_data  The usage of sent data
 * @param[in]  user_data  The user data passed from the request function
 * @pre  tethering_get_data_usage() will invoked this callback.
 */
typedef void (*tethering_data_usage_cb)(tethering_error_e result, unsigned long long received_data, unsigned long long sent_data, void *user_data);

/**
 * @brief Called when the security type of Wi-Fi tethering is changed.
 * @since_tizen 2.3
 * @param[in]  changed_type  The changed security type of Wi-Fi tethering
 * @param[in]  user_data  The user data passed from the register function
 * @see	tethering_wifi_set_security_type_changed_cb()
 * @see	tethering_wifi_unset_security_type_changed_cb()
 */
typedef void (*tethering_wifi_security_type_changed_cb)(tethering_wifi_security_type_e changed_type, void *user_data);

/**
 * @brief Called when the visibility of SSID is changed.
 * @since_tizen 2.3
 * @param[in]  changed_visible  The changed visibility of SSID
 * @param[in]  user_data  The user data passed from the register function
 * @see	tethering_wifi_set_ssid_visibility_changed_cb()
 * @see	tethering_wifi_unset_ssid_visibility_changed_cb()
 */
typedef void (*tethering_wifi_ssid_visibility_changed_cb)(bool changed_visible, void *user_data);

/**
 * @brief Called when the passphrase of Wi-Fi tethering is changed.
 * @since_tizen 2.3
 * @param[in]  user_data  The user data passed from the register function
 * @see	tethering_wifi_set_passphrase_changed_cb()
 * @see	tethering_wifi_unset_passphrase_changed_cb()
 */
typedef void (*tethering_wifi_passphrase_changed_cb)(void *user_data);

/**
 * @brief Called when the settings are reloaded.
 * @since_tizen 2.3
 * @param[in]  result  The result of reloading the settings
 * @param[in]  user_data  The user data passed from the request function
 * @pre  tethering_wifi_reload_settings() will invoke this callback.
 */
typedef void (*tethering_wifi_settings_reloaded_cb)(tethering_error_e result, void *user_data);

/**
 * @brief Creates the handle for tethering.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks The @a tethering must be released using tethering_destroy().
 * @param[out]  tethering  A handle of a new mobile ap handle on success
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API is not supported
 * @see  tethering_destroy()
 */
int tethering_create(tethering_h *tethering);

/**
 * @brief Destroys the handle for tethering.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_create()
 */
int tethering_destroy(tethering_h tethering);

/**
 * @brief Enables the tethering, asynchronously.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @post tethering_enabled_cb() will be invoked.
 * @see  tethering_is_enabled()
 * @see  tethering_disable()
 */
int tethering_enable(tethering_h tethering, tethering_type_e type);

/**
 * @brief Disables the tethering, asynchronously.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @post tethering_disabled_cb() will be invoked.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_disable(tethering_h tethering, tethering_type_e type);

/**
 * @brief Checks whether the tethering is enabled or not.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @return  @c true if tethering is enabled, \n @c false if tethering is disabled
 */
bool tethering_is_enabled(tethering_h tethering, tethering_type_e type);

/**
 * @brief Gets the MAC address of local device as "FC:A1:3E:D6:B1:B1".
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks @a mac_address must be released using free().
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[out]  mac_address  The MAC address
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  The tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_mac_address(tethering_h tethering, tethering_type_e type, char **mac_address);

/**
 * @brief Gets the name of network interface (e.g. usb0).
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks @a interface_name must be released using free().
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[out]  interface_name  The name of the network interface
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  The tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_network_interface_name(tethering_h tethering, tethering_type_e type, char **interface_name);

/**
 * @brief Gets the local IP address.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks @a ip_address must be released using free().
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[in]  address_family  The address family of IP address (currently, #TETHERING_ADDRESS_FAMILY_IPV4 is only supported)
 * @param[out]  ip_address  The local IP address
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  The tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_ip_address(tethering_h tethering, tethering_type_e type, tethering_address_family_e address_family, char **ip_address);

/**
 * @brief Gets the Gateway address.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks @a gateway_address must be released using free().
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[in]  address_family  The address family of IP address (currently, #TETHERING_ADDRESS_FAMILY_IPV4 is only supported)
 * @param[out]  gateway_address  The local IP address
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  The tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_gateway_address(tethering_h tethering, tethering_type_e type, tethering_address_family_e address_family, char **gateway_address);

/**
 * @brief Gets the Subnet Mask.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks @a subnet_mask must be released using free().
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[in]  address_family  The address family of IP address (currently, #TETHERING_ADDRESS_FAMILY_IPV4 is only supported)
 * @param[out]  subnet_mask  The local IP address
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  The tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_subnet_mask(tethering_h tethering, tethering_type_e type, tethering_address_family_e address_family, char **subnet_mask);

/**
 * @brief Gets the data usage.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[out]  usage  The data usage
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  The tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_data_usage(tethering_h tethering, tethering_data_usage_cb callback, void *user_data);

/**
 * @brief Gets the clients which are connected.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @pre  The tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_foreach_connected_clients(tethering_h tethering, tethering_type_e type, tethering_connected_client_cb callback, void *user_data);

/**
 * @brief Registers the callback function, which is called when tethering is enabled.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_unset_enabled_cb()
 */
int tethering_set_enabled_cb(tethering_h tethering, tethering_type_e type, tethering_enabled_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function, which is called when tethering is enabled.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_set_enabled_cb()
 */
int tethering_unset_enabled_cb(tethering_h tethering, tethering_type_e type);

/**
 * @brief Registers the callback function called when tethering is disabled.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_unset_disabled_cb()
 */
int tethering_set_disabled_cb(tethering_h tethering, tethering_type_e type, tethering_disabled_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function, which is called when tethering is disabled.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_set_disabled_cb()
 */
int tethering_unset_disabled_cb(tethering_h tethering, tethering_type_e type);

/**
 * @brief Registers the callback function, which is called when the state of connection is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_unset_connection_state_changed_cb_cb()
 */
int tethering_set_connection_state_changed_cb(tethering_h tethering, tethering_type_e type, tethering_connection_state_changed_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function, which is called when the state of connection is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_set_connection_state_changed_cb()
 */
int tethering_unset_connection_state_changed_cb(tethering_h tethering, tethering_type_e type);

/**
 * @brief Registers the callback function, which is called when the security type of Wi-Fi tethering is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_unset_security_type_changed_cb()
 */
int tethering_wifi_set_security_type_changed_cb(tethering_h tethering, tethering_wifi_security_type_changed_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function, which is called when the security type of Wi-Fi tethering is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_set_security_type_changed_cb()
 */
int tethering_wifi_unset_security_type_changed_cb(tethering_h tethering);

/**
 * @brief Registers the callback function , which iscalled when the visibility of SSID is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_unset_ssid_visibility_changed_cb_cb()
 */
int tethering_wifi_set_ssid_visibility_changed_cb(tethering_h tethering, tethering_wifi_ssid_visibility_changed_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function, which is called when the visibility of SSID is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_set_ssid_visibility_changed_cb()
 */
int tethering_wifi_unset_ssid_visibility_changed_cb(tethering_h tethering);

/**
 * @brief Registers the callback function, which is called when the passphrase of Wi-Fi tethering is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_unset_passphrase_changed_cb()
 */
int tethering_wifi_set_passphrase_changed_cb(tethering_h tethering, tethering_wifi_passphrase_changed_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function, which is called when the passphrase of Wi-Fi tethering is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_set_passphrase_changed_cb()
 */
int tethering_wifi_unset_passphrase_changed_cb(tethering_h tethering);

/**
 * @}
 */


/**
 * @addtogroup CAPI_NETWORK_TETHERING_WIFI_MODULE
 * @{
 */

/**
 * @brief Sets the security type of Wi-Fi tethering.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks This change is applied next time Wi-Fi tethering is enabled.
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The security type
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_get_security_type()
 */
int tethering_wifi_set_security_type(tethering_h tethering, tethering_wifi_security_type_e type);

/**
 * @brief Gets the security type of Wi-Fi tethering.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[out]  type  The security type
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_set_security_type()
 */
int tethering_wifi_get_security_type(tethering_h tethering, tethering_wifi_security_type_e *type);

/**
 * @brief Sets the SSID (service set identifier).
 * @details The SSID cannot exceed 32 bytes. If SSID is not set, device name is used as SSID.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks This change is applied next time Wi-Fi tethering is enabled with same @a tethering handle.
 * @param[in]  tethering  The tethering handle
 * @param[in]  ssid  The SSID
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 */
int tethering_wifi_set_ssid(tethering_h tethering, const char *ssid);

/**
 * @brief Gets the SSID (service set identifier).
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks @a ssid must be released using free().
 * @param[in]  tethering  The tethering handle
 * @param[out]  ssid  The SSID
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 */
int tethering_wifi_get_ssid(tethering_h tethering, char **ssid);

/**
 * @brief Sets the visibility of SSID (service set identifier).
 * @details If the visibility is set to invisible, then the SSID of this device is hidden and Wi-Fi scan will not find the device.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks This change is applied next time Wi-Fi tethering is enabled.
 * @param[in]  tethering  The tethering handle
 * @param[in]  visible  The visibility of SSID: (@c true = visible, @c false = invisible)
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_get_ssid_visibility()
 */
int tethering_wifi_set_ssid_visibility(tethering_h tethering, bool visible);

/**
 * @brief Gets the visibility of SSID (service set identifier).
 * @details If the visibility is set to invisible, then the SSID of this device is hidden and Wi-Fi scan will not find the device.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[out]  visible  The visibility of SSID: (@c true = visible, @c false = invisible)
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_set_ssid_visibility()
 */
int tethering_wifi_get_ssid_visibility(tethering_h tethering, bool *visible);

/**
 * @brief Sets the passphrase.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks This change is applied next time Wi-Fi tethering is enabled.
 * @param[in]  tethering  The tethering handle
 * @param[in]  passphrase  The passphrase
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_get_passphrase()
 */
int tethering_wifi_set_passphrase(tethering_h tethering, const char *passphrase);

/**
 * @brief Gets the passphrase.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks @a passphrase must be released using free().
 * @param[in]  tethering  The tethering handle
 * @param[out]  passphrase  The passphrase
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_set_passphrase()
 */
int tethering_wifi_get_passphrase(tethering_h tethering, char **passphrase);

/**
 * @brief Reloads the settings (SSID / Passphrase / Security type / SSID visibility).
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks Connected devices via Wi-Fi tethering or MobileAP will be disconnected when the settings are reloaded.
 * @param[in]  tethering  The tethering handle
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 */
int tethering_wifi_reload_settings(tethering_h tethering, tethering_wifi_settings_reloaded_cb callback, void *user_data);

/**
 * @brief Gets the mac_filter for Wi-Fi Tethering.
 * @details If you set the mac_filter to enable, then the device can be allowed/blocked based on mac-address.
 * By default mac_filter is set to false.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[out]  mac_filter The mac filter: (@c true = enable, @c false = disable)
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORTED  API is not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 * @see  tethering_mobileap_set_mac_filter()
 */
int tethering_wifi_get_mac_filter(tethering_h tethering, bool *mac_filter);

/**
 * @brief Sets the mac-filter for Wi-Fi Tethering.
 * @details If you set the mac_filter to enable, then the device can be allowed/blocked based on mac-address.
 * By default mac_filter is set to @c false.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks This change is applied next time Wi-Fi tethering is enabled.
 * @param[in]  tethering  The tethering handle
 * @param[in]  mac_filter  The mac filter: (@c true = enable, @c false = disable)
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_SUPPORTED  API is not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 * @see  tethering_mobileap_get_mac_filter()
 */
int tethering_wifi_set_mac_filter(tethering_h tethering, bool mac_filter);

/**
 * @brief Adds the mac-address to the allowed client list.
 * @details AP can allow the client by adding clients mac-address to the allowed list.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  mac  The mac address
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORTED  API is not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 * @see  tethering_mobileap_set_mac_filter()
 */
int tethering_wifi_add_allowed_mac_list(tethering_h tethering, const char *mac);

/**
 * @brief Removes the mac-address from the allowed client list.
 * @details Removes the mac-address from the allowed client list.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  mac  The mac address
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORTED  API is not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 * @see  tethering_mobileap_set_mac_filter()
 */
int tethering_wifi_remove_allowed_mac_list(tethering_h tethering, const char *mac);
/**
 * @brief Gets the mac-addresses from the allowed client list.
 * @details Gets the mac-addresses from the allowed client list.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[out]  allowed_mac_list  list of allowed mac addresses list
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORTED  API is not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 * @see  tethering_mobileap_set_mac_filter()
 */
int tethering_wifi_get_allowed_mac_list(tethering_h tethering, void **allowed_mac_list);

/**
 * @brief Adds the mac-address to the blocked(black list) client list.
 * @details AP can disallow the client by adding clients mac-address to the blocked list.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  mac  The mac address
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORTED  API is not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 * @see  tethering_mobileap_set_mac_filter()
 */
int tethering_wifi_add_blocked_mac_list(tethering_h tethering, const char *mac);

/**
 * @brief Removes the mac-address from the blocked(black list) client list.
 * @details Removes the mac-address from the blocked client list.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  mac  The mac address
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORTED  API is not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 * @see  tethering_mobileap_set_mac_filter()
 */
int tethering_wifi_remove_blocked_mac_list(tethering_h tethering, const char *mac);

/**
 * @brief Gets the mac-addresses from the blocked client list.
 * @details Get the mac-addresses from the blocked client list.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[out]  blocked_mac_list  list of blocked mac addresses list
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORTED  API is not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 * @see  tethering_mobileap_set_mac_filter()
 */
int tethering_wifi_get_blocked_mac_list(tethering_h tethering, void **blocked_mac_list);

/**
 * @brief Enables/disables the dhcp server.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @details Enable/disable the dhcp server.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  enable  Enable/disable the dhcp server
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int tethering_wifi_enable_dhcp(tethering_h tethering, bool enable);

/**
 * @brief Enables the dhcp server with the address range.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @details Enable the dhcp server with the address range.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  rangestart Start address range
 * @param[in]  rangestop  End address range
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int tethering_wifi_set_dhcp_range(tethering_h tethering, char *rangestart, char *rangestop);

/**
 * @brief Checks whether the dhcp is enabled or not.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[out] dhcp_enabled  @c true if dhcp is enabled, \n @c false if dhcp is disabled
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int tethering_wifi_is_dhcp_enabled(tethering_h tethering, bool *dhcp_enabled);

/**
 * @brief Sets the Channel for Wi-Fi.
 * @details The Channel should be in between 1-14. If channel is not set, Wi-Fi sets default channel.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  channel  The channel number
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int tethering_wifi_set_channel(tethering_h tethering, int channel);

/**
 * @brief Gets the channel for Wi-Fi.
 * @details If channel is not set, Wi-Fi gets default channel.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[out]  channel  The channel number
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_set_channel()
 */
int tethering_wifi_get_channel(tethering_h tethering, int *channel);

/**
 * @brief Sets the mode for Wi-Fi.
 * @details The mobile AP mode (ex: b only, g only, ad, a). If mode is not set, Wi-Fi sets default mode.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type	The mobile AP mode
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 */
int tethering_wifi_set_mode(tethering_h tethering, tethering_wifi_mode_type_e type);

/**
 * @brief Gets the mode for Wi-Fi.
 * @details If the mode is not set, Wi-Fi gets default mode.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks @a mode must be released using free().
 * @param[in]  tethering  The tethering handle
 * @param[out]  type  The mode of Wi-Fi tethering
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_set_mode()
 */
int tethering_wifi_get_mode(tethering_h tethering, tethering_wifi_mode_type_e *type);

/**
 * @brief Sets txpower for Wi-Fi tethering.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in] tethering The tethering handle
 * @param[in] txpower  value of txpower to be set
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 * @see tethering_wifi_get_txpower()
 */
int tethering_wifi_set_txpower(tethering_h tethering, unsigned int txpower);

/**
 * @brief Gets txpower for Wi-Fi tethering.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in] tethering The tethering handle
 * @param[out] txpower  value of txpower
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 * @see tethering_wifi_set_txpower()
 */
int tethering_wifi_get_txpower(tethering_h tethering, unsigned int *txpower);

/**
  * @brief Sets mtu for Wi-Fi tethering.
  * @since_tizen 3.0
  * @privlevel platform
  * @privilege %http://tizen.org/privilege/tethering.admin
  * @param[in] tethering The tethering handle
  * @param[in] mtu value of mtu to be set
  * @return  0 on success, otherwise a negative error value
  * @retval  #TETHERING_ERROR_NONE  Successful
  * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
  * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
  * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
  */
int tethering_wifi_set_mtu(tethering_h tethering, unsigned int mtu);

/**
  * @brief Changes mac address for Wi-Fi tethering.
  * @since_tizen 3.0
  * @privlevel platform
  * @privilege %http://tizen.org/privilege/tethering.admin
  * @param[in] tethering The client handle
  * @param[in]  mac  The mac address
  * @return  0 on success, otherwise a negative error value
  * @retval  #TETHERING_ERROR_NONE  Successful
  * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
  * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
  * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
  */
int tethering_wifi_change_mac(tethering_h tethering, char *mac);

/**
  * @brief Sets max connected devices for Wi-Fi tethering.
  * @since_tizen 3.0
  * @privlevel platform
  * @privilege %http://tizen.org/privilege/tethering.admin
  * @param[in] tethering The client handle
  * @param[in] max_device value of max_device to be set
  * @return  0 on success, otherwise a negative error value
  * @retval  #TETHERING_ERROR_NONE  Successful
  * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
  * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
  * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
  * @see tethering_wifi_get_max_connected_device()
  */
int tethering_wifi_set_max_connected_device(tethering_h tethering, int max_device);

/**
  * @brief Gets max connected devices for Wi-Fi tethering.
  * @since_tizen 3.0
  * @privlevel platform
  * @privilege %http://tizen.org/privilege/tethering.admin
  * @param[in] tethering The client handle
  * @param[out] max_device value of max_device
  * @return  0 on success, otherwise a negative error value
  * @retval  #TETHERING_ERROR_NONE  Successful
  * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
  * @see tethering_wifi_set_max_connected_device()
  */
int tethering_wifi_get_max_connected_device(tethering_h tethering, int *max_device);

/**
  * @brief Enables port forwarding feature.
  * @since_tizen 3.0
  * @privlevel platform
  * @privilege %http://tizen.org/privilege/tethering.admin
  * @details enable/disable port forwarding feature.
  * @param[in]  tethering  The handle of tethering
  * @param[in]  enable Enable/Disable port forwarding
  * @return 0 on success, otherwise negative error value.
  * @retval  #TETHERING_ERROR_NONE  Successful
  * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
  * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
  * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
  */
int tethering_wifi_enable_port_forwarding(tethering_h tethering, bool enable);

/**
  * @brief Sets port forwarding rule.
  * @since_tizen 3.0
  * @privlevel platform
  * @privilege %http://tizen.org/privilege/tethering.admin
  * @details Set port forwarding rule.
  * @param[in]  tethering  The handle of tethering
  * @param[in]  ifname interface name
  * @param[in]  protocol protocol (tcp/udp)
  * @param[in]  org_ip original destination ip where packet was meant to sent
  * @param[in]  org_port original destination port where packet was meant to sent
  * @param[in]  final_ip new destination ip where packet will be forwarded
  * @param[in]  final_port new destination port where packet will be forwarded
  * @return 0 on success, otherwise negative error value.
  * @retval  #TETHERING_ERROR_NONE  Successful
  * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
  * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
  * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
  */
int tethering_wifi_add_port_forwarding_rule(tethering_h tethering, char *ifname, char *protocol, char *org_ip, int org_port, char *final_ip, int final_port);

/**
  * @brief Resets port forwarding rule.
  * @since_tizen 3.0
  * @privlevel platform
  * @privilege %http://tizen.org/privilege/tethering.admin
  * @details Reset port forwarding rule.
  * @param[in]  tethering  The handle of tethering
  * @return 0 on success, otherwise negative error value.
  * @retval  #TETHERING_ERROR_NONE  Successful
  * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
  * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
  * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
  */
int tethering_wifi_reset_port_forwarding_rule(tethering_h tethering);

/**
 * @brief Checks whether the port forwarding is enabled or not.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[out] forwarding_enabled  @c true if port forwarding is enabled, \n @c false if port forwarding is disabled
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 */
int tethering_wifi_is_port_forwarding_enabled(tethering_h tethering, bool* forwarding_enabled);

/**
 * @brief Gets the port forwarding rule for Wi-Fi tethering.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in] tethering The client handle
 * @param[out] port_forwarding_list list of port forwarding rules
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 */
int tethering_wifi_get_port_forwarding_rule(tethering_h tethering, void **port_forwarding_list);

/**
 * @brief Enables port filtering feature.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @details enable/disable port filtering feature.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  enable Enable/Disable port filtering
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 */
int tethering_wifi_enable_port_filtering(tethering_h tethering, bool enable);

/**
 * @brief Sets port filtering rule.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @details Set port filtering rule.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  port to be filtered
 * @param[in]  protocol protocol (tcp/udp)
 * @param[in]  allow allow/disallow port filtering
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 */
int tethering_wifi_add_port_filtering_rule(tethering_h tethering, int port, char *protocol, bool allow);

/**
 * @brief Sets custom port filtering rule.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @details Set custom port filtering rule.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  port1 to be filtered
 * @param[in]  port2 to be filtered
 * @param[in]  protocol protocol (tcp/udp)
 * @param[in]  allow allow/disallow port filtering
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 */
int tethering_wifi_add_custom_port_filtering_rule(tethering_h tethering, int port1, int port2, char *protocol, bool allow);

/**
 * @brief Gets the port filtering rule for Wi-Fi tethering.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in] tethering The client handle
 * @param[out] port_filtering_list list of port filtering rules
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 */
int tethering_wifi_get_port_filtering_rule(tethering_h tethering, void **port_filtering_list);

/**
 * @brief Gets the custom port filtering rule for Wi-Fi tethering.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in] tethering The client handle
 * @param[out] custom_port_filtering_list list of custom port filtering rules
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 */
int tethering_wifi_get_custom_port_filtering_rule(tethering_h tethering, void **custom_port_filtering_list);

/**
 * @brief Checks whether the port filtering is enabled or not.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[out] filtering_enabled  @c true if port filtering is enabled, \n @c false if port filtering is disabled
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 */
int tethering_wifi_is_port_filtering_enabled(tethering_h tethering, bool* filtering_enabled);

/**
 * @brief Sets vpn passthrough rule.
 * @since_tizen 3.0
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @details Set vpn passthrough rule.
 * @param[in]  tethering	The handle of tethering
 * @param[in]  type			vpn passthrough type
 * @param[in]  enable		@c true if vpn passthrough is enabled, \n @c false if vpn passthrough is disabled
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API not supported
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission Denied
 */
int tethering_wifi_set_vpn_passthrough_rule(tethering_h tethering, tethering_vpn_passthrough_type_e type, bool enable);

/**
 * @brief Pushes the WPS button to connect with Wi-Fi Tethering client. (WPS PBC)
 * @since_tizen 3.0
 * @remarks The WPS button should be pushed when client tries to connect with Soft AP by using WPS PBC.
 * @param[in]  tethering  The tethering handle
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission denied
 * @retval  #TETHERING_ERROR_NOT_SUPPORTED  API is not supported
 */
int tethering_wifi_push_wps_button(tethering_h tethering);

/**
 * @brief Sets the WPS PIN to connect with Wi-Fi Tethering client. (WPS PIN)
 * @since_tizen 3.0
 * @remarks The WPS PIN should be inserted when client tries to connect with Soft AP by using WPS PIN.
 * @param[in]  tethering  The tethering handle
 * @param[in]  wps_pin  The WPS PIN
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_PERMISSION_DENIED  Permission denied
 * @retval  #TETHERING_ERROR_NOT_SUPPORTED  API is not supported
 */
int tethering_wifi_set_wps_pin(tethering_h tethering, const char *wps_pin);


/**
 * @}
 */


/**
 * @addtogroup CAPI_NETWORK_TETHERING_CLIENT_MODULE
 * @{
 */

/**
 * @brief Clones the handle of a client.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks @a dest must be release using tethering_client_destroy().
 * @param[out]  dest  The cloned client handle
 * @param[in]  origin  The origin client handle
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @see  tethering_client_destroy()
 */
int tethering_client_clone(tethering_client_h *dest, tethering_client_h origin);

/**
 * @brief Destroys the handle of a client.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  client  The client handle
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_client_clone()
 */
int tethering_client_destroy(tethering_client_h client);

/**
 * @brief  Gets the tethering type of client.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in]  client  The handle of client
 * @param[out]  type  The type of tethering
 * @return  0 on success, otherwise a negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_usb_get_connected_client()
 * @see  tethering_connection_state_changed_cb()
 */
int tethering_client_get_tethering_type(tethering_client_h client, tethering_type_e *type);

/**
 * @brief Gets the name of a client.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks @a name must be released using free().
 * @param[in]  client  The client handle
 * @param[out]  name  The name of the client
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @see  tethering_usb_get_connected_client()
 * @see  tethering_connection_state_changed_cb()
 */
int tethering_client_get_name(tethering_client_h client, char **name);

/**
 * @brief Gets the IP address of a client.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks @a ip_address must be released using free().
 * @param[in]  client  The client handle
 * @param[in]  address_family  The address family of IP address. Currently, #TETHERING_ADDRESS_FAMILY_IPV4 is only supported
 * @param[out]  ip_address  The IP address
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @see  tethering_usb_get_connected_client()
 * @see  tethering_connection_state_changed_cb()
 */
int tethering_client_get_ip_address(tethering_client_h client, tethering_address_family_e address_family, char **ip_address);

/**
 * @brief Gets the MAC address of a client such as "FC:A1:3E:D6:B1:B1".
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @remarks @a mac_address must be released using free().
 * @param[in]  client  The client handle
 * @param[out]  mac_address  The MAC address
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @see  tethering_usb_get_connected_client()
 * @see  tethering_connection_state_changed_cb()
 */
int tethering_client_get_mac_address(tethering_client_h client, char **mac_address);

/**
 * @brief Gets the connection time of a client.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/tethering.admin
 * @param[in] client The client handle
 * @param[out]  time  The connected time of the client
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_usb_get_connected_client()
 * @see  tethering_connection_state_changed_cb()
 */
int tethering_client_get_time(tethering_client_h client, time_t *timestamp);

/**
 * @}
 */


#ifdef __cplusplus
 }
#endif

#endif /* __TIZEN_NETWORK_TETHERING_H__ */


