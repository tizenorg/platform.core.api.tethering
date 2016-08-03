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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <glib-object.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <vconf.h>

#include "tethering.h"

#define DISABLE_REASON_TEXT_LEN	64
#define COMMON_STR_BUF_LEN	32

gboolean test_thread(GIOChannel *source, GIOCondition condition, gpointer data);

typedef struct {
	tethering_enabled_cb enabled_cb;
	tethering_disabled_cb disabled_cb;
	tethering_connection_state_changed_cb changed_cb;
	tethering_wifi_security_type_changed_cb security_type_changed_cb;
	tethering_wifi_ssid_visibility_changed_cb ssid_visibility_changed_cb;
	tethering_wifi_passphrase_changed_cb passphrase_changed_cb;
} __tethering_cbs;

tethering_h th = NULL;

static bool __is_err(tethering_error_e ret)
{
	char *err_msg = NULL;

	switch (ret) {
	case TETHERING_ERROR_INVALID_PARAMETER:
		err_msg = "Wrong parameter is used";
		break;

	case TETHERING_ERROR_OUT_OF_MEMORY:
		err_msg = "Memory is not enough";
		break;

	case TETHERING_ERROR_NONE:
		return false;

	case TETHERING_ERROR_NOT_ENABLED:
		err_msg = "Tethering is not enabled";
		break;

	case TETHERING_ERROR_OPERATION_FAILED:
		err_msg = "Operation is failed";
		break;

	case TETHERING_ERROR_RESOURCE_BUSY:
		err_msg = "Resource is busy";
		break;

	default:
		err_msg = "This should not be happened";
		break;
	}

	g_print("##ERR: %s\n", err_msg);

	return true;
}

static const char *__convert_tethering_type_to_str(const tethering_type_e type)
{
	static char str_buf[COMMON_STR_BUF_LEN] = {0, };

	switch (type) {
	case TETHERING_TYPE_USB:
		g_strlcpy(str_buf, "USB Tethering", sizeof(str_buf));
		break;

	case TETHERING_TYPE_WIFI:
		g_strlcpy(str_buf, "Wi-Fi Tethering", sizeof(str_buf));
		break;

	case TETHERING_TYPE_BT:
		g_strlcpy(str_buf, "Bluetooth Tethering", sizeof(str_buf));
		break;

	default:
		g_strlcpy(str_buf, "Unknown", sizeof(str_buf));
		break;
	}

	return str_buf;
}

static const char *__convert_disabled_code_to_str(const tethering_disabled_cause_e code)
{
	static char str_buf[DISABLE_REASON_TEXT_LEN] = {0, };

	switch (code) {
	case TETHERING_DISABLED_BY_USB_DISCONNECTION:
		strncpy(str_buf, "disabled due to usb disconnection", sizeof(str_buf));
		break;

	case TETHERING_DISABLED_BY_FLIGHT_MODE:
		strncpy(str_buf, "disabled due to flight mode on", sizeof(str_buf));
		break;

	case TETHERING_DISABLED_BY_LOW_BATTERY:
		strncpy(str_buf, "disabled due to low battery", sizeof(str_buf));
		break;

	case TETHERING_DISABLED_BY_NETWORK_CLOSE:
		strncpy(str_buf, "disabled due to pdp network close", sizeof(str_buf));
		break;

	case TETHERING_DISABLED_BY_TIMEOUT:
		strncpy(str_buf, "disabled due to timeout", sizeof(str_buf));
		break;

	case TETHERING_DISABLED_BY_OTHERS:
		strncpy(str_buf, "disabled by other apps", sizeof(str_buf));
		break;

	case TETHERING_DISABLED_BY_REQUEST:
		strncpy(str_buf, "disabled by my request", sizeof(str_buf));
		break;

	case TETHERING_DISABLED_BY_WIFI_ON:
		strncpy(str_buf, "disabled by Wi-Fi station on", sizeof(str_buf));
		break;

	case TETHERING_DISABLED_BY_BT_OFF:
		strncpy(str_buf, "disabled by bluetooth off", sizeof(str_buf));
		break;

	default:
		strncpy(str_buf, "disabled by unknown reason", sizeof(str_buf));
		break;
	}

	return str_buf;
}

static void __register_cbs(tethering_h th, __tethering_cbs *cbs, void *user_data)
{
	tethering_error_e ret = TETHERING_ERROR_NONE;

	ret = tethering_set_enabled_cb(th, TETHERING_TYPE_ALL,
			cbs->enabled_cb, user_data);
	if (__is_err(ret) == true)
		g_print("tethering_set_enabled_cb is failed\n");

	ret = tethering_set_disabled_cb(th, TETHERING_TYPE_ALL,
			cbs->disabled_cb, user_data);
	if (__is_err(ret) == true)
		g_print("tethering_set_disabled_cb is failed\n");

	ret = tethering_set_connection_state_changed_cb(th, TETHERING_TYPE_ALL,
			cbs->changed_cb, user_data);
	if (__is_err(ret) == true)
		g_print("tethering_set_connection_state_changed_cb is failed\n");

	ret = tethering_wifi_set_security_type_changed_cb(th,
			cbs->security_type_changed_cb, user_data);
	if (__is_err(ret) == true)
		g_print("tethering_wifi_set_security_type_changed_cb is failed\n");

	ret = tethering_wifi_set_ssid_visibility_changed_cb(th,
			cbs->ssid_visibility_changed_cb, user_data);
	if (__is_err(ret) == true)
		g_print("tethering_wifi_set_ssid_visibility_changed_cb is failed\n");

	ret = tethering_wifi_set_passphrase_changed_cb(th,
			cbs->passphrase_changed_cb, user_data);
	if (__is_err(ret) == true)
		g_print("tethering_wifi_set_passphrase_changed_cb is failed\n");

	return;
}

static void __deregister_cbs(tethering_h th)
{
	tethering_error_e ret = TETHERING_ERROR_NONE;

	ret = tethering_unset_enabled_cb(th, TETHERING_TYPE_ALL);
	if (__is_err(ret) == true)
		g_print("tethering_unset_enabled_cb is failed\n");

	ret = tethering_unset_disabled_cb(th, TETHERING_TYPE_ALL);
	if (__is_err(ret) == true)
		g_print("tethering_unset_disabled_cb is failed\n");

	ret = tethering_unset_connection_state_changed_cb(th, TETHERING_TYPE_ALL);
	if (__is_err(ret) == true)
		g_print("tethering_unset_connection_state_changed_cb is failed\n");

	ret = tethering_wifi_unset_security_type_changed_cb(th);
	if (__is_err(ret) == true)
		g_print("tethering_wifi_unset_security_type_changed_cb is failed\n");

	ret = tethering_wifi_unset_ssid_visibility_changed_cb(th);
	if (__is_err(ret) == true)
		g_print("tethering_wifi_unset_ssid_visibility_changed_cb is failed\n");

	ret = tethering_wifi_unset_passphrase_changed_cb(th);
	if (__is_err(ret) == true)
		g_print("tethering_wifi_unset_passphrase_changed_cb is failed\n");

	return;
}

/* Tethering callbacks */
static void __enabled_cb(tethering_error_e error, tethering_type_e type, bool is_requested, void *data)
{
	if (__is_err(error)) {
		if (!is_requested)
			return;

		g_print("## %s is not enabled. error code[0x%X]\n",
				__convert_tethering_type_to_str(type),
				error);
		return;
	}

	if (is_requested)
		g_print("## %s is enabled successfully\n",
				__convert_tethering_type_to_str(type));
	else
		g_print("## %s is enabled by other app\n",
				__convert_tethering_type_to_str(type));

	return;
}

static void __disabled_cb(tethering_error_e error, tethering_type_e type, tethering_disabled_cause_e code, void *data)
{
	if (__is_err(error)) {
		if (code != TETHERING_DISABLED_BY_REQUEST)
			return;

		g_print("## %s is not disabled. error code[0x%X]\n",
				__convert_tethering_type_to_str(type), error);
		return;
	}

	g_print("## %s is %s\n",
			__convert_tethering_type_to_str(type),
			__convert_disabled_code_to_str(code));

	return;
}

static void __connection_state_changed_cb(tethering_client_h client, bool open, void *data)
{
	tethering_client_h clone = NULL;
	tethering_type_e type;
	char *ip_address = NULL;
	char *mac_address = NULL;
	char *hostname = NULL;

	tethering_client_clone(&clone, client);
	if (clone == NULL) {
		g_print("tetheirng_client_clone is failed\n");
		return;
	}

	tethering_client_get_tethering_type(clone, &type);
	tethering_client_get_ip_address(clone,
			TETHERING_ADDRESS_FAMILY_IPV4, &ip_address);
	tethering_client_get_mac_address(clone, &mac_address);
	tethering_client_get_name(clone, &hostname);

	if (open) {
		g_print("## New station Type [%s], IP [%s], MAC [%s], hostname [%s]\n",
				__convert_tethering_type_to_str(type),
				ip_address, mac_address, hostname);
	} else {
		g_print("## Disconnected station Type [%s], IP [%s], MAC [%s], hostname [%s]\n",
				__convert_tethering_type_to_str(type),
				ip_address, mac_address, hostname);
	}

	if (ip_address)
		free(ip_address);
	if (mac_address)
		free(mac_address);
	if (hostname)
		free(hostname);

	tethering_client_destroy(clone);

	return;
}

static void __data_usage_cb(tethering_error_e result, unsigned long long received_data,
		unsigned long long sent_data, void *user_data)
{
	g_print("__data_usage_cb\n");

	if (result != TETHERING_ERROR_NONE) {
		g_print("tethering_get_data_usage is failed. error[0x%X]\n", result);
		return;
	}

	g_print("## Received data : %llu bytes\n", received_data);
	g_print("## Sent data : %llu bytes\n", sent_data);

	return;
}

static void __settings_reloaded_cb(tethering_error_e result, void *user_data)
{
	g_print("__settings_reloaded_cb\n");

	if (result != TETHERING_ERROR_NONE) {
		g_print("tethering_wifi_reload_settings is failed. error[0x%X]\n", result);
		return;
	}

	g_print("## Wi-Fi tethering setting is reloaded\n");

	return;
}

static bool __clients_foreach_cb(tethering_client_h client, void *data)
{
	tethering_client_h clone = NULL;
	tethering_type_e type;
	char *ip_address = NULL;
	char *mac_address = NULL;
	char *hostname = NULL;

	/* Clone internal information */
	if (tethering_client_clone(&clone, client) != TETHERING_ERROR_NONE) {
		g_print("tethering_client_clone is failed\n");
		return false;
	}

	/* Get information */
	if (tethering_client_get_tethering_type(clone, &type) != TETHERING_ERROR_NONE)
		g_print("tethering_client_get_type is failed\n");

	if (tethering_client_get_ip_address(clone, TETHERING_ADDRESS_FAMILY_IPV4, &ip_address) != TETHERING_ERROR_NONE)
		g_print("tethering_client_get_ip_address is failed\n");

	if (tethering_client_get_mac_address(clone, &mac_address) != TETHERING_ERROR_NONE)
		g_print("tethering_client_get_mac_address is failed\n");

	if (tethering_client_get_name(clone, &hostname) != TETHERING_ERROR_NONE)
		g_print("tethering_client_get_hostname is failed\n");

	/* End of getting information */

	g_print("\n< Client Info. >\n");
	g_print("\tType %s\n", __convert_tethering_type_to_str(type));
	g_print("\tIP Address %s\n", ip_address);
	g_print("\tMAC Address : %s\n", mac_address);
	g_print("\tHostname : %s\n", hostname);

	/* Destroy cloned objects */
	if (ip_address)
		free(ip_address);
	if (mac_address)
		free(mac_address);
	if (hostname)
		free(hostname);

	tethering_client_destroy(clone);

	/* Continue iteration */
	return true;
}

static void __security_type_changed_cb(tethering_wifi_security_type_e changed_type, void *user_data)
{

	char *sec_str = NULL;

	switch (changed_type) {
	case TETHERING_WIFI_SECURITY_TYPE_NONE:
		sec_str = "open";
		break;
	case TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK:
		sec_str = "wpa2-psk";
		break;
	case TETHERING_WIFI_SECURITY_TYPE_WPS:
		sec_str = "wps";
		break;
	default:
		sec_str = "unknown";
		break;
	}
	g_print("Wi-Fi Tethering Security type is changed to [%s]\n", sec_str);

	return;
}

static void __ssid_visibility_changed_cb(bool changed_visible, void *user_data)
{
	g_print("SSID visibility for Wi-Fi tethering changed to [%s]\n",
			changed_visible ? "visible" : "invisible");
	return;
}

static void __passphrase_changed_cb(void *user_data)
{
	g_print("Wi-Fi Tethering passphrase is changed\n");
	return;
}
/* End of tethering callbacks */

static void __print_interface_info(tethering_h th, tethering_type_e type)
{
	char *interface = NULL;
	char *mac_address = NULL;
	char *ip_address = NULL;
	char *gateway_address = NULL;
	char *subnet_mask = NULL;

	if (tethering_is_enabled(th, type) == FALSE) {
		g_print("%s is not enabled\n",
				__convert_tethering_type_to_str(type));
		return;
	}

	tethering_get_network_interface_name(th, type, &interface);
	tethering_get_mac_address(th, type, &mac_address);
	tethering_get_ip_address(th, type, TETHERING_ADDRESS_FAMILY_IPV4,
			&ip_address);
	tethering_get_gateway_address(th, type, TETHERING_ADDRESS_FAMILY_IPV4,
			&gateway_address);
	tethering_get_subnet_mask(th, type, TETHERING_ADDRESS_FAMILY_IPV4,
			&subnet_mask);

	g_print("interface name : %s\n", interface);
	g_print("mac address : %s\n", mac_address);
	g_print("ip address : %s\n", ip_address);
	g_print("gateway address: %s\n", gateway_address);
	g_print("subnet mask : %s\n", subnet_mask);

	if (interface)
		free(interface);
	if (mac_address)
		free(mac_address);
	if (ip_address)
		free(ip_address);
	if (gateway_address)
		free(gateway_address);
	if (subnet_mask)
		free(subnet_mask);

	return;
}

static void __print_wifi_tethering_setting(tethering_h th)
{
	char *ssid = NULL;
	char *passphrase = NULL;
	char *sec_str = NULL;
	bool visibility = false;
	bool mac_filter = 0;
	bool forwarding_enabled = false;
	bool filtering_enabled = false;
	int channel = 0;
	int max_connected = 0;
	tethering_wifi_security_type_e security_type = TETHERING_WIFI_SECURITY_TYPE_NONE;
	tethering_wifi_mode_type_e hw_mode = TETHERING_WIFI_MODE_TYPE_G;

	int error = TETHERING_ERROR_NONE;

	error = tethering_wifi_get_ssid(th, &ssid);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else
		g_print("\n\t** WiFi tethering SSID : %s\n", ssid);

	error = tethering_wifi_get_passphrase(th, &passphrase);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else
		g_print("\t** WiFi tethering passphrase : %s\n", passphrase);

	error = tethering_wifi_get_ssid_visibility(th, &visibility);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else
		g_print("\t** WiFi tethering ssid visibility : %s\n",
				visibility ? "visible" : "invisible");

	error = tethering_wifi_get_security_type(th, &security_type);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else {
		switch (security_type) {
		case TETHERING_WIFI_SECURITY_TYPE_NONE:
			sec_str = "open";
			break;
		case TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK:
			sec_str = "wpa2-psk";
			break;
		case TETHERING_WIFI_SECURITY_TYPE_WPS:
			sec_str = "wps";
			break;
		default:
			sec_str = "unknown";
			break;
		}
		g_print("\t** WiFi tethering security_type : %s\n", sec_str);
	}

	error = tethering_wifi_get_mode(th, &hw_mode);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else
		 g_print("\t** WiFi tethering mode : %d\n", hw_mode);

	error = tethering_wifi_get_channel(th, &channel);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else
		 g_print("\t** WiFi tethering channel : %d\n", channel);

	error = tethering_wifi_get_max_connected_device(th, &max_connected);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else
		 g_print("\t** WiFi tethering max connected device : %d\n", max_connected);

	error = tethering_wifi_get_mac_filter(th, &mac_filter);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else
		g_print("\t** WiFi tethering mac filter : %s\n",
				mac_filter ? "enable" : "disable");

	error = tethering_wifi_is_port_filtering_enabled(th, &filtering_enabled);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else
		g_print("\t** WiFi tethering port filtering : %s\n",
				filtering_enabled ? "enable" : "disable");

	error = tethering_wifi_is_port_forwarding_enabled(th, &forwarding_enabled);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else
		g_print("\t** WiFi tethering port forwarding : %s\n",
				forwarding_enabled ? "enable" : "disable");

	if (ssid)
		free(ssid);
	if (passphrase)
		free(passphrase);

	return;
}

void __display_list(GSList *list)
{
	GSList *iterator = NULL;

	for (iterator = list; iterator; iterator = iterator->next)
		printf("%s\n", (char*)iterator->data);
}

bool __get_tethering_type(tethering_type_e *type)
{
	int sel;
	int ret;

	printf("Select tethering type (1:Wi-Fi, 2:BT, 3:USB 4:ALL)\n");
	ret = scanf("%9d", &sel);
	if (ret < 0) {
		printf("scanf is failed!!\n");
		return false;
	}

	switch (sel) {
	case 1:
		*type = TETHERING_TYPE_WIFI;
		break;
	case 2:
		*type = TETHERING_TYPE_BT;
		break;
	case 3:
		*type = TETHERING_TYPE_USB;
		break;
	case 4:
		*type = TETHERING_TYPE_ALL;
		break;
	default:
		printf("Invalid input!!\n");
		return false;
	}

	return true;
}

static int test_tethering_create(void)
{
	int ret = tethering_create(&th);
	__tethering_cbs cbs = {
		__enabled_cb, __disabled_cb,
		__connection_state_changed_cb, __security_type_changed_cb,
		__ssid_visibility_changed_cb, __passphrase_changed_cb};

	if (__is_err(ret) == false) __register_cbs(th, &cbs, NULL);
	else {
		printf("Tethering create is failed\n");
		return -1;
	}
	printf("Tethering create and register callback success\n");

	return 1;
}

static int test_tethering_destroy(void)
{
	int ret = TETHERING_ERROR_NONE;

	__deregister_cbs(th);

	ret = tethering_destroy(th);
	if (__is_err(ret) == true) {
		printf("Tethering destroy is failed\n");
		return -1;
	}

	return 1;
}

static int test_tethering_enable(void)
{
	int ret = TETHERING_ERROR_NONE;
	tethering_type_e type;

	if (!__get_tethering_type(&type))
		return -1;

	ret = tethering_enable(th, type);
	if (__is_err(ret) == true) {
		printf("Fail to enable tethering\n");
		return -1;
	}
	return 1;
}

static int test_tethering_disable(void)
{
	int ret = TETHERING_ERROR_NONE;
	tethering_type_e type;

	if (!__get_tethering_type(&type))
		return -1;

	ret = tethering_disable(th, type);
	if (__is_err(ret) == true) {
		printf("Fail to disable tethering\n");
		return -1;
	}
	return 1;
}

static int test_tethering_get_client_info(void)
{
	int ret;
	tethering_type_e type;

	if (!__get_tethering_type(&type))
		return -1;

	ret = tethering_foreach_connected_clients(th, type,
					__clients_foreach_cb, NULL);
	if (__is_err(ret) == true) {
		printf("Fail to disable tethering\n");
		return -1;
	}

	return 1;
}

static int test_tethering_get_interface_info(void)
{
	tethering_type_e type;

	if (!__get_tethering_type(&type))
		return -1;

	__print_interface_info(th, type);

	return 1;
}

static int test_tethering_get_data_usage(void)
{
	int ret = tethering_get_data_usage(th, __data_usage_cb, NULL);

	if (__is_err(ret) == true) {
		printf("Fail to get data usage!!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_get_setting(void)
{
	__print_wifi_tethering_setting(th);
	return 1;
}

static int test_tethering_wifi_set_ssid(void)
{
	int ret;
	char ssid[100];

	printf("Input SSID for Wi-Fi tethering: ");
	ret = scanf("%99s", ssid);
	if (ret < 0) {
		printf("scanf is failed!!\n");
		return -1;
	}

	ret = tethering_wifi_set_ssid(th, ssid);
	if (__is_err(ret) == true) {
		printf("Fail to set wifi ssid!!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_set_security_type(void)
{
	int ret;
	int security_type;

	printf("Input security type for Wi-Fi tethering (0:NONE, 1:WPA2_PSK, 2:WPS)");
	ret = scanf("%9d", &security_type);
	if (ret < 0) {
		printf("scanf is failed!!\n");
		return -1;
	}

	ret = tethering_wifi_set_security_type(th, security_type);
	if (__is_err(ret) == true) {
		printf("Fail to set security type!!\n");
		return -1;
	}

	return 1;
}

int test_tethering_wifi_set_visibility(void)
{
	int ret;
	int visibility;

	printf("Input security type for Wi-Fi tethering (0:invisible, 1:visible)");
	ret = scanf("%9d", &visibility);
	if (ret < 0) {
		printf("scanf is failed!!\n");
		return -1;
	}

	ret = tethering_wifi_set_ssid_visibility(th, visibility);
	if (__is_err(ret) == true) {
		printf("Fail to set visibility!!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_set_passphrase(void)
{
	int ret;
	char passphrase[100];

	printf("Input passphrase for Wi-Fi tethering: ");
	ret = scanf("%99s", passphrase);
	if (ret < 0) {
		printf("scanf is failed!!\n");
		return -1;
	}

	ret = tethering_wifi_set_passphrase(th, passphrase);
	if (__is_err(ret) == true) {
		printf("Fail to set passphrase!!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_set_channel(void)
{
	int ret;
	int channel;

	printf("Input channel for Wi-Fi tethering: ");
	ret = scanf("%d", &channel);

	ret = tethering_wifi_set_channel(th, channel);
	if (__is_err(ret) == true) {
		printf("Fail to set channel!!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_set_mode(void)
{
	int ret;
	int type;

	printf("Input hw_mode for Wi-Fi tethering(0-b, 1-g, 2-a, 3-ad): ");
	ret = scanf("%d", &type);

	ret = tethering_wifi_set_mode(th, type);
	if (__is_err(ret) == true) {
		printf("Fail to set mode!!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_enable_dhcp(void)
{
	int ret;
	int enable;

	printf("Input (0-Disable, 1-Enable): ");
	ret = scanf("%d", &enable);

	ret = tethering_wifi_enable_dhcp(th, enable);
	if (__is_err(ret) == true) {
		printf("Fail to enable dhcp server!!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_set_dhcp_range(void)
{
	int ret;
	char rangestart[16], rangestop[16];

	printf("Input range (ex: 192.168.0.50 192.168.0.150): ");

	ret = scanf("%15s %15s", rangestart, rangestop);

	ret = tethering_wifi_set_dhcp_range(th, rangestart, rangestop);
	if (__is_err(ret) == true) {
		printf("Fail to set dhcp range and enable dhcp server!!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_is_dhcp_enabled(void)
{
	int ret;
	bool enabled;

	ret = tethering_wifi_is_dhcp_enabled(th, &enabled);

	if (__is_err(ret) == true) {
		printf("Fail to get dhcp server status!!\n");
		return -1;
	} else {
		printf("DHCP server is %s\n", enabled ? "enabled" : "disabled");
	}

	return 1;
}

static int test_tethering_wifi_set_mac_filtering(void)
{
	int ret;
	int enable;

	printf("Input mac filtering option (0: disable, 1: enable): ");
	ret = scanf("%d", &enable);

	ret = tethering_wifi_set_mac_filter(th, enable);
	if (__is_err(ret) == true) {
		printf("Fail to set mac filtering!!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_manage_mac_list(void)
{
	int ret = 0;
	int list, option;
	char mac[100];

	printf("Select MAC list to modify (0: allowed mac list, 1: blocked mac list): ");
	ret = scanf("%d", &list);

	printf("Select option (0: Add, 1: Remove): ");
	ret = scanf("%d", &option);

	printf("Input MAC Address to add/remove allowed/blocked mac list: ");
	ret = scanf("%99s", mac);
	if (ret < 0) {
		printf("scanf is failed!!\n");
		return -1;
	}

	if (!list && !option) {
		/* Add to allowed mac list*/
		ret = tethering_wifi_add_allowed_mac_list(th, mac);
	} else if (!list && option) {
		/* Remove from allowed mac list */
		ret = tethering_wifi_remove_allowed_mac_list(th, mac);
	} else if (list && !option) {
		/* Add to blocked mac list */
		ret = tethering_wifi_add_blocked_mac_list(th, mac);
	} else if (list && option) {
		/* Remove from blocked mac list */
		ret = tethering_wifi_remove_blocked_mac_list(th, mac);
	} else {
		printf("Input failed!!\n");
		return -1;
	}

	if (ret < 0)
		return -1;

	return 1;
}

static int test_tethering_get_mac_list(void)
{
	int ret = 0;
	int list = 0;
	void *mac_list = NULL;

	printf("Select MAC list to get (0: allowed mac list, 1: blocked mac list): ");
	ret = scanf("%d", &list);

	switch (list) {
	case 0:
		ret = tethering_wifi_get_allowed_mac_list(th, &mac_list);
		break;
	case 1:
		ret = tethering_wifi_get_blocked_mac_list(th, &mac_list);
		break;
	default:
		printf("Input failed!!\n");
		break;
	}

	if (ret < 0)
		return -1;

	__display_list(mac_list);

	return 1;
}

static int test_tethering_wifi_reload_settings(void)
{
	int ret = tethering_wifi_reload_settings(th, __settings_reloaded_cb, NULL);

	if (__is_err(ret) == true) {
		printf("Fail to reload wifi tethering!!\n");
		return -1;
	}
	return 1;
}

static int test_tethering_wifi_get_txpower(void)
{
	int ret = TETHERING_ERROR_NONE;

	unsigned int txpower = 0;
	ret = tethering_wifi_get_txpower(th, &txpower);
	if (__is_err(ret) == true) {
		printf("Fail to get txpower!!\n");
		return -1;
	}
	g_print("tethering_hostapd_get_txpower received [%d]\n", txpower);
	return 1;
}

static int test_tethering_wifi_set_txpower(void)
{
	int ret;
	unsigned int txpower = 0;

	printf("Input tx power for Wi-Fi tethering: ");
	ret = scanf("%d", &txpower);

	ret = tethering_wifi_set_txpower(th, txpower);
	if (__is_err(ret) == true) {
		printf("Fail to set txpower!!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_set_mtu(void)
{
	int ret;
	unsigned int mtu = 0;

	printf("Input mtu for Wi-Fi tethering: ");
	ret = scanf("%d", &mtu);

	ret = tethering_wifi_set_mtu(th, mtu);
	if (__is_err(ret) == true) {
		printf("Fail to set mtu!!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_change_mac(void)
{
	int ret;
	char mac[18];

	printf("Input mac address: ");
	ret = scanf("%17s", mac);

	ret = tethering_wifi_change_mac(th, mac);
	if (__is_err(ret) == true) {
		printf("Fail to change mac!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_set_max_connected_device(void)
{
	int ret;
	int max_connected;

	printf("Input max connected device: ");
	ret = scanf("%d", &max_connected);

	ret = tethering_wifi_set_max_connected_device(th, max_connected);
	if (__is_err(ret) == true) {
		printf("Fail to set max connected device!\n");
		return -1;
	}

	return 1;

}

static int test_tethering_wifi_enable_port_forwarding(void)
{
	int ret;
	int enable = false;

	printf("Wi-Fi tethring port forwarding(0:disable 1:enable): ");
	ret = scanf("%d", &enable);

	ret = tethering_wifi_enable_port_forwarding(th, enable);
	if (__is_err(ret) == true) {
		printf("Fail to enable port forwarding!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_add_port_forwarding_rule(void)
{
	int ret;
	char ifname[20];
	char proto[20];
	char org_ip[16];
	char final_ip[16];
	int org_port, final_port;

	printf("Input ifname, protocol, original ip/port, final ip/port: ");
	ret = scanf("%19s", ifname);
	ret = scanf("%19s", proto);
	ret = scanf("%15s", org_ip);
	ret = scanf("%d", &org_port);
	ret = scanf("%15s", final_ip);
	ret = scanf("%d", &final_port);

	ret = tethering_wifi_add_port_forwarding_rule(th, ifname, proto, org_ip, org_port, final_ip, final_port);
	if (__is_err(ret) == true) {
		printf("Fail to add port forwarding rule!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_reset_port_forwarding_rule(void)
{
	int ret;

	ret = tethering_wifi_reset_port_forwarding_rule(th);
	if (__is_err(ret) == true) {
		printf("Fail to reset port forwarding rule!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_get_port_forwarding_rule(void)
{
	int ret = 0;
	void *pf_list = NULL;

	ret = tethering_wifi_get_port_forwarding_rule(th, &pf_list);
	if (__is_err(ret) == true) {
		printf("Fail to get port forwarding rule!\n");
		return -1;
	}

	__display_list(pf_list);

	return 1;
}

static int test_tethering_wifi_enable_port_filtering(void)
{
	int ret;
	int enable = false;

	printf("Wi-Fi tethring port filtering(0:disable 1:enable): ");
	ret = scanf("%d", &enable);

	ret = tethering_wifi_enable_port_filtering(th, enable);
	if (__is_err(ret) == true) {
		printf("Fail to enable port filtering!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_add_port_filtering_rule(void)
{
	int ret;
	char proto[20];
	int port;
	int allow;

	printf("Input protocol, port, allow: ");
	ret = scanf("%19s", proto);
	ret = scanf("%d", &port);
	ret = scanf("%d", &allow);

	ret = tethering_wifi_add_port_filtering_rule(th, port, proto, allow);
	if (__is_err(ret) == true) {
		printf("Fail to add port forwarding rule!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_add_custom_port_filtering_rule(void)
{
	int ret;
	char proto[20];
	int port1, port2;
	int allow;

	printf("Input protocol, port1, port2, allow: ");
	ret = scanf("%19s", proto);
	ret = scanf("%d", &port1);
	ret = scanf("%d", &port2);
	ret = scanf("%d", &allow);

	ret = tethering_wifi_add_custom_port_filtering_rule(th, port1, port2, proto, allow);
	if (__is_err(ret) == true) {
		printf("Fail to add custom port forwarding rule!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_get_port_filtering_rule(void)
{
	int ret = 0;
	void *pf_list = NULL;

	ret = tethering_wifi_get_port_filtering_rule(th, &pf_list);
	if (__is_err(ret) == true) {
		printf("Fail to get port filtering rule!\n");
		return -1;
	}

	__display_list(pf_list);

	return 1;
}

static int test_tethering_wifi_get_custom_port_filtering_rule(void)
{
	int ret = 0;
	void *pf_list = NULL;

	ret = tethering_wifi_get_custom_port_filtering_rule(th, &pf_list);
	if (__is_err(ret) == true) {
		printf("Fail to get port filtering rule!\n");
		return -1;
	}

	__display_list(pf_list);

	return 1;
}

static int test_tethering_wifi_set_vpn_passthrough_rule(void)
{
	int ret = 0;
	int type;

	printf("Select vpn passthrough type (0:IPSEC 1:PPTP 2:L2TP): ");
	ret = scanf("%d", &type);

	ret = tethering_wifi_set_vpn_passthrough_rule(th, (tethering_vpn_passthrough_type_e)type, true);
	if (__is_err(ret) == true) {
		printf("Fail to get port filtering rule!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_push_wps_button(void)
{
	int ret = 0;

	ret = tethering_wifi_push_wps_button(th);
	if (__is_err(ret) == true) {
		printf("Fail to get port filtering rule!\n");
		return -1;
	}

	return 1;
}

static int test_tethering_wifi_set_wps_pin(void)
{
	int ret = 0;
	char wps_pin[128];

	printf("Input WPS PIN: ");
	ret = scanf("%127s", wps_pin);

	ret = tethering_wifi_set_wps_pin(th, wps_pin);
	if (__is_err(ret) == true) {
		printf("Fail to get port filtering rule!\n");
		return -1;
	}

	return 1;
}

int main(int argc, char **argv)
{
	GMainLoop *mainloop;

#if !GLIB_CHECK_VERSION(2, 36, 0)
	g_type_init();
#endif
	mainloop = g_main_loop_new(NULL, false);

	GIOChannel *channel = g_io_channel_unix_new(0);
	g_io_add_watch(channel, (G_IO_IN|G_IO_ERR|G_IO_HUP|G_IO_NVAL), test_thread, NULL);
	printf("Test Thread created...\n");
	g_main_loop_run(mainloop);

	return 0;
}

gboolean test_thread(GIOChannel *source, GIOCondition condition, gpointer data)
{
	int rv;
	char a[10];

	printf("Event received from stdin\n");

	rv = read(0, a, 10);

	if (rv <= 0 || a[0] == '0')
		exit(1);

	if (a[0] == '\n' || a[0] == '\r') {
		printf("\n\n Network Connection API Test App\n\n");
		printf("Options..\n");
		printf("1       - Tethering create and set callbacks\n");
		printf("2       - Tethering destroy\n");
		printf("3       - Enable Tethering\n");
		printf("4       - Disable Tethering\n");
		printf("5       - Get client information\n");
		printf("6       - Get interface information\n");
		printf("7       - Get data usage\n");
		printf("8       - Get Wi-Fi tethering setting\n");
		printf("a       - Set Wi-Fi tethering SSID\n");
		printf("b       - Set Wi-Fi tethering security type\n");
		printf("c       - Set Wi-Fi tethering visibility\n");
		printf("d       - Set Wi-Fi tethering passphrase\n");
		printf("e       - Set Wi-Fi tethering mac filtering\n");
		printf("f       - Add/Remove MAC adress to/from allowed/blocked list\n");
		printf("g       - Get allowed/blocked list\n");
		printf("k       - Reload Wi-Fi tethering\n");
		printf("m       - Set Wi-Fi channel\n");
		printf("n       - Set Wi-Fi hw_mode\n");
		printf("o       - Enable dhcp server\n");
		printf("p       - Enable dhcp server with range\n");
		printf("q       - Is dhcp server enabled?\n");
		printf("r       - Get Wi-Fi txpower\n");
		printf("s       - Set Wi-Fi txpower\n");
		printf("t       - Set Wi-Fi mtu\n");
		printf("u       - Change mac address\n");
		printf("v       - Set max connected device(Wi-Fi tethering)\n");
		printf("w       - Enable port forwarding\n");
		printf("x       - Add port forwarding rule\n");
		printf("y       - Reset port forwarding rule\n");
		printf("z       - Get port forwarding rule\n");
		printf("A       - Enable port filtering\n");
		printf("B       - Add port filtering rule\n");
		printf("C       - Add custom port filtering rule\n");
		printf("D       - Get port filtering rule\n");
		printf("E       - Get custom port filtering rule\n");
		printf("F       - Set vpn passthrough rule\n");
		printf("G       - Push WPS button\n");
		printf("H       - Set WPS PIN\n");
		printf("0       - \n");
		printf("ENTER  - Show options menu.......\n");
	}

	switch (a[0]) {
	case '1':
		rv = test_tethering_create();
		break;
	case '2':
		rv = test_tethering_destroy();
		break;
	case '3':
		rv = test_tethering_enable();
		break;
	case '4':
		rv = test_tethering_disable();
		break;
	case '5':
		rv = test_tethering_get_client_info();
		break;
	case '6':
		rv = test_tethering_get_interface_info();
		break;
	case '7':
		rv = test_tethering_get_data_usage();
		break;
	case '8':
		rv = test_tethering_wifi_get_setting();
		break;
	case 'a':
		rv = test_tethering_wifi_set_ssid();
		break;
	case 'b':
		rv = test_tethering_wifi_set_security_type();
		break;
	case 'c':
		rv = test_tethering_wifi_set_visibility();
		break;
	case 'd':
		rv = test_tethering_wifi_set_passphrase();
		break;
	case 'e':
		rv = test_tethering_wifi_set_mac_filtering();
		break;
	case 'f':
		rv = test_tethering_manage_mac_list();
		break;
	case 'g':
		rv = test_tethering_get_mac_list();
		break;
	case 'k':
		rv = test_tethering_wifi_reload_settings();
		break;
	case 'm':
		rv = test_tethering_wifi_set_channel();
		break;
	case 'n':
		rv = test_tethering_wifi_set_mode();
		break;
	case 'o':
		rv = test_tethering_wifi_enable_dhcp();
		break;
	case 'p':
		rv = test_tethering_wifi_set_dhcp_range();
		break;
	case 'q':
		rv = test_tethering_wifi_is_dhcp_enabled();
		break;
	case 'r':
		rv = test_tethering_wifi_get_txpower();
		break;
	case 's':
		rv = test_tethering_wifi_set_txpower();
		break;
	case 't':
		rv = test_tethering_wifi_set_mtu();
		break;
	case 'u':
		rv = test_tethering_wifi_change_mac();
		break;
	case 'v':
		rv = test_tethering_wifi_set_max_connected_device();
		break;
	case 'w':
		rv = test_tethering_wifi_enable_port_forwarding();
		break;
	case 'x':
		rv = test_tethering_wifi_add_port_forwarding_rule();
		break;
	case 'y':
		rv = test_tethering_wifi_reset_port_forwarding_rule();
		break;
	case 'z':
		rv = test_tethering_wifi_get_port_forwarding_rule();
		break;
	case 'A':
		rv = test_tethering_wifi_enable_port_filtering();
		break;
	case 'B':
		rv = test_tethering_wifi_add_port_filtering_rule();
		break;
	case 'C':
		rv = test_tethering_wifi_add_custom_port_filtering_rule();
		break;
	case 'D':
		rv = test_tethering_wifi_get_port_filtering_rule();
		break;
	case 'E':
		rv = test_tethering_wifi_get_custom_port_filtering_rule();
		break;
	case 'F':
		rv = test_tethering_wifi_set_vpn_passthrough_rule();
		break;
	case 'G':
		rv = test_tethering_wifi_push_wps_button();
		break;
	case 'H':
		rv = test_tethering_wifi_set_wps_pin();
		break;
	}

	if (rv == 1)
		printf("Operation succeeded!\n");
	else
		printf("Operation failed!\n");

	return true;
}
