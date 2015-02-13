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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>

#include <vconf.h>
#include <ss_manager.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "tethering-client-stub.h"
#include "marshal.h"
#include "tethering_private.h"

static void __handle_wifi_tether_on(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_wifi_tether_off(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_usb_tether_on(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_usb_tether_off(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_bt_tether_on(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_bt_tether_off(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_wifi_ap_on(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_wifi_ap_off(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_net_closed(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_no_data_timeout(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_low_battery_mode(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_flight_mode(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_power_save_mode(DBusGProxy *proxy, const char *value_name, gpointer user_data);

static __tethering_sig_t sigs[] = {
	{SIGNAL_NAME_NET_CLOSED, __handle_net_closed},
	{SIGNAL_NAME_WIFI_TETHER_ON, __handle_wifi_tether_on},
	{SIGNAL_NAME_WIFI_TETHER_OFF, __handle_wifi_tether_off},
	{SIGNAL_NAME_USB_TETHER_ON, __handle_usb_tether_on},
	{SIGNAL_NAME_USB_TETHER_OFF, __handle_usb_tether_off},
	{SIGNAL_NAME_BT_TETHER_ON, __handle_bt_tether_on},
	{SIGNAL_NAME_BT_TETHER_OFF, __handle_bt_tether_off},
	{SIGNAL_NAME_WIFI_AP_ON, __handle_wifi_ap_on},
	{SIGNAL_NAME_WIFI_AP_OFF, __handle_wifi_ap_off},
	{SIGNAL_NAME_NO_DATA_TIMEOUT, __handle_no_data_timeout},
	{SIGNAL_NAME_LOW_BATTERY_MODE, __handle_low_battery_mode},
	{SIGNAL_NAME_FLIGHT_MODE, __handle_flight_mode},
	{SIGNAL_NAME_POWER_SAVE_MODE, __handle_power_save_mode},
	{"", NULL}};

static int retry = 0;

static void __send_dbus_signal(DBusConnection *conn, const char *signal_name, const char *arg)
{
	if (conn == NULL || signal_name == NULL)
		return;

	DBusMessage *signal = NULL;

	signal = dbus_message_new_signal(TETHERING_SERVICE_OBJECT_PATH,
			TETHERING_SERVICE_INTERFACE, signal_name);
	if (!signal) {
		ERR("Unable to allocate D-Bus signal\n");
		return;
	}

	if (arg && !dbus_message_append_args(signal, DBUS_TYPE_STRING, &arg,
				DBUS_TYPE_INVALID)) {
		ERR("dbus_message_append_args is failed\n");
		dbus_message_unref(signal);
		return;
	}

	if (dbus_connection_send(conn, signal, NULL) == FALSE)
		ERR("dbus_connection_send is failed\n");
	dbus_message_unref(signal);

	return;
}

static bool __any_tethering_is_enabled(tethering_h tethering)
{
	if (tethering_is_enabled(tethering, TETHERING_TYPE_USB) ||
			tethering_is_enabled(tethering, TETHERING_TYPE_WIFI) ||
			tethering_is_enabled(tethering, TETHERING_TYPE_BT) ||
			tethering_is_enabled(tethering, TETHERING_TYPE_RESERVED))
		return true;

	return false;
}

static tethering_error_e __set_security_type(const tethering_wifi_security_type_e security_type)
{
	if (security_type != TETHERING_WIFI_SECURITY_TYPE_NONE &&
			security_type != TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK) {
		ERR("Invalid param\n");
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	if (vconf_set_int(VCONFKEY_MOBILE_HOTSPOT_SECURITY, security_type) < 0) {
		ERR("vconf_set_int is failed\n");
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	return TETHERING_ERROR_NONE;
}

static tethering_error_e __get_security_type(tethering_wifi_security_type_e *security_type)
{
	if (security_type == NULL) {
		ERR("Invalid param\n");
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	if (vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_SECURITY,
				(int *)security_type) < 0) {
		ERR("vconf_get_int is failed\n");
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	return TETHERING_ERROR_NONE;
}

static bool __get_ssid_from_vconf(const char *path, char *ssid, unsigned int size)
{
	if (path == NULL || ssid == NULL || size == 0)
		return false;

	char *ptr = NULL;
	char *ptr_tmp = NULL;

	ptr = vconf_get_str(path);
	if (ptr == NULL)
		return false;

	if (!g_utf8_validate(ptr, -1, (const char **)&ptr_tmp))
		*ptr_tmp = '\0';

	g_strlcpy(ssid, ptr, size);
	free(ptr);

	return true;
}

static tethering_error_e __set_visible(const bool visible)
{
	if (vconf_set_int(VCONFKEY_MOBILE_HOTSPOT_HIDE, visible ? 0 : 1) < 0) {
		ERR("vconf_set_int is failed\n");
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	return TETHERING_ERROR_NONE;
}

static tethering_error_e __get_visible(bool *visible)
{
	if (visible == NULL) {
		ERR("Invalid param\n");
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	int hide = 0;

	if (vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_HIDE, &hide) < 0) {
		ERR("vconf_get_int is failed\n");
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	if (hide)
		*visible = false;
	else
		*visible = true;

	return TETHERING_ERROR_NONE;
}

static unsigned int __generate_initial_passphrase(char *passphrase, unsigned int size)
{
	if (passphrase == NULL ||
			size == 0 || size < TETHERING_WIFI_KEY_MIN_LEN + 1)
		return 0;

	guint32 rand_int = 0;
	int index = 0;

	for (index = 0; index < TETHERING_WIFI_KEY_MIN_LEN; index++) {
		rand_int = g_random_int_range('a', 'z');
		passphrase[index] = rand_int;
	}
	passphrase[index] = '\0';

	return index;
}

#if 0
static tethering_error_e __set_passphrase(const char *passphrase, const unsigned int size)
{
	if (passphrase == NULL || size == 0)
		return TETHERING_ERROR_INVALID_PARAMETER;

	int ret = -1;

	ret = ssa_put(TETHERING_PASSPHRASE_PATH, passphrase, size, TETHERING_PASSPHRASE_GROUP_ID,NULL);
	if (ret < 0) {
		ERR("ssa_put is failed : %d\n", ret);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	return TETHERING_ERROR_NONE;
}
#endif

static tethering_error_e __get_passphrase(char *passphrase,
		unsigned int passphrase_size, unsigned int *passphrase_len)
{
	if (passphrase == NULL || passphrase_size == 0) {
		ERR("Invalid parameter\n");
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

#if 0
	int ret = 0;
	char *key = NULL;
	char tmp[TETHERING_WIFI_KEY_MAX_LEN + 1] = {0, };

	ret = ssa_get(TETHERING_PASSPHRASE_PATH, &key, TETHERING_PASSPHRASE_GROUP_ID,NULL);

	if (ret < 0) {
		DBG("Create new password\n");
		ret = __generate_initial_passphrase(tmp, sizeof(tmp));

		if (ret == 0) {
			ERR("generate_initial_passphrase failed : %d\n", *passphrase_len);
			return TETHERING_ERROR_OPERATION_FAILED;
		} else {
			*passphrase_len = ret;
			g_strlcpy(passphrase,tmp,(*passphrase_len)+1);

			if (__set_passphrase(passphrase, *passphrase_len) != TETHERING_ERROR_NONE) {
				DBG("set_passphrase is failed : %s, %d",passphrase, *passphrase_len);
				return TETHERING_ERROR_OPERATION_FAILED;
			}
		}
	} else {
		*passphrase_len = ret;
		g_strlcpy(passphrase, key, (*passphrase_len) + 1);
	}

	if (key != NULL)
		g_free(key);
#endif

	return TETHERING_ERROR_NONE;
}

static tethering_error_e __get_error(int agent_error)
{
	tethering_error_e err = TETHERING_ERROR_NONE;

	switch (agent_error) {
	case MOBILE_AP_ERROR_NONE:
		err = TETHERING_ERROR_NONE;
		break;

	case MOBILE_AP_ERROR_RESOURCE:
		err = TETHERING_ERROR_OUT_OF_MEMORY;
		break;

	case MOBILE_AP_ERROR_INTERNAL:
		err = TETHERING_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_INVALID_PARAM:
		err = TETHERING_ERROR_INVALID_PARAMETER;
		break;

	case MOBILE_AP_ERROR_ALREADY_ENABLED:
		err = TETHERING_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_NOT_ENABLED:
		err = TETHERING_ERROR_NOT_ENABLED;
		break;

	case MOBILE_AP_ERROR_NET_OPEN:
		err = TETHERING_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_NET_CLOSE:
		err = TETHERING_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_DHCP:
		err = TETHERING_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_IN_PROGRESS:
		err = TETHERING_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_NOT_PERMITTED:
		err = TETHERING_ERROR_NOT_PERMITTED;
		break;

	case MOBILE_AP_ERROR_PERMISSION_DENIED:
		err = TETHERING_ERROR_PERMISSION_DENIED;
		break;

	default:
		ERR("Not defined error : %d\n", agent_error);
		err = TETHERING_ERROR_OPERATION_FAILED;
		break;
	}

	return err;
}

static void __handle_dhcp(DBusGProxy *proxy, const char *member,
		guint interface, const char *ip, const char *mac,
		const char *name, guint timestamp, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	bool opened = false;
	tethering_type_e type = 0;
	tethering_connection_state_changed_cb ccb = NULL;
	__tethering_client_h client = {0, };
	void *data = NULL;

	if (!g_strcmp0(member, "DhcpConnected")) {
		opened = true;
	} else if (!g_strcmp0(member, "DhcpLeaseDeleted")) {
		opened = false;
	} else {
		ERR("Unknown event [%s]\n", member);
		return;
	}

	if (interface == MOBILE_AP_TYPE_USB)
		type = TETHERING_TYPE_USB;
	else if (interface == MOBILE_AP_TYPE_WIFI)
		type = TETHERING_TYPE_WIFI;
	else if (interface == MOBILE_AP_TYPE_BT)
		type = TETHERING_TYPE_BT;
	else if (interface == MOBILE_AP_TYPE_WIFI_AP) {
		type = TETHERING_TYPE_RESERVED;
	} else {
		ERR("Not supported tethering type [%d]\n", interface);
		return;
	}

	ccb = th->changed_cb[type];
	if (ccb == NULL)
		return;
	data = th->changed_user_data[type];

	client.interface = type;
	g_strlcpy(client.ip, ip, sizeof(client.ip));
	g_strlcpy(client.mac, mac, sizeof(client.mac));
	if (name)
		client.hostname = g_strdup(name);
	client.tm = (time_t)timestamp;

	ccb((tethering_client_h)&client, opened, data);

	g_free(client.hostname);

	DBG("-\n");
	return;
}

static void __handle_net_closed(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = 0;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_NETWORK_CLOSE;

	for (type = TETHERING_TYPE_USB; type <= TETHERING_TYPE_BT; type++) {
		dcb = th->disabled_cb[type];
		if (dcb == NULL)
			continue;
		data = th->disabled_user_data[type];

		dcb(TETHERING_ERROR_NONE, type, code, data);
	}

	return;
}

static void __handle_wifi_tether_on(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = TETHERING_TYPE_WIFI;
	bool is_requested = false;
	tethering_enabled_cb ecb = NULL;
	void *data = NULL;

	ecb = th->enabled_cb[type];
	if (ecb == NULL)
		return;
	data = th->enabled_user_data[type];

	ecb(TETHERING_ERROR_NONE, type, is_requested, data);
}

static void __handle_wifi_tether_off(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = TETHERING_TYPE_WIFI;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_OTHERS;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;

	dcb = th->disabled_cb[type];
	if (dcb == NULL)
		return;
	data = th->disabled_user_data[type];

	if (!g_strcmp0(value_name, SIGNAL_MSG_NOT_AVAIL_INTERFACE))
		code = TETHERING_DISABLED_BY_WIFI_ON;
	else if (!g_strcmp0(value_name, SIGNAL_MSG_TIMEOUT))
		code = TETHERING_DISABLED_BY_TIMEOUT;

	dcb(TETHERING_ERROR_NONE, type, code, data);

	return;
}

static void __handle_usb_tether_on(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = TETHERING_TYPE_USB;
	bool is_requested = false;
	tethering_enabled_cb ecb = NULL;
	void *data = NULL;

	ecb = th->enabled_cb[type];
	if (ecb == NULL)
		return;
	data = th->enabled_user_data[type];

	ecb(TETHERING_ERROR_NONE, type, is_requested, data);
}

static void __handle_usb_tether_off(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = TETHERING_TYPE_USB;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_OTHERS;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;

	dcb = th->disabled_cb[type];
	if (dcb == NULL)
		return;
	data = th->disabled_user_data[type];

	if (!g_strcmp0(value_name, SIGNAL_MSG_NOT_AVAIL_INTERFACE))
		code = TETHERING_DISABLED_BY_USB_DISCONNECTION;

	dcb(TETHERING_ERROR_NONE, type, code, data);

	return;
}

static void __handle_bt_tether_on(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = TETHERING_TYPE_BT;
	bool is_requested = false;
	tethering_enabled_cb ecb = NULL;
	void *data = NULL;

	ecb = th->enabled_cb[type];
	if (ecb == NULL)
		return;
	data = th->enabled_user_data[type];

	ecb(TETHERING_ERROR_NONE, type, is_requested, data);
}

static void __handle_bt_tether_off(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = TETHERING_TYPE_BT;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_OTHERS;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;

	dcb = th->disabled_cb[type];
	if (dcb == NULL)
		return;
	data = th->disabled_user_data[type];

	if (!g_strcmp0(value_name, SIGNAL_MSG_NOT_AVAIL_INTERFACE))
		code = TETHERING_DISABLED_BY_BT_OFF;
	else if (!g_strcmp0(value_name, SIGNAL_MSG_TIMEOUT))
		code = TETHERING_DISABLED_BY_TIMEOUT;

	dcb(TETHERING_ERROR_NONE, type, code, data);

	return;
}

static void __handle_wifi_ap_on(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = TETHERING_TYPE_RESERVED;
	bool is_requested = false;
	tethering_enabled_cb ecb = NULL;
	void *data = NULL;

	ecb = th->enabled_cb[type];
	if (ecb == NULL)
		return;
	data = th->enabled_user_data[type];

	ecb(TETHERING_ERROR_NONE, type, is_requested, data);
}

static void __handle_wifi_ap_off(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = TETHERING_TYPE_RESERVED;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_OTHERS;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;

	dcb = th->disabled_cb[type];
	if (dcb == NULL)
		return;
	data = th->disabled_user_data[type];

	if (!g_strcmp0(value_name, SIGNAL_MSG_NOT_AVAIL_INTERFACE))
		code = TETHERING_DISABLED_BY_WIFI_ON;
	else if (!g_strcmp0(value_name, SIGNAL_MSG_TIMEOUT))
		code = TETHERING_DISABLED_BY_TIMEOUT;

	dcb(TETHERING_ERROR_NONE, type, code, data);

	return;
}

static void __handle_no_data_timeout(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = 0;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_TIMEOUT;

	for (type = TETHERING_TYPE_USB; type <= TETHERING_TYPE_BT; type++) {
		dcb = th->disabled_cb[type];
		if (dcb == NULL)
			continue;
		data = th->disabled_user_data[type];

		dcb(TETHERING_ERROR_NONE, type, code, data);
	}
}

static void __handle_low_battery_mode(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = 0;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_LOW_BATTERY;

	for (type = TETHERING_TYPE_USB; type <= TETHERING_TYPE_RESERVED; type++) {
		dcb = th->disabled_cb[type];
		if (dcb == NULL)
			continue;
		data = th->disabled_user_data[type];

		dcb(TETHERING_ERROR_NONE, type, code, data);
	}
}

static void __handle_flight_mode(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = 0;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_FLIGHT_MODE;

	for (type = TETHERING_TYPE_USB; type <= TETHERING_TYPE_RESERVED; type++) {
		dcb = th->disabled_cb[type];
		if (dcb == NULL)
			continue;
		data = th->disabled_user_data[type];

		dcb(TETHERING_ERROR_NONE, type, code, data);
	}
}

static void __handle_power_save_mode(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = 0;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_POWER_SAVE_MODE;

	for (type = TETHERING_TYPE_WIFI; type <= TETHERING_TYPE_RESERVED; type++) {
		dcb = th->disabled_cb[type];
		if (dcb == NULL)
			continue;
		data = th->disabled_user_data[type];

		dcb(TETHERING_ERROR_NONE, type, code, data);
	}
}

static void __handle_security_type_changed(__tethering_h *th, const char *value_name)
{
	DBG("+\n");

	_retm_if(th == NULL, "parameter(th) is NULL\n");

	tethering_wifi_security_type_changed_cb scb = NULL;
	void *data = NULL;
	tethering_wifi_security_type_e security_type;

	scb = th->security_type_changed_cb;
	if (scb == NULL)
		return;

	data = th->security_type_user_data;
	if (g_strcmp0(value_name, TETHERING_WIFI_SECURITY_TYPE_OPEN_STR) == 0)
		security_type = TETHERING_WIFI_SECURITY_TYPE_NONE;
	else if (g_strcmp0(value_name, TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK_STR) == 0)
		security_type = TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK;
	else {
		SERR("Unknown type : %s\n", value_name);
		return;
	}

	scb(security_type, data);

	return;
}

static void __handle_ssid_visibility_changed(__tethering_h *th, const char *value_name)
{
	DBG("+\n");

	_retm_if(th == NULL, "parameter(th) is NULL\n");

	tethering_wifi_ssid_visibility_changed_cb scb = NULL;
	void *data = NULL;
	bool visible = false;

	scb = th->ssid_visibility_changed_cb;
	if (scb == NULL)
		return;

	data = th->ssid_visibility_user_data;
	if (g_strcmp0(value_name, SIGNAL_MSG_SSID_VISIBLE) == 0)
		visible = true;

	scb(visible, data);

	return;
}

static void __handle_passphrase_changed(__tethering_h *th)
{
	DBG("+\n");

	_retm_if(th == NULL, "parameter(th) is NULL\n");

	tethering_wifi_passphrase_changed_cb pcb = NULL;
	void *data = NULL;

	pcb = th->passphrase_changed_cb;
	if (pcb == NULL)
		return;

	data = th->passphrase_user_data;

	pcb(data);

	return;
}

static DBusHandlerResult __handle_signal_filter(DBusConnection *conn,
		DBusMessage *msg, void *user_data)
{
	if (conn == NULL || msg == NULL || user_data == NULL) {
		ERR("Invalid param\n");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	__tethering_h *th = (__tethering_h *)user_data;
	DBusError error;
	char *arg = NULL;

	if (!g_strcmp0(dbus_bus_get_unique_name(conn), dbus_message_get_sender(msg)))
		return DBUS_HANDLER_RESULT_HANDLED;

	if (dbus_message_is_signal(msg, TETHERING_SERVICE_INTERFACE,
				SIGNAL_NAME_SECURITY_TYPE_CHANGED)) {
		dbus_error_init(&error);
		if (!dbus_message_get_args(msg, &error,
					DBUS_TYPE_STRING, &arg,
					DBUS_TYPE_INVALID)) {
			ERR("Cannot read message, cause: %s\n", error.message);
			dbus_error_free(&error);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		__handle_security_type_changed(th, arg);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, TETHERING_SERVICE_INTERFACE,
				SIGNAL_NAME_SSID_VISIBILITY_CHANGED)) {
		dbus_error_init(&error);
		if (!dbus_message_get_args(msg, &error,
					DBUS_TYPE_STRING, &arg,
					DBUS_TYPE_INVALID)) {
			ERR("Cannot read message, cause: %s\n", error.message);
			dbus_error_free(&error);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		__handle_ssid_visibility_changed(th, arg);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, TETHERING_SERVICE_INTERFACE,
				SIGNAL_NAME_PASSPHRASE_CHANGED)) {

		__handle_passphrase_changed(th);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void __wifi_enabled_cfm_cb(DBusGProxy *remoteobj, guint event, guint info,
		GError *g_error, gpointer user_data)
{
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_enabled_cb ecb = th->enabled_cb[TETHERING_TYPE_WIFI];
	void *data = th->enabled_user_data[TETHERING_TYPE_WIFI];
	tethering_error_e error = __get_error(info);

	if (g_error) {
		ERR("DBus error [%s]\n", g_error->message);
		if (g_error->code == DBUS_GERROR_NO_REPLY &&
				++retry < TETHERING_ERROR_RECOVERY_MAX) {
			g_error_free(g_error);
			tethering_enable((tethering_h)th, TETHERING_TYPE_WIFI);
			return;
		}
		g_error_free(g_error);
		if (g_error->code == DBUS_GERROR_ACCESS_DENIED)
			error = TETHERING_ERROR_PERMISSION_DENIED;
		else
			error = TETHERING_ERROR_OPERATION_FAILED;
	}
	retry = 0;

	dbus_g_proxy_connect_signal(remoteobj, SIGNAL_NAME_WIFI_TETHER_ON,
			G_CALLBACK(__handle_wifi_tether_on),
			(gpointer)th, NULL);

	if (!ecb)
		return;

	ecb(error, TETHERING_TYPE_WIFI, true, data);
	return;
}

static void __bt_enabled_cfm_cb (DBusGProxy *remoteobj, guint event, guint info,
		GError *g_error, gpointer user_data)
{
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_enabled_cb ecb = th->enabled_cb[TETHERING_TYPE_BT];
	void *data = th->enabled_user_data[TETHERING_TYPE_BT];
	tethering_error_e error = __get_error(info);

	if (g_error) {
		ERR("DBus error [%s]\n", g_error->message);
		if (g_error->code == DBUS_GERROR_NO_REPLY &&
				++retry < TETHERING_ERROR_RECOVERY_MAX) {
			g_error_free(g_error);
			tethering_enable((tethering_h)th, TETHERING_TYPE_BT);
			return;
		}
		g_error_free(g_error);
		if (g_error->code == DBUS_GERROR_ACCESS_DENIED)
			error = TETHERING_ERROR_PERMISSION_DENIED;
		else
			error = TETHERING_ERROR_OPERATION_FAILED;
	}
	retry = 0;

	dbus_g_proxy_connect_signal(remoteobj, SIGNAL_NAME_BT_TETHER_ON,
			G_CALLBACK(__handle_bt_tether_on),
			(gpointer)th, NULL);

	if (!ecb)
		return;

	ecb(error, TETHERING_TYPE_BT, true, data);
	return;
}

static void __usb_enabled_cfm_cb (DBusGProxy *remoteobj, guint event, guint info,
		GError *g_error, gpointer user_data)
{
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_enabled_cb ecb = th->enabled_cb[TETHERING_TYPE_USB];
	void *data = th->enabled_user_data[TETHERING_TYPE_USB];
	tethering_error_e error = __get_error(info);

	if (g_error) {
		ERR("DBus error [%s]\n", g_error->message);
		if (g_error->code == DBUS_GERROR_NO_REPLY &&
				++retry < TETHERING_ERROR_RECOVERY_MAX) {
			g_error_free(g_error);
			tethering_enable((tethering_h)th, TETHERING_TYPE_USB);
			return;
		}
		g_error_free(g_error);
		if (g_error->code == DBUS_GERROR_ACCESS_DENIED)
			error = TETHERING_ERROR_PERMISSION_DENIED;
		else
			error = TETHERING_ERROR_OPERATION_FAILED;
	}
	retry = 0;

	dbus_g_proxy_connect_signal(remoteobj, SIGNAL_NAME_USB_TETHER_ON,
			G_CALLBACK(__handle_usb_tether_on),
			(gpointer)th, NULL);

	if (!ecb)
		return;

	ecb(error, TETHERING_TYPE_USB, true, data);
	return;
}

static void __wifi_ap_enabled_cfm_cb (DBusGProxy *remoteobj, guint event, guint info,
		GError *g_error, gpointer user_data)
{
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_enabled_cb ecb = th->enabled_cb[TETHERING_TYPE_RESERVED];
	void *data = th->enabled_user_data[TETHERING_TYPE_RESERVED];
	tethering_error_e error = __get_error(info);

	if (g_error) {
		ERR("DBus error [%s]\n", g_error->message);
		if (g_error->code == DBUS_GERROR_NO_REPLY &&
				++retry < TETHERING_ERROR_RECOVERY_MAX) {
			g_error_free(g_error);
			tethering_enable((tethering_h)th, TETHERING_TYPE_RESERVED);
			return;
		}
		g_error_free(g_error);
		if (g_error->code == DBUS_GERROR_ACCESS_DENIED)
			error = TETHERING_ERROR_PERMISSION_DENIED;
		else
			error = TETHERING_ERROR_OPERATION_FAILED;
	}
	retry = 0;

	dbus_g_proxy_connect_signal(remoteobj, SIGNAL_NAME_WIFI_AP_ON,
			G_CALLBACK(__handle_wifi_ap_on),
			(gpointer)th, NULL);

	if (!ecb)
		return;

	ecb(error, TETHERING_TYPE_RESERVED, true, data);
	return;
}

static void __disabled_cfm_cb(DBusGProxy *remoteobj, guint event, guint info,
		GError *g_error, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	tethering_h tethering = (tethering_h)user_data;
	__tethering_h *th = (__tethering_h *)tethering;

	tethering_type_e type;
	tethering_error_e error = __get_error(info);
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_REQUEST;

	tethering_disabled_cb dcb = NULL;
	void *data = NULL;

	DBG("cfm event : %d info : %d\n", event, info);

	if (g_error) {
		ERR("DBus error [%s]\n", g_error->message);
		g_error_free(g_error);
		return;
	}

	switch (event) {
	case MOBILE_AP_DISABLE_WIFI_TETHERING_CFM:
		dbus_g_proxy_connect_signal(th->client_bus_proxy,
				SIGNAL_NAME_WIFI_TETHER_OFF,
				G_CALLBACK(__handle_wifi_tether_off),
				(gpointer)tethering, NULL);

		type = TETHERING_TYPE_WIFI;
		dcb = th->disabled_cb[type];
		data = th->disabled_user_data[type];
		if (dcb)
			dcb(error, type, code, data);
		break;

	case MOBILE_AP_DISABLE_BT_TETHERING_CFM:
		dbus_g_proxy_connect_signal(th->client_bus_proxy,
				SIGNAL_NAME_BT_TETHER_OFF,
				G_CALLBACK(__handle_bt_tether_off),
				(gpointer)tethering, NULL);

		type = TETHERING_TYPE_BT;
		dcb = th->disabled_cb[type];
		data = th->disabled_user_data[type];
		if (dcb)
			dcb(error, type, code, data);
		break;

	case MOBILE_AP_DISABLE_USB_TETHERING_CFM:
		dbus_g_proxy_connect_signal(th->client_bus_proxy,
				SIGNAL_NAME_USB_TETHER_OFF,
				G_CALLBACK(__handle_usb_tether_off),
				(gpointer)tethering, NULL);

		type = TETHERING_TYPE_USB;
		dcb = th->disabled_cb[type];
		data = th->disabled_user_data[type];
		if (dcb)
			dcb(error, type, code, data);
		break;

	case MOBILE_AP_DISABLE_WIFI_AP_CFM:
		dbus_g_proxy_connect_signal(th->client_bus_proxy,
				SIGNAL_NAME_WIFI_AP_OFF,
				G_CALLBACK(__handle_wifi_ap_off),
				(gpointer)tethering, NULL);

		type = TETHERING_TYPE_RESERVED;
		dcb = th->disabled_cb[type];
		data = th->disabled_user_data[type];
		if (dcb)
			dcb(error, type, code, data);
		break;

	case MOBILE_AP_DISABLE_CFM:
		dbus_g_proxy_connect_signal(th->client_bus_proxy,
				SIGNAL_NAME_USB_TETHER_OFF,
				G_CALLBACK(__handle_usb_tether_off),
				(gpointer)tethering, NULL);
		dbus_g_proxy_connect_signal(th->client_bus_proxy,
				SIGNAL_NAME_WIFI_TETHER_OFF,
				G_CALLBACK(__handle_wifi_tether_off),
				(gpointer)tethering, NULL);
		dbus_g_proxy_connect_signal(th->client_bus_proxy,
				SIGNAL_NAME_BT_TETHER_OFF,
				G_CALLBACK(__handle_bt_tether_off),
				(gpointer)tethering, NULL);

		for (type = TETHERING_TYPE_USB; type <= TETHERING_TYPE_BT; type++) {
			dcb = th->disabled_cb[type];
			if (dcb == NULL)
				continue;
			data = th->disabled_user_data[type];

			dcb(error, type, code, data);
		}
		break;

	default:
		ERR("Invalid event\n");
		return;
	}

	return;
}

static void __get_data_usage_cb(DBusGProxy *remoteobj, guint event,
		guint64 tx_bytes, guint64 rx_bytes,
		GError *error, gpointer user_data)
{
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_error_e tethering_error = TETHERING_ERROR_NONE;

	if (th->data_usage_cb == NULL) {
		ERR("There is no data_usage_cb\n");
		return;
	}

	if (error || event != MOBILE_AP_GET_DATA_PACKET_USAGE_CFM) {
		if (error)  {
			ERR("DBus fail [%s]\n", error->message);
			g_error_free(error);
			if (error->code == DBUS_GERROR_ACCESS_DENIED)
				tethering_error = TETHERING_ERROR_PERMISSION_DENIED;
			else
				tethering_error = TETHERING_ERROR_OPERATION_FAILED;
		}

		th->data_usage_cb(tethering_error,
				0LL, 0LL, th->data_usage_user_data);

		th->data_usage_cb = NULL;
		th->data_usage_user_data = NULL;

		return;
	}

	th->data_usage_cb(TETHERING_ERROR_NONE,
			rx_bytes, tx_bytes, th->data_usage_user_data);

	th->data_usage_cb = NULL;
	th->data_usage_user_data = NULL;

	return;
}

static void __settings_reloaded_cb(DBusGProxy *remoteobj, guint result,
		GError *error, gpointer user_data)
{
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_error_e tethering_error = __get_error(result);

	if (th->settings_reloaded_cb == NULL) {
		DBG("There is no settings_reloaded_cb\n");
		return;
	}

	if (error) {
		ERR("DBus fail [%s]\n", error->message);
		g_error_free(error);
		if (error->code == DBUS_GERROR_ACCESS_DENIED)
			tethering_error = TETHERING_ERROR_PERMISSION_DENIED;
		else
			tethering_error = TETHERING_ERROR_OPERATION_FAILED;
	}

	th->settings_reloaded_cb(tethering_error,
			th->settings_reloaded_user_data);

	th->settings_reloaded_cb = NULL;
	th->settings_reloaded_user_data = NULL;

	return;
}

static void __ap_settings_reloaded_cb(DBusGProxy *remoteobj, guint result,
		GError *error, gpointer user_data)
{
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_error_e tethering_error = __get_error(result);

	if (th->ap_settings_reloaded_cb == NULL) {
		DBG("There is no settings_reloaded_cb\n");
		return;
	}

	if (error) {
		ERR("DBus fail [%s]\n", error->message);
		g_error_free(error);
		if (error->code == DBUS_GERROR_ACCESS_DENIED)
			tethering_error = TETHERING_ERROR_PERMISSION_DENIED;
		else
			tethering_error = TETHERING_ERROR_OPERATION_FAILED;
	}

	th->ap_settings_reloaded_cb(tethering_error,
			th->ap_settings_reloaded_user_data);

	th->ap_settings_reloaded_cb = NULL;
	th->ap_settings_reloaded_user_data = NULL;

	return;
}

static void __ip_forward_cb(DBusGProxy *remoteobj, gint result,
		GError *error, gpointer user_data)
{
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	if (error) {
		ERR("DBus fail [%s]\n", error->message);
		g_error_free(error);
	}

	return;
}

static void __connect_signals(tethering_h tethering)
{
	_retm_if(tethering == NULL, "parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;
	int i = 0;

	for (i = 0; sigs[i].cb != NULL; i++) {
		dbus_g_proxy_add_signal(proxy, sigs[i].name,
				G_TYPE_STRING, G_TYPE_INVALID);
		dbus_g_proxy_connect_signal(proxy, sigs[i].name,
				G_CALLBACK(sigs[i].cb), (gpointer)tethering, NULL);
	}

	dbus_g_object_register_marshaller(marshal_VOID__STRING_UINT_STRING_STRING_STRING_UINT,
			G_TYPE_NONE, G_TYPE_STRING, G_TYPE_UINT, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT, G_TYPE_INVALID);
	dbus_g_proxy_add_signal(proxy, SIGNAL_NAME_DHCP_STATUS,
			G_TYPE_STRING, G_TYPE_UINT, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal(proxy, SIGNAL_NAME_DHCP_STATUS,
			G_CALLBACK(__handle_dhcp), (gpointer)tethering, NULL);

	return;
}

static void __disconnect_signals(tethering_h tethering)
{
	_retm_if(tethering == NULL, "parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;

	int i = 0;

	for (i = 0; sigs[i].cb != NULL; i++) {
		dbus_g_proxy_disconnect_signal(proxy, sigs[i].name,
				G_CALLBACK(sigs[i].cb), (gpointer)tethering);
	}

	dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_DHCP_STATUS,
			G_CALLBACK(__handle_dhcp), (gpointer)tethering);

	return;
}

static bool __get_intf_name(tethering_type_e type, char *buf, unsigned int len)
{
	_retvm_if(buf == NULL, false, "parameter(buf) is NULL\n");

	switch (type) {
	case TETHERING_TYPE_USB:
		g_strlcpy(buf, TETHERING_USB_IF, len);
		break;

	case TETHERING_TYPE_WIFI:
		g_strlcpy(buf, TETHERING_WIFI_IF, len);
		break;

	case TETHERING_TYPE_BT:
		g_strlcpy(buf, TETHERING_BT_IF, len);
		break;

	case TETHERING_TYPE_RESERVED:
		g_strlcpy(buf, TETHERING_WIFI_IF, len);
		break;

	default:
		ERR("Not supported type : %d\n", type);
		return false;
	}

	return true;
}

static bool __get_gateway_addr(tethering_type_e type, char *buf, unsigned int len)
{
	_retvm_if(buf == NULL, false, "parameter(buf) is NULL\n");

	switch (type) {
	case TETHERING_TYPE_USB:
		g_strlcpy(buf, TETHERING_USB_GATEWAY, len);
		break;

	case TETHERING_TYPE_WIFI:
		g_strlcpy(buf, TETHERING_WIFI_GATEWAY, len);
		break;

	case TETHERING_TYPE_BT:
		g_strlcpy(buf, TETHERING_BT_GATEWAY, len);
		break;

	case TETHERING_TYPE_RESERVED:
		g_strlcpy(buf, TETHERING_WIFI_GATEWAY, len);
		break;

	default:
		ERR("Not supported type : %d\n", type);
		return false;
	}

	return true;
}

static int __get_common_ssid(char *ssid, unsigned int size)
{
	if (ssid == NULL)
		return TETHERING_ERROR_INVALID_PARAMETER;

	char *ptr = NULL;
	char *ptr_tmp = NULL;

	ptr = vconf_get_str(VCONFKEY_SETAPPL_DEVICE_NAME_STR);
	if (ptr == NULL)
		return TETHERING_ERROR_OPERATION_FAILED;

	g_strlcpy(ssid, ptr, size);
	free(ptr);

	if (!g_utf8_validate(ssid, -1, (const char **)&ptr_tmp))
		*ptr_tmp = '\0';

	return TETHERING_ERROR_NONE;
}

static int __prepare_wifi_settings(tethering_h tethering, _softap_settings_t *set)
{
	__tethering_h *th = (__tethering_h *)tethering;
	tethering_error_e ret = TETHERING_ERROR_NONE;

	if (th == NULL || set == NULL) {
		ERR("null parameter\n");
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	if (th->ssid == NULL) {
		__get_common_ssid(set->ssid, sizeof(set->ssid));
	} else {
		g_strlcpy(set->ssid, th->ssid, sizeof(set->ssid));
	}

	ret = __get_security_type(&set->sec_type);
	if (ret != TETHERING_ERROR_NONE) {
		set->sec_type = th->sec_type;
	}

	ret = __get_visible(&set->visibility);
	if (ret != TETHERING_ERROR_NONE) {
		set->visibility = th->visibility;
	}

	if (set->sec_type == TETHERING_WIFI_SECURITY_TYPE_NONE) {
		g_strlcpy(set->key, "", sizeof(set->key));
	} else {
		char pass[TETHERING_WIFI_KEY_MAX_LEN + 1] = {0, };
		unsigned int len = 0;

		ret = __get_passphrase(pass, sizeof(pass), &len);
		if (ret != TETHERING_ERROR_NONE) {
			ERR("getting passphrase failed\n");
			return TETHERING_ERROR_OPERATION_FAILED;
		}
		g_strlcpy(set->key, pass, sizeof(set->key));
	}

	return TETHERING_ERROR_NONE;
}

static int __prepare_wifi_ap_settings(tethering_h tethering, _softap_settings_t *set)
{
	__tethering_h *th = (__tethering_h *)tethering;

	if (th == NULL || set == NULL) {
		ERR("null parameter\n");
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	g_strlcpy(set->ssid, th->ap_ssid, sizeof(set->ssid));
	set->sec_type = th->sec_type;
	set->visibility = th->visibility;

	if (set->sec_type == TETHERING_WIFI_SECURITY_TYPE_NONE) {
		g_strlcpy(set->key, "", sizeof(set->key));
	} else {
		g_strlcpy(set->key, th->passphrase, sizeof(set->key));
	}

	return TETHERING_ERROR_NONE;
}

static void __wifi_set_passphrase_cb(DBusGProxy *remoteobj,
		GError *error, gpointer user_data)
{
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	tethering_h tethering = (tethering_h)user_data;
	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;

	if (error) {
		ERR("DBus fail [%s]\n", error->message);
		g_error_free(error);
	}

	dbus_g_proxy_connect_signal(proxy, SIGNAL_NAME_PASSPHRASE_CHANGED,
			G_CALLBACK(__handle_passphrase_changed),
			(gpointer)tethering, NULL);

	return;
}

static bool __check_precondition(tethering_type_e type)
{
	int dnet_state = 0;
	int cellular_state = 0;
	int wifi_state = 0;

	// data network through cellular
	vconf_get_int(VCONFKEY_NETWORK_CELLULAR_STATE, &cellular_state);
	if(cellular_state == VCONFKEY_NETWORK_CELLULAR_ON) {
		ERR("Data Network can be connected later");
		return TRUE;
	}

	vconf_get_int(VCONFKEY_DNET_STATE, &dnet_state);
	if(dnet_state > VCONFKEY_DNET_OFF) {
		ERR("Data Network is connected");
		return TRUE;
	}

	// data network through wifi
	if(type != TETHERING_TYPE_WIFI) {
		vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state);
		if(wifi_state > VCONFKEY_WIFI_UNCONNECTED) {
			ERR("Wi-Fi is connected!");
			return TRUE;
		}
	}

	ERR("Network is not available!");
	return FALSE;
}

/**
 * @internal
 * @brief  Creates the handle of tethering.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks  The @a tethering must be released tethering_destroy() by you.
 * @param[out]  tethering  A handle of a new mobile ap handle on success
 * @return  0 on success, otherwise a negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API is not supported
 * @see  tethering_destroy()
 */
API int tethering_create(tethering_h *tethering)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = NULL;
	GError *error = NULL;
	DBusError dbus_error;
	char ssid[TETHERING_WIFI_SSID_MAX_LEN + 1] = {0, };

	th = (__tethering_h *)malloc(sizeof(__tethering_h));

	_retvm_if(th == NULL, TETHERING_ERROR_OUT_OF_MEMORY,
			"malloc is failed\n");
	memset(th, 0x00, sizeof(__tethering_h));
	th->sec_type = TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK;
	th->visibility = true;

	if (__generate_initial_passphrase(th->passphrase,
			sizeof(th->passphrase)) == 0) {
		ERR("random passphrase generation failed\n");
		free(th);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	if (__get_common_ssid(ssid, sizeof(ssid)) != TETHERING_ERROR_NONE) {
		ERR("common ssid get failed\n");
		free(th);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	th->ap_ssid = g_strdup(ssid);
	if (th->ap_ssid == NULL) {
		ERR("g_strdup failed\n");
		free(th);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

#if !GLIB_CHECK_VERSION(2,36,0)
	g_type_init();
#endif

	th->client_bus = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (error) {
		ERR("Couldn't connect to the System bus[%s]", error->message);
		g_error_free(error);
		g_free(th->ap_ssid);
		free(th);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	th->client_bus_proxy = dbus_g_proxy_new_for_name(th->client_bus,
			TETHERING_SERVICE_NAME,
			TETHERING_SERVICE_OBJECT_PATH,
			TETHERING_SERVICE_INTERFACE);
	if (!th->client_bus_proxy) {
		ERR("Couldn't create the proxy object");
		dbus_g_connection_unref(th->client_bus);
		g_free(th->ap_ssid);
		free(th);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	th->client_bus_connection = dbus_g_connection_get_connection(th->client_bus);

	dbus_error_init(&dbus_error);
	dbus_bus_add_match(th->client_bus_connection,
			TETHERING_SIGNAL_MATCH_RULE, &dbus_error);
	if (dbus_error_is_set(&dbus_error)) {
		ERR("Cannot add D-BUS match rule, cause: %s", dbus_error.message);
		dbus_error_free(&dbus_error);

		g_object_unref(th->client_bus_proxy);
		dbus_g_connection_unref(th->client_bus);
		g_free(th->ap_ssid);
		free(th);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	if (dbus_connection_add_filter(th->client_bus_connection,
				__handle_signal_filter, th, NULL) == FALSE) {
		ERR("Cannot add D-BUS filter\n");

		dbus_bus_remove_match(th->client_bus_connection,
				TETHERING_SIGNAL_MATCH_RULE, NULL);
		g_object_unref(th->client_bus_proxy);
		dbus_g_connection_unref(th->client_bus);
		g_free(th->ap_ssid);
		free(th);
		return TETHERING_ERROR_OPERATION_FAILED;

	}

	__connect_signals((tethering_h)th);

	*tethering = (tethering_h)th;
	DBG("Tethering Handle : 0x%X\n", th);

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief  Destroys the handle of tethering.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @return  0 on success, otherwise a negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_create()
 */
API int tethering_destroy(tethering_h tethering)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	DBG("Tethering Handle : 0x%X\n", th);
	__disconnect_signals(tethering);

	dbus_connection_remove_filter(th->client_bus_connection,
			__handle_signal_filter, th);
	dbus_bus_remove_match(th->client_bus_connection,
			TETHERING_SIGNAL_MATCH_RULE, NULL);

	if (th->ssid)
		free(th->ssid);
	if (th->ap_ssid)
		free(th->ap_ssid);

	g_object_unref(th->client_bus_proxy);
	dbus_g_connection_unref(th->client_bus);
	memset(th, 0x00, sizeof(__tethering_h));
	free(th);

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Enables the tethering, asynchronously.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @post tethering_enabled_cb() will be invoked.
 * @see  tethering_is_enabled()
 * @see  tethering_disable()
 */
API int tethering_enable(tethering_h tethering, tethering_type_e type)
{
	DBG("+\n");

	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	tethering_error_e ret = TETHERING_ERROR_NONE;
	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;

	dbus_g_proxy_set_default_timeout(proxy, DBUS_TIMEOUT_INFINITE);

	if(type != TETHERING_TYPE_RESERVED
		&& __check_precondition(type) == FALSE)
    	return TETHERING_ERROR_OPERATION_FAILED;

	switch (type) {
	case TETHERING_TYPE_USB:
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_USB_TETHER_ON,
				G_CALLBACK(__handle_usb_tether_on),
				(gpointer)tethering);
		org_tizen_tethering_enable_usb_tethering_async(proxy,
				__usb_enabled_cfm_cb, (gpointer)tethering);
		break;

	case TETHERING_TYPE_WIFI: {
		_softap_settings_t set = {"", "", 0, false};

		ret = __prepare_wifi_settings(tethering, &set);
		if (ret != TETHERING_ERROR_NONE) {
			ERR("softap settings initialization failed\n");
			return TETHERING_ERROR_OPERATION_FAILED;
		}

		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_WIFI_TETHER_ON,
				G_CALLBACK(__handle_wifi_tether_on),
				(gpointer)tethering);

		org_tizen_tethering_enable_wifi_tethering_async(proxy,
				set.ssid, set.key, set.visibility, set.sec_type,
				__wifi_enabled_cfm_cb, (gpointer)tethering);
		break;
	}

	case TETHERING_TYPE_BT:
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_BT_TETHER_ON,
				G_CALLBACK(__handle_bt_tether_on),
				(gpointer)tethering);
		org_tizen_tethering_enable_bt_tethering_async(proxy,
				__bt_enabled_cfm_cb, (gpointer)tethering);

		break;

	case TETHERING_TYPE_RESERVED: {
		_softap_settings_t set = {"", "", 0, false};

		ret = __prepare_wifi_ap_settings(tethering, &set);
		if (ret != TETHERING_ERROR_NONE) {
			ERR("softap settings initialization failed\n");
			return TETHERING_ERROR_OPERATION_FAILED;
		}

		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_WIFI_AP_ON,
				G_CALLBACK(__handle_wifi_ap_on),
				(gpointer)tethering);

		org_tizen_tethering_enable_wifi_ap_async(proxy,
				set.ssid, set.key, set.visibility, set.sec_type,
				__wifi_ap_enabled_cfm_cb, (gpointer)tethering);
		break;
	}
	case TETHERING_TYPE_ALL: {
		_softap_settings_t set = {"", "", 0, false};

		ret = __prepare_wifi_settings(tethering, &set);
		if (ret != TETHERING_ERROR_NONE) {
			ERR("softap settings initialization failed\n");
			return TETHERING_ERROR_OPERATION_FAILED;
		}

		/* TETHERING_TYPE_USB */
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_USB_TETHER_ON,
				G_CALLBACK(__handle_usb_tether_on),
				(gpointer)tethering);
		org_tizen_tethering_enable_usb_tethering_async(proxy,
				__usb_enabled_cfm_cb, (gpointer)tethering);

		/* TETHERING_TYPE_WIFI */
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_WIFI_TETHER_ON,
				G_CALLBACK(__handle_wifi_tether_on),
				(gpointer)tethering);

		org_tizen_tethering_enable_wifi_tethering_async(proxy,
				set.ssid, set.key, set.visibility, set.sec_type,
				__wifi_enabled_cfm_cb, (gpointer)tethering);

		/* TETHERING_TYPE_BT */
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_BT_TETHER_ON,
				G_CALLBACK(__handle_bt_tether_on),
				(gpointer)tethering);
		org_tizen_tethering_enable_bt_tethering_async(proxy,
				__bt_enabled_cfm_cb, (gpointer)tethering);
		break;
	}
	default:
		ERR("Unknown type : %d\n", type);

		dbus_g_proxy_set_default_timeout(proxy, DBUS_TIMEOUT_USE_DEFAULT);

		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	dbus_g_proxy_set_default_timeout(proxy, DBUS_TIMEOUT_USE_DEFAULT);

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Disables the tethering, asynchronously.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @post tethering_disabled_cb() will be invoked.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
API int tethering_disable(tethering_h tethering, tethering_type_e type)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;

	switch (type) {
	case TETHERING_TYPE_USB:
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_USB_TETHER_OFF,
				G_CALLBACK(__handle_usb_tether_off),
				(gpointer)tethering);
		org_tizen_tethering_disable_usb_tethering_async(proxy,
				__disabled_cfm_cb, (gpointer)tethering);
		break;

	case TETHERING_TYPE_WIFI:
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_WIFI_TETHER_OFF,
				G_CALLBACK(__handle_wifi_tether_off),
				(gpointer)tethering);
		org_tizen_tethering_disable_wifi_tethering_async(proxy,
				__disabled_cfm_cb, (gpointer)tethering);
		break;

	case TETHERING_TYPE_BT:
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_BT_TETHER_OFF,
				G_CALLBACK(__handle_bt_tether_off),
				(gpointer)tethering);
		org_tizen_tethering_disable_bt_tethering_async(proxy,
				__disabled_cfm_cb, (gpointer)tethering);
		break;

	case TETHERING_TYPE_RESERVED:
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_WIFI_AP_OFF,
				G_CALLBACK(__handle_wifi_ap_off),
				(gpointer)tethering);
		org_tizen_tethering_disable_wifi_ap_async(proxy,
				__disabled_cfm_cb, (gpointer)tethering);
		break;

	case TETHERING_TYPE_ALL:
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_USB_TETHER_OFF,
				G_CALLBACK(__handle_usb_tether_off),
				(gpointer)tethering);
		org_tizen_tethering_disable_usb_tethering_async(proxy,
				__disabled_cfm_cb, (gpointer)tethering);

		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_WIFI_TETHER_OFF,
				G_CALLBACK(__handle_wifi_tether_off),
				(gpointer)tethering);
		org_tizen_tethering_disable_wifi_tethering_async(proxy,
				__disabled_cfm_cb, (gpointer)tethering);

		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_BT_TETHER_OFF,
				G_CALLBACK(__handle_bt_tether_off),
				(gpointer)tethering);
		org_tizen_tethering_disable_bt_tethering_async(proxy,
				__disabled_cfm_cb, (gpointer)tethering);
		break;

	default :
		ERR("Not supported tethering type [%d]\n", type);
		return TETHERING_ERROR_INVALID_PARAMETER;
		break;
	}

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief  Checks whetehr the tethering is enabled or not.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @return  @c true if tethering is enabled, \n @c false if tethering is disabled.
 */
API bool tethering_is_enabled(tethering_h tethering, tethering_type_e type)
{
	int is_on = 0;
	int vconf_type = VCONFKEY_MOBILE_HOTSPOT_MODE_NONE;

	if (vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &is_on) != 0) {
		return FALSE;
	}

	switch (type) {
	case TETHERING_TYPE_USB:
		vconf_type = VCONFKEY_MOBILE_HOTSPOT_MODE_USB;
		break;

	case TETHERING_TYPE_WIFI:
		vconf_type = VCONFKEY_MOBILE_HOTSPOT_MODE_WIFI;
		break;

	case TETHERING_TYPE_BT:
		vconf_type = VCONFKEY_MOBILE_HOTSPOT_MODE_BT;
		break;

	case TETHERING_TYPE_RESERVED:
		vconf_type = VCONFKEY_MOBILE_HOTSPOT_MODE_WIFI_AP;
		break;

	default:
		ERR("Not supported type : %d\n", type);
		break;
	}

	return is_on & vconf_type ? true : false;
}

/**
 * @internal
 * @brief  Gets the MAC address of local device as "FC:A1:3E:D6:B1:B1".
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a mac_address must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[out]  mac_address  The MAC address
 * @return  0 on success, otherwise a negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
API int tethering_get_mac_address(tethering_h tethering, tethering_type_e type, char **mac_address)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(mac_address == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(mac_address) is NULL\n");
	_retvm_if(tethering_is_enabled(tethering, type) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering type[%d] is not enabled\n", type);

	struct ifreq ifr;
	int s = 0;
	char *macbuf = NULL;

	_retvm_if(!__get_intf_name(type, ifr.ifr_name, sizeof(ifr.ifr_name)),
			TETHERING_ERROR_OPERATION_FAILED,
			"getting interface name is failed\n");

	s = socket(AF_INET, SOCK_DGRAM, 0);
	_retvm_if(s < 0, TETHERING_ERROR_OPERATION_FAILED,
			"getting socket is failed\n");
	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
		ERR("getting mac is failed\n");
		close(s);
		return TETHERING_ERROR_OPERATION_FAILED;
	}
	close(s);

	macbuf = (char *)malloc(TETHERING_STR_INFO_LEN);
	_retvm_if(macbuf == NULL, TETHERING_ERROR_OUT_OF_MEMORY,
			"Not enough memory\n");
	snprintf(macbuf, TETHERING_STR_INFO_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
			(unsigned char)ifr.ifr_hwaddr.sa_data[0],
			(unsigned char)ifr.ifr_hwaddr.sa_data[1],
			(unsigned char)ifr.ifr_hwaddr.sa_data[2],
			(unsigned char)ifr.ifr_hwaddr.sa_data[3],
			(unsigned char)ifr.ifr_hwaddr.sa_data[4],
			(unsigned char)ifr.ifr_hwaddr.sa_data[5]);

	*mac_address = macbuf;

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Gets the name of network interface. For example, usb0.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a interface_name must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[out]  interface_name  The name of network interface
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
API int tethering_get_network_interface_name(tethering_h tethering, tethering_type_e type, char **interface_name)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(interface_name == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(interface_name) is NULL\n");
	_retvm_if(tethering_is_enabled(tethering, type) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering type[%d] is not enabled\n", type);

	char intf[TETHERING_STR_INFO_LEN] = {0, };

	_retvm_if(!__get_intf_name(type, intf, sizeof(intf)),
			TETHERING_ERROR_OPERATION_FAILED,
			"getting interface name is failed\n");
	*interface_name = strdup(intf);
	_retvm_if(*interface_name == NULL, TETHERING_ERROR_OUT_OF_MEMORY,
			"Not enough memory\n");

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Gets the local IP address.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a ip_address must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[in]  address_family  The address family of IP address. Currently, #TETHERING_ADDRESS_FAMILY_IPV4 is only supported.
 * @param[out]  ip_address  The local IP address
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
API int tethering_get_ip_address(tethering_h tethering, tethering_type_e type, tethering_address_family_e address_family, char **ip_address)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(ip_address == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(ip_address) is NULL\n");
	_retvm_if(tethering_is_enabled(tethering, type) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering type[%d] is not enabled\n", type);

	struct ifreq ifr;
	int s = 0;
	char *ipbuf = NULL;

	_retvm_if(!__get_intf_name(type, ifr.ifr_name, sizeof(ifr.ifr_name)),
			TETHERING_ERROR_OPERATION_FAILED,
			"getting interface name is failed\n");

	s = socket(AF_INET, SOCK_DGRAM, 0);
	_retvm_if(s < 0, TETHERING_ERROR_OPERATION_FAILED,
			"getting socket is failed\n");
	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		ERR("ioctl is failed\n");
		close(s);
		return TETHERING_ERROR_OPERATION_FAILED;
	}
	close(s);

	ipbuf = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
	*ip_address = strdup(ipbuf);
	_retvm_if(*ip_address == NULL, TETHERING_ERROR_OUT_OF_MEMORY,
			"Not enough memory\n");

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Gets the Gateway address.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a gateway_address must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[in]  address_family  The address family of IP address. Currently, #TETHERING_ADDRESS_FAMILY_IPV4 is only supported.
 * @param[out]  gateway_address  The local IP address
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
API int tethering_get_gateway_address(tethering_h tethering, tethering_type_e type, tethering_address_family_e address_family, char **gateway_address)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(gateway_address == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(gateway_address) is NULL\n");
	_retvm_if(tethering_is_enabled(tethering, type) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering type[%d] is not enabled\n", type);

	char gateway_buf[TETHERING_STR_INFO_LEN] = {0, };

	_retvm_if(!__get_gateway_addr(type, gateway_buf, sizeof(gateway_buf)),
			TETHERING_ERROR_OPERATION_FAILED,
			"getting gateway address is failed\n");

	*gateway_address = strdup(gateway_buf);

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Gets the Subnet Mask.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a subnet_mask must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[in]  address_family  The address family of IP address. Currently, #TETHERING_ADDRESS_FAMILY_IPV4 is only supported.
 * @param[out]  subnet_mask  The local IP address
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
API int tethering_get_subnet_mask(tethering_h tethering, tethering_type_e type, tethering_address_family_e address_family, char **subnet_mask)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(tethering_is_enabled(tethering, type) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering is not enabled\n");
	_retvm_if(subnet_mask == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(subnet_mask) is NULL\n");

	*subnet_mask = strdup(TETHERING_SUBNET_MASK);
	_retvm_if(*subnet_mask == NULL, TETHERING_ERROR_OUT_OF_MEMORY,
			"Not enough memory\n");

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Gets the data usage.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[out]  usage  The data usage
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
API int tethering_get_data_usage(tethering_h tethering, tethering_data_usage_cb callback, void *user_data)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");
	_retvm_if(__any_tethering_is_enabled(tethering) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering is not enabled\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;

	th->data_usage_cb = callback;
	th->data_usage_user_data = user_data;

	org_tizen_tethering_get_data_packet_usage_async(proxy,
			__get_data_usage_cb, (gpointer)th);

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Gets the client which is connected by USB tethering.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @pre  tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
API int tethering_foreach_connected_clients(tethering_h tethering, tethering_type_e type, tethering_connected_client_cb callback, void *user_data)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");
	_retvm_if(__any_tethering_is_enabled(tethering) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering is not enabled\n");

	__tethering_h *th = (__tethering_h *)tethering;
	__tethering_client_h client = {0, };

	guint event = 0;
	GPtrArray *array = NULL;
	GValue value = {0, {{0}}};
	GError *error = NULL;
	int i = 0;
	int no_of_client = 0;
	guint interface = 0;
	gchar *ip = NULL;
	gchar *mac = NULL;
	gchar *hostname = NULL;
	guint timestamp = 0;

	org_tizen_tethering_get_station_info(th->client_bus_proxy, &event,
			&array, &error);
	if (error != NULL) {
		ERR("DBus fail : %s\n", error->message);
		g_error_free(error);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	g_value_init(&value, DBUS_STRUCT_STATIONS);
	no_of_client = array->len;
	for (i = 0; i < no_of_client; i++) {
		g_value_set_boxed(&value, g_ptr_array_index(array, i));

		dbus_g_type_struct_get(&value, 0, &interface, 1, &ip,
				2, &mac, 3, &hostname, 4, &timestamp, G_MAXUINT);

		if (interface == MOBILE_AP_TYPE_USB)
			client.interface = TETHERING_TYPE_USB;
		else if (interface == MOBILE_AP_TYPE_WIFI)
			client.interface = TETHERING_TYPE_WIFI;
		else if (interface == MOBILE_AP_TYPE_BT)
			client.interface = TETHERING_TYPE_BT;
		else if (interface == MOBILE_AP_TYPE_WIFI_AP)
			client.interface = TETHERING_TYPE_RESERVED;

		if (client.interface != type && (TETHERING_TYPE_ALL != type &&
					client.interface != TETHERING_TYPE_RESERVED))
			continue;

		g_strlcpy(client.ip, ip, sizeof(client.ip));
		g_strlcpy(client.mac, mac, sizeof(client.mac));
		if (hostname)
			client.hostname = g_strdup(hostname);
		client.tm = (time_t)timestamp;

		g_free(ip);
		g_free(mac);
		g_free(hostname);

		if (callback((tethering_client_h)&client, user_data) == false) {
			DBG("iteration is stopped\n");
			g_free(client.hostname);
			return TETHERING_ERROR_NONE;
		}
		g_free(client.hostname);
	}

	if (array->len > 0)
		g_ptr_array_free(array, TRUE);

	return TETHERING_ERROR_NONE;
}

/**
 * @brief Set the ip forward status
 * @param[in]  tethering  The handle of tethering
 * @param[in]  status  The ip forward status: (@c true = enable, @c false = disable)
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_get_ip_forward_status()
 */
API int tethering_set_ip_forward_status(tethering_h tethering, bool status)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;

	org_tizen_tethering_set_ip_forward_status_async(proxy, status,
			__ip_forward_cb, (gpointer)tethering);

	return TETHERING_ERROR_NONE;
}

/**
 * @brief Get the ip forward status
 * @param[in]  tethering  The handle of tethering
 * @param[out]  status  The ip forward status: (@c true = enable, @c false = disable)
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_set_ip_forward_status()
 */
API int tethering_get_ip_forward_status(tethering_h tethering, bool *status)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(status == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(status) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;
	GError *error = NULL;
	int forward_mode = 0;

	org_tizen_tethering_get_ip_forward_status(proxy, &forward_mode, &error);
	if (error != NULL) {
		ERR("DBus fail : %s\n", error->message);
		g_error_free(error);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	if (forward_mode == 1)
		*status = true;
	else
		*status = false;

	return TETHERING_ERROR_NONE;
}


/**
 * @internal
 * @brief Registers the callback function called when tethering is enabled.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_unset_enabled_cb()
 */
API int tethering_set_enabled_cb(tethering_h tethering, tethering_type_e type, tethering_enabled_cb callback, void *user_data)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	tethering_type_e ti;

	if (type != TETHERING_TYPE_ALL) {
		th->enabled_cb[type] = callback;
		th->enabled_user_data[type] = user_data;

		return TETHERING_ERROR_NONE;
	}

	/* TETHERING_TYPE_ALL */
	for (ti = TETHERING_TYPE_USB; ti <= TETHERING_TYPE_BT; ti++) {
		th->enabled_cb[ti] = callback;
		th->enabled_user_data[ti] = user_data;
	}

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Unregisters the callback function called when tethering is disabled.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_set_enabled_cb()
 */
API int tethering_unset_enabled_cb(tethering_h tethering, tethering_type_e type)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	tethering_type_e ti;

	if (type != TETHERING_TYPE_ALL) {
		th->enabled_cb[type] = NULL;
		th->enabled_user_data[type] = NULL;

		return TETHERING_ERROR_NONE;
	}

	/* TETHERING_TYPE_ALL */
	for (ti = TETHERING_TYPE_USB; ti <= TETHERING_TYPE_BT; ti++) {
		th->enabled_cb[ti] = NULL;
		th->enabled_user_data[ti] = NULL;
	}

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Registers the callback function called when tethering is disabled.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_unset_disabled_cb()
 */
API int tethering_set_disabled_cb(tethering_h tethering, tethering_type_e type, tethering_disabled_cb callback, void *user_data)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	tethering_type_e ti;

	if (type != TETHERING_TYPE_ALL) {
		th->disabled_cb[type] = callback;
		th->disabled_user_data[type] = user_data;

		return TETHERING_ERROR_NONE;
	}

	/* TETHERING_TYPE_ALL */
	for (ti = TETHERING_TYPE_USB; ti <= TETHERING_TYPE_BT; ti++) {
		th->disabled_cb[ti] = callback;
		th->disabled_user_data[ti] = user_data;
	}

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Unregisters the callback function called when tethering is disabled.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_set_disabled_cb()
 */
API int tethering_unset_disabled_cb(tethering_h tethering, tethering_type_e type)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	tethering_type_e ti;

	if (type != TETHERING_TYPE_ALL) {
		th->disabled_cb[type] = NULL;
		th->disabled_user_data[type] = NULL;

		return TETHERING_ERROR_NONE;
	}

	/* TETHERING_TYPE_ALL */
	for (ti = TETHERING_TYPE_USB; ti <= TETHERING_TYPE_BT; ti++) {
		th->disabled_cb[ti] = NULL;
		th->disabled_user_data[ti] = NULL;
	}

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Registers the callback function called when the state of connection is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_unset_connection_state_changed_cb_cb()
 */
API int tethering_set_connection_state_changed_cb(tethering_h tethering, tethering_type_e type, tethering_connection_state_changed_cb callback, void *user_data)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	tethering_type_e ti;

	if (type != TETHERING_TYPE_ALL) {
		th->changed_cb[type] = callback;
		th->changed_user_data[type] = user_data;

		return TETHERING_ERROR_NONE;
	}

	/* TETHERING_TYPE_ALL */
	for (ti = TETHERING_TYPE_USB; ti <= TETHERING_TYPE_BT; ti++) {
		th->changed_cb[ti] = callback;
		th->changed_user_data[ti] = user_data;
	}

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Unregisters the callback function called when the state of connection is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_set_connection_state_changed_cb()
 */
API int tethering_unset_connection_state_changed_cb(tethering_h tethering, tethering_type_e type)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	tethering_type_e ti;

	if (type != TETHERING_TYPE_ALL) {
		th->changed_cb[type] = NULL;
		th->changed_user_data[type] = NULL;

		return TETHERING_ERROR_NONE;
	}

	/* TETHERING_TYPE_ALL */
	for (ti = TETHERING_TYPE_USB; ti <= TETHERING_TYPE_BT; ti++) {
		th->changed_cb[ti] = NULL;
		th->changed_user_data[ti] = NULL;
	}

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Registers the callback function called when the security type of Wi-Fi tethering is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_unset_security_type_changed_cb()
 */
API int tethering_wifi_set_security_type_changed_cb(tethering_h tethering, tethering_wifi_security_type_changed_cb callback, void *user_data)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	th->security_type_changed_cb = callback;
	th->security_type_user_data = user_data;

	return TETHERING_ERROR_NONE;

}

/**
 * @internal
 * @brief Unregisters the callback function called when the security type of Wi-Fi tethering is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_set_security_type_changed_cb()
 */
API int tethering_wifi_unset_security_type_changed_cb(tethering_h tethering)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	th->security_type_changed_cb = NULL;
	th->security_type_user_data = NULL;

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Registers the callback function called when the visibility of SSID is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_unset_ssid_visibility_changed_cb_cb()
 */
API int tethering_wifi_set_ssid_visibility_changed_cb(tethering_h tethering, tethering_wifi_ssid_visibility_changed_cb callback, void *user_data)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	th->ssid_visibility_changed_cb = callback;
	th->ssid_visibility_user_data = user_data;

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Unregisters the callback function called when the visibility of SSID is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_set_ssid_visibility_changed_cb()
 */
API int tethering_wifi_unset_ssid_visibility_changed_cb(tethering_h tethering)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	th->ssid_visibility_changed_cb = NULL;
	th->ssid_visibility_user_data = NULL;

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Registers the callback function called when the passphrase of Wi-Fi tethering is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_unset_passphrase_changed_cb()
 */
API int tethering_wifi_set_passphrase_changed_cb(tethering_h tethering, tethering_wifi_passphrase_changed_cb callback, void *user_data)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	th->passphrase_changed_cb = callback;
	th->passphrase_user_data = user_data;

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Unregisters the callback function called when the passphrase of Wi-Fi tethering is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_set_passphrase_changed_cb()
 */
API int tethering_wifi_unset_passphrase_changed_cb(tethering_h tethering)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	th->passphrase_changed_cb = NULL;
	th->passphrase_user_data = NULL;

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Sets the security type of Wi-Fi tethering.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks This change is applied next time Wi-Fi tethering is enabled
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The security type
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_get_security_type()
 */
API int tethering_wifi_set_security_type(tethering_h tethering, tethering_wifi_security_type_e type)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	tethering_error_e ret = TETHERING_ERROR_NONE;

	ret = __set_security_type(type);
	if (ret == TETHERING_ERROR_NONE) {
		__send_dbus_signal(th->client_bus_connection,
				SIGNAL_NAME_SECURITY_TYPE_CHANGED,
				type == TETHERING_WIFI_SECURITY_TYPE_NONE ?
				TETHERING_WIFI_SECURITY_TYPE_OPEN_STR :
				TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK_STR);
	}

	return ret;
}

/**
 * @internal
 * @brief Gets the security type of Wi-Fi tethering.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The handle of tethering
 * @param[out]  type  The security type
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_set_security_type()
 */
API int tethering_wifi_get_security_type(tethering_h tethering, tethering_wifi_security_type_e *type)
{
	_retvm_if(type == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(type) is NULL\n");

	return __get_security_type(type);
}

/**
 * @internal
 * @brief Sets the SSID (service set identifier).
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @details If SSID is not set, Device name is used as SSID
 * @remarks This change is applied next time Wi-Fi tethering is enabled with same @a tethering handle
 * @param[in]  tethering  The handle of tethering
 * @param[out]  ssid  The SSID
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 */
API int tethering_wifi_set_ssid(tethering_h tethering, const char *ssid)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(ssid == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(ssid) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	char *p_ssid = NULL;
	int ssid_len = 0;

	ssid_len = strlen(ssid);
	if (ssid_len > TETHERING_WIFI_SSID_MAX_LEN) {
		ERR("parameter(ssid) is too long");
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	p_ssid = strdup(ssid);
	_retvm_if(p_ssid == NULL, TETHERING_ERROR_OUT_OF_MEMORY,
			"strdup is failed\n");

	if (th->ssid)
		free(th->ssid);
	th->ssid = p_ssid;

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Gets the SSID (service set identifier).
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a ssid must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[out]  ssid  The SSID
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 */
API int tethering_wifi_get_ssid(tethering_h tethering, char **ssid)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(ssid == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(ssid) is NULL\n");
	DBG("+\n");

	__tethering_h *th = (__tethering_h *)tethering;
	char val[TETHERING_WIFI_SSID_MAX_LEN + 1] = {0, };

	if (!tethering_is_enabled(NULL, TETHERING_TYPE_WIFI)) {
		if (th->ssid != NULL) {
			DBG("Private SSID is set\n");
			*ssid = strdup(th->ssid);
		} else {
			if (__get_ssid_from_vconf(VCONFKEY_SETAPPL_DEVICE_NAME_STR,
						val, sizeof(val)) == false) {
				return TETHERING_ERROR_OPERATION_FAILED;
			}
			*ssid = strdup(val);
		}
	} else {
		if (__get_ssid_from_vconf(VCONFKEY_MOBILE_HOTSPOT_SSID,
					val, sizeof(val)) == false) {
			return TETHERING_ERROR_OPERATION_FAILED;
		}
		*ssid = strdup(val);
	}

	if (*ssid == NULL) {
		ERR("strdup is failed\n");
		return TETHERING_ERROR_OUT_OF_MEMORY;
	}

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Sets the visibility of SSID(service set identifier).
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @details If you set the visibility invisible, then the SSID of this device is hidden. So, Wi-Fi scan can't find your device.
 * @remarks This change is applied next time Wi-Fi tethering is enabled
 * @param[in]  tethering  The handle of tethering
 * @param[in]  visible  The visibility of SSID: (@c true = visible, @c false = invisible)
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_get_ssid_visibility()
 */
API int tethering_wifi_set_ssid_visibility(tethering_h tethering, bool visible)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	tethering_error_e ret = TETHERING_ERROR_NONE;

	ret = __set_visible(visible);
	if (ret == TETHERING_ERROR_NONE) {
		__send_dbus_signal(th->client_bus_connection,
				SIGNAL_NAME_SSID_VISIBILITY_CHANGED,
				visible ? SIGNAL_MSG_SSID_VISIBLE :
				SIGNAL_MSG_SSID_HIDE);
	}

	return ret;
}

/**
 * @internal
 * @brief Gets the visibility of SSID(service set identifier).
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @details If the visibility is set invisible, then the SSID of this device is hidden. So, Wi-Fi scan can't find your device.
 * @param[in]  tethering  The handle of tethering
 * @param[out]  visible  The visibility of SSID: (@c true = visible, @c false = invisible)
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_set_ssid_visibility()
 */
API int tethering_wifi_get_ssid_visibility(tethering_h tethering, bool *visible)
{
	_retvm_if(visible == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(visible) is NULL\n");

	return __get_visible(visible);
}

/**
 * @internal
 * @brief Sets the passphrase.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks This change is applied next time Wi-Fi tethering is enabled
 * @param[in]  tethering  The handle of tethering
 * @param[in]  passphrase  The passphrase
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_get_passphrase()
 */
API int tethering_wifi_set_passphrase(tethering_h tethering, const char *passphrase)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(passphrase == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(passphrase) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;
	int passphrase_len = 0;

	passphrase_len = strlen(passphrase);
	if (passphrase_len < TETHERING_WIFI_KEY_MIN_LEN ||
			passphrase_len > TETHERING_WIFI_KEY_MAX_LEN) {
		ERR("parameter(passphrase) is too short or long\n");
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_PASSPHRASE_CHANGED,
			G_CALLBACK(__handle_passphrase_changed),
			(gpointer)tethering);

	org_tizen_tethering_set_wifi_tethering_passphrase_async(proxy,
			passphrase, passphrase_len,
			__wifi_set_passphrase_cb, (gpointer)tethering);

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Gets the passphrase.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a passphrase must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[out]  passphrase  The passphrase
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_set_passphrase()
 */
API int tethering_wifi_get_passphrase(tethering_h tethering, char **passphrase)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(passphrase == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(passphrase) is NULL\n");
	DBG("+\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;
	GError *error = NULL;
	char *passphrase_buf = NULL;
	unsigned int len = 0;

	org_tizen_tethering_get_wifi_tethering_passphrase(proxy,
			&passphrase_buf, &len, &error);
	if (error != NULL) {
		ERR("dbus fail : %s\n", error->message);
		g_error_free(error);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	if (passphrase_buf == NULL)
		return TETHERING_ERROR_OPERATION_FAILED;

	*passphrase = strdup(passphrase_buf);
	if (*passphrase == NULL) {
		ERR("Memory allocation failed\n");
		return TETHERING_ERROR_OUT_OF_MEMORY;
	}

	g_free(passphrase_buf);

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Reload the settings (SSID / Passphrase / Security type / SSID visibility).
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks Connected devices via Wi-Fi tethering or MobileAP will be disconnected when the settings are reloaded
 * @param[in]  tethering  The handle of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 */
API int tethering_wifi_reload_settings(tethering_h tethering, tethering_wifi_settings_reloaded_cb callback, void *user_data)

{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	_softap_settings_t set = {"", "", 0, false};
	DBusGProxy *proxy = th->client_bus_proxy;
	int ret = 0;

	DBG("+\n");

	if (th->settings_reloaded_cb) {
		ERR("Operation in progress\n");
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	ret = __prepare_wifi_settings(tethering, &set);
	if (ret != TETHERING_ERROR_NONE) {
		ERR("softap settings initialization failed\n");
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	th->settings_reloaded_cb = callback;
	th->settings_reloaded_user_data = user_data;

	org_tizen_tethering_reload_wifi_settings_async(proxy,
				set.ssid, set.key, set.visibility, set.sec_type,
				__settings_reloaded_cb, (gpointer)tethering);

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Sets the security type of Wi-Fi AP.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @details If security type is not set, WPA2_PSK is used
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The security type
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_ap_get_security_type()
 */
API int tethering_wifi_ap_set_security_type(tethering_h tethering, tethering_wifi_security_type_e type)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
		"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	th->sec_type = type;
	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Gets the security type of Wi-Fi AP.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @details If security type is not set, WPA2_PSK is used
 * @param[in]  tethering  The handle of tethering
 * @param[out]  type  The security type
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_ap_set_security_type()
 */
API int tethering_wifi_ap_get_security_type(tethering_h tethering, tethering_wifi_security_type_e *type)
{
	_retvm_if(type == NULL, TETHERING_ERROR_INVALID_PARAMETER,
		"parameter(type) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	*type = th->sec_type;
	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Sets the SSID (service set identifier) for Wi-Fi AP. The SSID cannot exceed 32 bytes.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @details If SSID is not set, Device name is used as SSID
 * @param[in]  tethering  The handle of tethering
 * @param[in]  ssid  The SSID
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 */
API int tethering_wifi_ap_set_ssid(tethering_h tethering, const char *ssid)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(ssid == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(ssid) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	char *p_ssid = NULL;
	int ssid_len = 0;

	ssid_len = strlen(ssid);
	if (ssid_len > TETHERING_WIFI_SSID_MAX_LEN) {
		ERR("parameter(ssid) is too long");
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	p_ssid = strdup(ssid);
	if (p_ssid == NULL) {
		ERR("strdup failed\n");
		return TETHERING_ERROR_OUT_OF_MEMORY;
	}

	if (th->ap_ssid)
		g_free(th->ap_ssid);
	th->ap_ssid = p_ssid;

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Gets the SSID (service set identifier) for Wi-Fi AP.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @details If SSID is not set, Device name is used as SSID
 * @remarks @a ssid must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[out]  ssid  The SSID
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 */
API int tethering_wifi_ap_get_ssid(tethering_h tethering, char **ssid)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(ssid == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(ssid) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	*ssid = g_strdup(th->ap_ssid);
	if (*ssid == NULL) {
		ERR("strdup failed\n");
		return TETHERING_ERROR_OUT_OF_MEMORY;
	}

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Sets the visibility of SSID(service set identifier) for Wi-Fi AP.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @details If you set the visibility invisible, then the SSID of this device is hidden. So, Wi-Fi scan can't find your device.
 * @details by default visibility is set to true.
 * @remarks This change is applied next time Wi-Fi tethering is enabled
 * @param[in]  tethering  The handle of tethering
 * @param[in]  visible  The visibility of SSID: (@c true = visible, @c false = invisible)
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_ap_get_ssid_visibility()
 */
API int tethering_wifi_ap_set_ssid_visibility(tethering_h tethering, bool visible)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
		"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	th->visibility = visible;
	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Gets the visibility of SSID(service set identifier) for Wi-Fi AP.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @details If the visibility is set invisible, then the SSID of this device is hidden. So, Wi-Fi scan can't find your device.
 * @details by default visibility is set to true.
 * @param[in]  tethering  The handle of tethering
 * @param[out]  visible  The visibility of SSID: (@c true = visible, @c false = invisible)
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_ap_set_ssid_visibility()
 */
API int tethering_wifi_ap_get_ssid_visibility(tethering_h tethering, bool *visible)
{
	_retvm_if(visible == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(visible) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	*visible = th->visibility;
	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Sets the passphrase for Wi-Fi AP.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @details If the passphrase is not set, random string of 8 alphabets will be used.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  passphrase  The passphrase
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_ap_get_passphrase()
 */
API int tethering_wifi_ap_set_passphrase(tethering_h tethering, const char *passphrase)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
		"parameter(tethering) is NULL\n");
	_retvm_if(passphrase == NULL, TETHERING_ERROR_INVALID_PARAMETER,
		"parameter(passphrase) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	int passphrase_len = 0;

	passphrase_len = strlen(passphrase);

	if (passphrase_len < TETHERING_WIFI_KEY_MIN_LEN ||
			passphrase_len > TETHERING_WIFI_KEY_MAX_LEN) {
		ERR("parameter(passphrase) is too short or long\n");
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	if (!g_strcmp0(passphrase, th->passphrase))
		return TETHERING_ERROR_NONE;

	g_strlcpy(th->passphrase, passphrase, sizeof(th->passphrase));
	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Gets the passphrase for Wi-Fi AP.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @details If the passphrase is not set, random string of 8 alphabets will be used.
 * @remarks @a passphrase must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[out]  passphrase  The passphrase
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @see  tethering_wifi_ap_set_passphrase()
 */
API int tethering_wifi_ap_get_passphrase(tethering_h tethering, char **passphrase)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(passphrase == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(passphrase) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	*passphrase = g_strdup(th->passphrase);
	if (*passphrase == NULL) {
		ERR("strdup is failed\n");
		return TETHERING_ERROR_OUT_OF_MEMORY;
	}

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Reload the settings (SSID / Passphrase / Security type / SSID visibility) for Wi-Fi AP.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks Connected devices via MobileAP will be disconnected when the settings are reloaded
 * @param[in]  tethering  The handle of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 */
API int tethering_wifi_ap_reload_settings(tethering_h tethering, tethering_wifi_ap_settings_reloaded_cb callback, void *user_data)

{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	_softap_settings_t set = {"", "", 0, false};
	DBusGProxy *proxy = th->client_bus_proxy;
	int ret = 0;

	DBG("+\n");

	if (th->ap_settings_reloaded_cb) {
		ERR("Operation in progress\n");
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	ret = __prepare_wifi_ap_settings(tethering, &set);
	if (ret != TETHERING_ERROR_NONE) {
		ERR("softap settings initialization failed\n");
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	th->ap_settings_reloaded_cb = callback;
	th->ap_settings_reloaded_user_data = user_data;

	org_tizen_tethering_reload_wifi_ap_settings_async(proxy,
			set.ssid, set.key, set.visibility, set.sec_type,
			__ap_settings_reloaded_cb, (gpointer)tethering);

	return TETHERING_ERROR_NONE;
}
