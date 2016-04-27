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
#include <gio/gio.h>
#include <vconf.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <ckmc/ckmc-manager.h>
#include "tethering_private.h"

#define ALLOWED_LIST	"/etc/hostapd.accept"
#define BLOCKED_LIST	"/etc/hostapd.deny"
#define TEMP_LIST	"/etc/hostapd_tmp"
#define MAC_ADDR_LEN	18
#define MAX_BUF_SIZE	80

static void __handle_wifi_tether_on(GDBusConnection *connection, const gchar *sender_name,
			const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
			GVariant *parameters, gpointer user_data);

static void __handle_wifi_tether_off(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_usb_tether_on(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_usb_tether_off(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_bt_tether_on(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_bt_tether_off(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_net_closed(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_no_data_timeout(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_low_battery_mode(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_flight_mode(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_security_type_changed(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_ssid_visibility_changed(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_passphrase_changed(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static void __handle_dhcp(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data);

static __tethering_sig_t sigs[] = {
	{0, SIGNAL_NAME_NET_CLOSED, __handle_net_closed},
	{0, SIGNAL_NAME_WIFI_TETHER_ON, __handle_wifi_tether_on},
	{0, SIGNAL_NAME_WIFI_TETHER_OFF, __handle_wifi_tether_off},
	{0, SIGNAL_NAME_USB_TETHER_ON, __handle_usb_tether_on},
	{0, SIGNAL_NAME_USB_TETHER_OFF, __handle_usb_tether_off},
	{0, SIGNAL_NAME_BT_TETHER_ON, __handle_bt_tether_on},
	{0, SIGNAL_NAME_BT_TETHER_OFF, __handle_bt_tether_off},
	{0, SIGNAL_NAME_NO_DATA_TIMEOUT, __handle_no_data_timeout},
	{0, SIGNAL_NAME_LOW_BATTERY_MODE, __handle_low_battery_mode},
	{0, SIGNAL_NAME_FLIGHT_MODE, __handle_flight_mode},
	{0, SIGNAL_NAME_SECURITY_TYPE_CHANGED, __handle_security_type_changed},
	{0, SIGNAL_NAME_SSID_VISIBILITY_CHANGED, __handle_ssid_visibility_changed},
	{0, SIGNAL_NAME_PASSPHRASE_CHANGED, __handle_passphrase_changed},
	{0, SIGNAL_NAME_DHCP_STATUS, __handle_dhcp},
	{0, "", NULL} };

static int retry = 0;

static void __send_dbus_signal(GDBusConnection *conn, const char *signal_name, const char *arg)
{
	if (conn == NULL || signal_name == NULL)
		return; //LCOV_EXCL_LINE

	GVariant *message = NULL;
	GError *error = NULL;

	if (arg)
		message = g_variant_new("(s)", arg);

	g_dbus_connection_emit_signal(conn, NULL, TETHERING_SERVICE_OBJECT_PATH,
					TETHERING_SERVICE_INTERFACE, signal_name, message, &error);
	if (error) {
		ERR("g_dbus_connection_emit_signal is failed because  %s\n", error->message); //LCOV_EXCL_LINE
		g_error_free(error); //LCOV_EXCL_LINE
	}
	g_variant_unref(message);
}

static bool __any_tethering_is_enabled(tethering_h tethering)
{
	if (tethering_is_enabled(tethering, TETHERING_TYPE_USB) ||
			tethering_is_enabled(tethering, TETHERING_TYPE_WIFI) ||
			tethering_is_enabled(tethering, TETHERING_TYPE_BT))
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

static tethering_error_e __get_error(int agent_error)
{
	tethering_error_e err = TETHERING_ERROR_NONE;

	switch (agent_error) {
	case MOBILE_AP_ERROR_NONE:
		err = TETHERING_ERROR_NONE;
		break;

	//LCOV_EXCL_START
	case MOBILE_AP_ERROR_RESOURCE:
		err = TETHERING_ERROR_OUT_OF_MEMORY;
		break;
	//LCOV_EXCL_STOP

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

	//LCOV_EXCL_START
	case MOBILE_AP_ERROR_NOT_PERMITTED:
		err = TETHERING_ERROR_NOT_PERMITTED;
		break;

	case MOBILE_AP_ERROR_PERMISSION_DENIED:
		err = TETHERING_ERROR_PERMISSION_DENIED;
		break;
	//LCOV_EXCL_STOP
	default:
		ERR("Not defined error : %d\n", agent_error);
		err = TETHERING_ERROR_OPERATION_FAILED;
		break;
	}

	return err;
}

//LCOV_EXCL_START
static void __handle_dhcp(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	bool opened = false;
	tethering_type_e type = 0;
	mobile_ap_type_e ap_type = 0;
	tethering_connection_state_changed_cb ccb = NULL;
	__tethering_client_h client;
	void *data = NULL;
	char *buf = NULL;
	char *name = NULL;
	char *mac = NULL;
	char *ip = NULL;
	guint timestamp;

	memset(&client, 0, sizeof(__tethering_client_h));
	g_variant_get(parameters, "(susssu)", &buf, &ap_type, &ip, &mac, &name, &timestamp);

	if (!g_strcmp0(buf, "DhcpConnected")) {
		opened = true;
	} else if (!g_strcmp0(buf, "DhcpLeaseDeleted")) {
		opened = false;
	} else {
		ERR("Unknown event [%s]\n", buf);
		goto DONE;
	}

	if (ap_type == MOBILE_AP_TYPE_USB)
		type = TETHERING_TYPE_USB;
	else if (ap_type == MOBILE_AP_TYPE_WIFI)
		type = TETHERING_TYPE_WIFI;
	else if (ap_type == MOBILE_AP_TYPE_BT)
		type = TETHERING_TYPE_BT;
	else {
		ERR("Not supported tethering type [%d]\n", ap_type);
		goto DONE;
	}

	ccb = th->changed_cb[type];
	if (ccb == NULL)
		goto DONE;
	data = th->changed_user_data[type];

	client.interface = type;
	g_strlcpy(client.ip, ip, sizeof(client.ip));
	g_strlcpy(client.mac, mac, sizeof(client.mac));
	if (name != NULL)
		client.hostname = g_strdup(name);
	client.tm = (time_t)timestamp;

	ccb((tethering_client_h)&client, opened, data);
	g_free(client.hostname);
DONE:
	g_free(buf);
	g_free(ip);
	g_free(mac);
	g_free(name);
	DBG("-\n");
}
//LCOV_EXCL_STOP

//LCOV_EXCL_START
static void __handle_net_closed(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data)
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

	DBG("-\n");
}
//LCOV_EXCL_STOP

static void __handle_wifi_tether_on(GDBusConnection *connection, const gchar *sender_name,
			const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
			GVariant *parameters, gpointer user_data)
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
	DBG("-\n");
}

static void __handle_wifi_tether_off(GDBusConnection *connection, const gchar *sender_name,
			const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
			GVariant *parameters, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = TETHERING_TYPE_WIFI;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_OTHERS;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;
	char *buf = NULL;

	dcb = th->disabled_cb[type];
	if (dcb == NULL)
		return;
	data = th->disabled_user_data[type];
	g_variant_get(parameters, "(s)", &buf);
	if (!g_strcmp0(buf, SIGNAL_MSG_NOT_AVAIL_INTERFACE))
		code = TETHERING_DISABLED_BY_WIFI_ON;
	else if (!g_strcmp0(buf, SIGNAL_MSG_TIMEOUT))
		code = TETHERING_DISABLED_BY_TIMEOUT;

	g_free(buf);
	dcb(TETHERING_ERROR_NONE, type, code, data);

	DBG("-\n");
}

//LCOV_EXCL_START
static void __handle_usb_tether_on(GDBusConnection *connection, const gchar *sender_name,
			const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
			GVariant *parameters, gpointer user_data)
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
	DBG("-\n");
}

static void __handle_usb_tether_off(GDBusConnection *connection, const gchar *sender_name,
			const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
			GVariant *parameters, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = TETHERING_TYPE_USB;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_OTHERS;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;
	char *buf = NULL;

	dcb = th->disabled_cb[type];
	if (dcb == NULL)
		return;
	data = th->disabled_user_data[type];

	g_variant_get(parameters, "(s)", &buf);
	if (!g_strcmp0(buf, SIGNAL_MSG_NOT_AVAIL_INTERFACE))
		code = TETHERING_DISABLED_BY_USB_DISCONNECTION;

	dcb(TETHERING_ERROR_NONE, type, code, data);
	g_free(buf);
	DBG("-\n");
}
//LCOV_EXCL_STOP

static void __handle_bt_tether_on(GDBusConnection *connection, const gchar *sender_name,
			const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
			GVariant *parameters, gpointer user_data)
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
	DBG("-\n");
}

static void __handle_bt_tether_off(GDBusConnection *connection, const gchar *sender_name,
			const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
			GVariant *parameters, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = TETHERING_TYPE_BT;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_OTHERS;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;
	char *buf = NULL;

	dcb = th->disabled_cb[type];
	if (dcb == NULL)
		return;
	data = th->disabled_user_data[type];
	g_variant_get(parameters, "(s)", &buf);
	if (!g_strcmp0(buf, SIGNAL_MSG_NOT_AVAIL_INTERFACE))
		code = TETHERING_DISABLED_BY_BT_OFF;
	else if (!g_strcmp0(buf, SIGNAL_MSG_TIMEOUT))
		code = TETHERING_DISABLED_BY_TIMEOUT;

	dcb(TETHERING_ERROR_NONE, type, code, data);

	g_free(buf);
	DBG("-\n");
}

//LCOV_EXCL_START
static void __handle_no_data_timeout(GDBusConnection *connection, const gchar *sender_name,
			const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
			GVariant *parameters, gpointer user_data)
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
	DBG("-\n");
}

static void __handle_low_battery_mode(GDBusConnection *connection, const gchar *sender_name,
			const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
			GVariant *parameters, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = 0;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_LOW_BATTERY;

	for (type = TETHERING_TYPE_USB; type <= TETHERING_TYPE_BT; type++) {
		dcb = th->disabled_cb[type];
		if (dcb == NULL)
			continue;
		data = th->disabled_user_data[type];

		dcb(TETHERING_ERROR_NONE, type, code, data);
	}
	DBG("-\n");
}

static void __handle_flight_mode(GDBusConnection *connection, const gchar *sender_name,
			const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
			GVariant *parameters, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = 0;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_FLIGHT_MODE;

	for (type = TETHERING_TYPE_USB; type <= TETHERING_TYPE_BT; type++) {
		dcb = th->disabled_cb[type];
		if (dcb == NULL)
			continue;
		data = th->disabled_user_data[type];

		dcb(TETHERING_ERROR_NONE, type, code, data);
	}
	DBG("-\n");
}
//LCOV_EXCL_STOP

static void __handle_security_type_changed(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data)

{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");
	__tethering_h *th = (__tethering_h *)user_data;

	tethering_wifi_security_type_changed_cb scb = NULL;
	void *data = NULL;
	tethering_wifi_security_type_e security_type;
	char *buf = NULL;

	scb = th->security_type_changed_cb;
	if (scb == NULL)
		return;

	g_variant_get(parameters, "(s)", &buf);
	data = th->security_type_user_data;
	if (g_strcmp0(buf, TETHERING_WIFI_SECURITY_TYPE_OPEN_STR) == 0)
		security_type = TETHERING_WIFI_SECURITY_TYPE_NONE;
	else if (g_strcmp0(buf, TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK_STR) == 0)
		security_type = TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK;
	else {
		SERR("Unknown type : %s\n", buf);
		g_free(buf);
		return;
	}
	g_free(buf);
	scb(security_type, data);

	return;
}

static void __handle_ssid_visibility_changed(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");
	__tethering_h *th = (__tethering_h *)user_data;

	tethering_wifi_ssid_visibility_changed_cb scb = NULL;
	void *data = NULL;
	bool visible = false;
	char *buf = NULL;

	scb = th->ssid_visibility_changed_cb;
	if (scb == NULL) {
		DBG("-\n");
		return;
	}
	g_variant_get(parameters, "(s)", &buf);
	data = th->ssid_visibility_user_data;
	if (g_strcmp0(buf, SIGNAL_MSG_SSID_VISIBLE) == 0)
		visible = true;

	scb(visible, data);
	g_free(buf);
	DBG("-\n");
}

static void __handle_passphrase_changed(GDBusConnection *connection, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name, const gchar *signal_name,
		GVariant *parameters, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");
	__tethering_h *th = (__tethering_h *)user_data;

	tethering_wifi_passphrase_changed_cb pcb = NULL;
	void *data = NULL;

	pcb = th->passphrase_changed_cb;
	if (pcb == NULL)
		return;

	data = th->passphrase_user_data;

	pcb(data);
	DBG("-\n");
}

static void __wifi_enabled_cfm_cb(GObject *source_object, GAsyncResult *res,
		gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");
	GError *g_error = NULL;
	GVariant *g_var;
	guint info;
	tethering_error_e error;
	__tethering_h *th = (__tethering_h *)user_data;
	tethering_enabled_cb ecb = th->enabled_cb[TETHERING_TYPE_WIFI];
	void *data = th->enabled_user_data[TETHERING_TYPE_WIFI];

	g_var  = g_dbus_proxy_call_finish(th->client_bus_proxy, res, &g_error);
	if (g_error) {
		//LCOV_EXCL_START
		ERR("DBus error [%s]\n", g_error->message);
		if (g_error->code == G_DBUS_ERROR_NO_REPLY &&
				++retry < TETHERING_ERROR_RECOVERY_MAX) {
			g_error_free(g_error);
			tethering_enable((tethering_h)th, TETHERING_TYPE_WIFI);
			return;
		} else if (g_error->code == G_DBUS_ERROR_ACCESS_DENIED)
			error = TETHERING_ERROR_PERMISSION_DENIED;
		else
			error = TETHERING_ERROR_OPERATION_FAILED;
		g_error_free(g_error);
		//LCOV_EXCL_STOP
	} else {
		g_variant_get(g_var, "(u)", &info);
		error = __get_error(info);
	}
	retry = 0;

	sigs[E_SIGNAL_WIFI_TETHER_ON].sig_id = g_dbus_connection_signal_subscribe(th->client_bus,
			NULL, TETHERING_SERVICE_INTERFACE, sigs[E_SIGNAL_WIFI_TETHER_ON].name,
			TETHERING_SERVICE_OBJECT_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
			sigs[E_SIGNAL_WIFI_TETHER_ON].cb, (gpointer)th, NULL);

	if (!ecb) {
		DBG("-\n");
		return;
	}
	ecb(error, TETHERING_TYPE_WIFI, true, data);
	g_variant_unref(g_var);
	DBG("-\n");
}

static void __bt_enabled_cfm_cb(GObject *source_object, GAsyncResult *res,
		gpointer user_data)
{
	DBG("+\n");
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");
	GError *g_error = NULL;
	GVariant *g_var;
	guint info;
	tethering_error_e error;

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_enabled_cb ecb = th->enabled_cb[TETHERING_TYPE_BT];
	void *data = th->enabled_user_data[TETHERING_TYPE_BT];

	g_var  = g_dbus_proxy_call_finish(th->client_bus_proxy, res, &g_error);
	if (g_error) {
		//LCOV_EXCL_START
		ERR("DBus error [%s]\n", g_error->message);
		if (g_error->code == G_DBUS_ERROR_NO_REPLY &&
				++retry < TETHERING_ERROR_RECOVERY_MAX) {
			g_error_free(g_error);
			tethering_enable((tethering_h)th, TETHERING_TYPE_BT);
			DBG("-\n");
			return;
		}
		if (g_error->code == G_DBUS_ERROR_ACCESS_DENIED)
			error = TETHERING_ERROR_PERMISSION_DENIED;
		else
			error = TETHERING_ERROR_OPERATION_FAILED;
		g_error_free(g_error);
		//LCOV_EXCL_STOP
	} else {
		g_variant_get(g_var, "(u)", &info);
		g_variant_unref(g_var);
		error = __get_error(info);
	}
	retry = 0;

	sigs[E_SIGNAL_BT_TETHER_ON].sig_id = g_dbus_connection_signal_subscribe(th->client_bus,
			NULL, TETHERING_SERVICE_INTERFACE, sigs[E_SIGNAL_BT_TETHER_ON].name,
			TETHERING_SERVICE_OBJECT_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
			sigs[E_SIGNAL_BT_TETHER_ON].cb, (gpointer)th, NULL);

	if (!ecb) {
		DBG("-\n");
		return;
	}

	ecb(error, TETHERING_TYPE_BT, true, data);
	DBG("-\n");
}

//LCOV_EXCL_START
static void __usb_enabled_cfm_cb(GObject *source_object, GAsyncResult *res,
					gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");
	__tethering_h *th = (__tethering_h *)user_data;
	GError *g_error = NULL;
	GVariant *g_var;
	guint info;
	tethering_error_e error;
	tethering_enabled_cb ecb = th->enabled_cb[TETHERING_TYPE_USB];
	void *data = th->enabled_user_data[TETHERING_TYPE_USB];

	g_var  = g_dbus_proxy_call_finish(th->client_bus_proxy, res, &g_error);
	if (g_error) {
		ERR("DBus error [%s]\n", g_error->message);
		if (g_error->code == G_DBUS_ERROR_NO_REPLY &&
				++retry < TETHERING_ERROR_RECOVERY_MAX) {
			g_error_free(g_error);
			tethering_enable((tethering_h)th, TETHERING_TYPE_USB);
			DBG("-\n");
			return;
		}
		if (g_error->code == G_DBUS_ERROR_ACCESS_DENIED)
			error = TETHERING_ERROR_PERMISSION_DENIED;
		else
			error = TETHERING_ERROR_OPERATION_FAILED;
		g_error_free(g_error);
	} else {
		g_variant_get(g_var, "(u)", &info);
		g_variant_unref(g_var);
		error = __get_error(info);
	}
	retry = 0;

	sigs[E_SIGNAL_USB_TETHER_ON].sig_id = g_dbus_connection_signal_subscribe(th->client_bus,
			NULL, TETHERING_SERVICE_INTERFACE, sigs[E_SIGNAL_USB_TETHER_ON].name,
			TETHERING_SERVICE_OBJECT_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
			sigs[E_SIGNAL_USB_TETHER_ON].cb, (gpointer)th, NULL);

	if (!ecb) {
		DBG("-\n");
		return;
	}

	ecb(error, TETHERING_TYPE_USB, true, data);
	DBG("-\n");
}
//LCOV_EXCL_STOP

static void __disabled_cfm_cb(GObject *source_object, GAsyncResult *res,
		gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");
	GError *g_error = NULL;
	GVariant *g_var;
	guint info, event_type;
	tethering_error_e error;
	tethering_type_e type;
	tethering_h tethering = (tethering_h)user_data;
	__tethering_h *th = (__tethering_h *)tethering;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_REQUEST;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;

	g_var  = g_dbus_proxy_call_finish(th->client_bus_proxy, res, &g_error);
	if (g_error) {
		//LCOV_EXCL_START
		ERR("DBus error [%s]\n", g_error->message);
		g_error_free(g_error);
		return;
		//LCOV_EXCL_STOP
	}
	g_variant_get(g_var, "(uu)", &event_type, &info);
	DBG("cfm event : %d info : %d\n", event_type, info);
	g_variant_unref(g_var);
	error = __get_error(info);
	DBG("cfm event : %d info : %d\n", event_type, error);
	switch (event_type) {
	case MOBILE_AP_DISABLE_WIFI_TETHERING_CFM:
		sigs[E_SIGNAL_WIFI_TETHER_OFF].sig_id = g_dbus_connection_signal_subscribe(th->client_bus,
				NULL, TETHERING_SERVICE_INTERFACE, sigs[E_SIGNAL_WIFI_TETHER_OFF].name,
				TETHERING_SERVICE_OBJECT_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
				sigs[E_SIGNAL_WIFI_TETHER_OFF].cb, (gpointer)th, NULL);

		type = TETHERING_TYPE_WIFI;
		dcb = th->disabled_cb[type];
		data = th->disabled_user_data[type];
		if (dcb)
			dcb(error, type, code, data);
		break;

	case MOBILE_AP_DISABLE_BT_TETHERING_CFM:
		sigs[E_SIGNAL_BT_TETHER_OFF].sig_id = g_dbus_connection_signal_subscribe(th->client_bus,
				NULL, TETHERING_SERVICE_INTERFACE, sigs[E_SIGNAL_BT_TETHER_OFF].name,
				TETHERING_SERVICE_OBJECT_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
				sigs[E_SIGNAL_BT_TETHER_OFF].cb, (gpointer)th, NULL);

		type = TETHERING_TYPE_BT;
		dcb = th->disabled_cb[type];
		data = th->disabled_user_data[type];
		if (dcb)
			dcb(error, type, code, data);
		break;

	//LCOV_EXCL_START
	case MOBILE_AP_DISABLE_USB_TETHERING_CFM:
		sigs[E_SIGNAL_USB_TETHER_OFF].sig_id = g_dbus_connection_signal_subscribe(th->client_bus,
				NULL, TETHERING_SERVICE_INTERFACE, sigs[E_SIGNAL_USB_TETHER_OFF].name,
				TETHERING_SERVICE_OBJECT_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
				sigs[E_SIGNAL_USB_TETHER_OFF].cb, (gpointer)th, NULL);

		type = TETHERING_TYPE_USB;
		dcb = th->disabled_cb[type];
		data = th->disabled_user_data[type];
		if (dcb)
			dcb(error, type, code, data);
		break;
	//LCOV_EXCL_STOP

	case MOBILE_AP_DISABLE_CFM:

		sigs[E_SIGNAL_WIFI_TETHER_OFF].sig_id = g_dbus_connection_signal_subscribe(th->client_bus,
				NULL, TETHERING_SERVICE_INTERFACE, sigs[E_SIGNAL_WIFI_TETHER_OFF].name,
				TETHERING_SERVICE_OBJECT_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
				sigs[E_SIGNAL_WIFI_TETHER_OFF].cb, (gpointer)th, NULL);
		sigs[E_SIGNAL_BT_TETHER_OFF].sig_id = g_dbus_connection_signal_subscribe(th->client_bus,
				NULL, TETHERING_SERVICE_INTERFACE, sigs[E_SIGNAL_BT_TETHER_OFF].name,
				TETHERING_SERVICE_OBJECT_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
				sigs[E_SIGNAL_BT_TETHER_OFF].cb, (gpointer)th, NULL);
		sigs[E_SIGNAL_USB_TETHER_OFF].sig_id = g_dbus_connection_signal_subscribe(th->client_bus,
				NULL, TETHERING_SERVICE_INTERFACE, sigs[E_SIGNAL_USB_TETHER_OFF].name,
				TETHERING_SERVICE_OBJECT_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
				sigs[E_SIGNAL_USB_TETHER_OFF].cb, (gpointer)th, NULL);

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
		break;
	}
	DBG("-\n");
}

static void __get_data_usage_cb(GObject *source_object, GAsyncResult *res,
				gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	GError *g_error = NULL;
	GVariant *g_var;
	guint event_type;
	guint64 tx_bytes, rx_bytes;
	__tethering_h *th = (__tethering_h *)user_data;
	tethering_error_e tethering_error = TETHERING_ERROR_NONE;
	bool flag = false;

	g_var = g_dbus_proxy_call_finish(th->client_bus_proxy, res, &g_error);
	if (g_error) {
		//LCOV_EXCL_START
		ERR("DBus fail [%s]\n", g_error->message);
		if (g_error->code == G_DBUS_ERROR_ACCESS_DENIED)
			tethering_error = TETHERING_ERROR_PERMISSION_DENIED;
		else
			tethering_error = TETHERING_ERROR_OPERATION_FAILED;

		flag = true;
		//LCOV_EXCL_STOP
	}
	if (th->data_usage_cb == NULL) {
		ERR("There is no data_usage_cb\n");
		return;
	}
	if (flag) {
		th->data_usage_cb(tethering_error, 0LL, 0LL, th->data_usage_user_data);
	} else {
		g_variant_get(g_var, "(utt)", &event_type, &tx_bytes, &rx_bytes);
		th->data_usage_cb(TETHERING_ERROR_NONE,
			rx_bytes, tx_bytes, th->data_usage_user_data);
		g_variant_unref(g_var);
	}
	th->data_usage_cb = NULL;
	th->data_usage_user_data = NULL;

	DBG("-\n");
}

static void __settings_reloaded_cb(GObject *source_object, GAsyncResult *res,
		gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");
	GError *g_error = NULL;
	GVariant *g_var;
	guint info;
	__tethering_h *th = (__tethering_h *)user_data;
	tethering_error_e tethering_error;

	g_var  = g_dbus_proxy_call_finish(th->client_bus_proxy, res, &g_error);
	if (g_error) {
		ERR("DBus fail [%s]\n", g_error->message);
		if (g_error->code == G_DBUS_ERROR_ACCESS_DENIED)
			tethering_error = TETHERING_ERROR_PERMISSION_DENIED;
		else
			tethering_error = TETHERING_ERROR_OPERATION_FAILED;
		g_error_free(g_error);
	}
	if (th->settings_reloaded_cb == NULL) {
		DBG("There is no settings_reloaded_cb\n-\n");
		return;
	}
	g_variant_get(g_var, "(u)", &info);
	tethering_error = __get_error(info);
	g_variant_unref(g_var);

	th->settings_reloaded_cb(tethering_error,
			th->settings_reloaded_user_data);

	th->settings_reloaded_cb = NULL;
	th->settings_reloaded_user_data = NULL;
	DBG("-\n");
}

static void __connect_signals(tethering_h tethering)
{
	DBG("+\n");
	_retm_if(tethering == NULL, "parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	GDBusConnection *connection = th->client_bus;
	int i = 0;

	for (i = E_SIGNAL_NET_CLOSED; i < E_SIGNAL_MAX; i++) {
		sigs[i].sig_id = g_dbus_connection_signal_subscribe(connection,
				NULL, TETHERING_SERVICE_INTERFACE, sigs[i].name,
				TETHERING_SERVICE_OBJECT_PATH, NULL, G_DBUS_SIGNAL_FLAGS_NONE,
				sigs[i].cb, tethering, NULL);
	}
	DBG("-\n");
}

static void __disconnect_signals(tethering_h tethering)
{
	DBG("+\n");

	_retm_if(tethering == NULL, "parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	GDBusConnection *connection = th->client_bus;

	int i = 0;

	for (i = E_SIGNAL_NET_CLOSED; i < E_SIGNAL_MAX; i++)
		g_dbus_connection_signal_unsubscribe(connection, sigs[i].sig_id);
	DBG("-\n");
}



static bool __get_intf_name(tethering_type_e type, char *buf, unsigned int len)
{
	_retvm_if(buf == NULL, false, "parameter(buf) is NULL\n");

	switch (type) {
	//LCOV_EXCL_START
	case TETHERING_TYPE_USB:
		g_strlcpy(buf, TETHERING_USB_IF, len);
		break;
	//LCOV_EXCL_STOP
	case TETHERING_TYPE_WIFI:
		g_strlcpy(buf, TETHERING_WIFI_IF, len);
		break;

	case TETHERING_TYPE_BT:
		g_strlcpy(buf, TETHERING_BT_IF, len);
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

	default:
		ERR("Not supported type : %d\n", type);
		return false;
	}
	return true;
}

static int __get_common_ssid(char *ssid, unsigned int size)
{
	if (ssid == NULL) {
		ERR("ssid is null\n"); //LCOV_EXCL_LINE
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	char *ptr = NULL;
	char *ptr_tmp = NULL;

	ptr = vconf_get_str(VCONFKEY_SETAPPL_DEVICE_NAME_STR);
	if (ptr == NULL) {
		ERR("vconf_get_str is failed and set default ssid");
		g_strlcpy(ssid, TETHERING_DEFAULT_SSID, size);
	} else
		g_strlcpy(ssid, ptr, size);

	free(ptr);

	if (!g_utf8_validate(ssid, -1, (const char **)&ptr_tmp))
		*ptr_tmp = '\0';

	return TETHERING_ERROR_NONE;
}

static bool __get_wifi_mode_type(tethering_wifi_mode_type_e type, char **buf)
{
	_retvm_if(buf == NULL, false, "parameter(buf) is NULL\n");

	switch (type) {
	case TETHERING_WIFI_MODE_TYPE_B:
		*buf = g_strdup("b");
		break;
	case TETHERING_WIFI_MODE_TYPE_G:
		*buf = g_strdup("g");
		break;
	case TETHERING_WIFI_MODE_TYPE_A:
		*buf = g_strdup("a");
		break;
	case TETHERING_WIFI_MODE_TYPE_AD:
		*buf = g_strdup("ad");
		break;
	default:
		ERR("Not supported type : %d\n", type);
		return false;
	}
	return true;
}

static int __prepare_wifi_settings(tethering_h tethering, _softap_settings_t *set)
{
	DBG("+\n");

	__tethering_h *th = (__tethering_h *)tethering;
	tethering_error_e ret = TETHERING_ERROR_NONE;
	char *ptr = NULL;

	if (th == NULL || set == NULL) {
		ERR("null parameter\n-\n");
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	if (th->ssid == NULL)
		__get_common_ssid(set->ssid, sizeof(set->ssid));
	else
		g_strlcpy(set->ssid, th->ssid, sizeof(set->ssid));

	ret = __get_security_type(&set->sec_type);
	if (ret != TETHERING_ERROR_NONE)
		set->sec_type = th->sec_type;

	ret = __get_visible(&set->visibility);
	if (ret != TETHERING_ERROR_NONE)
		set->visibility = th->visibility;

	set->mac_filter = th->mac_filter;
	set->channel = th->channel;

	__get_wifi_mode_type(th->mode_type, &ptr);
	if (ptr == NULL) {
		g_strlcpy(set->mode, "", sizeof(set->mode));
	} else {
		g_strlcpy(set->mode, ptr, sizeof(set->mode));
		free(ptr);
	}

	if (set->sec_type == TETHERING_WIFI_SECURITY_TYPE_NONE) {
		g_strlcpy(set->key, "", sizeof(set->key));
	} else {
		GDBusProxy *proxy = th->client_bus_proxy;
		GVariant *parameters;
		GError *error = NULL;
		char *passphrase = NULL;
		unsigned int len = 0;

		parameters = g_dbus_proxy_call_sync(proxy, "get_wifi_tethering_passphrase",
				NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

		if (error) {
			//LCOV_EXCL_START
			ERR("g_dbus_proxy_call_sync failed because  %s\n", error->message);

			if (error->code == G_DBUS_ERROR_ACCESS_DENIED)
				ret = TETHERING_ERROR_PERMISSION_DENIED;
			else
				ret = TETHERING_ERROR_OPERATION_FAILED;

			g_error_free(error);
			return ret;
			//LCOV_EXCL_STOP
		}

		if (parameters != NULL) {
			g_variant_get(parameters, "(siu)", &passphrase, &len, &ret);
			g_variant_unref(parameters);
		}

		g_strlcpy(set->key, passphrase, sizeof(set->key));
	}
	DBG("-\n");
	return TETHERING_ERROR_NONE;
}

static bool __check_precondition(tethering_type_e type)
{
	int dnet_state = 0;
	int cellular_state = 0;
	int wifi_state = 0;

	/* data network through cellular */
	vconf_get_int(VCONFKEY_NETWORK_CELLULAR_STATE, &cellular_state);
	if (cellular_state == VCONFKEY_NETWORK_CELLULAR_ON) {
		ERR("Data Network can be connected later");
		return TRUE;
	}

	vconf_get_int(VCONFKEY_DNET_STATE, &dnet_state);
	if (dnet_state > VCONFKEY_DNET_OFF) {
		ERR("Data Network is connected");
		return TRUE;
	}

	/* data network through wifi */
	if (type != TETHERING_TYPE_WIFI) {
		vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state);
		if (wifi_state > VCONFKEY_WIFI_UNCONNECTED) {
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
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE);
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	DBG("+\n");

	__tethering_h *th = NULL;
	GError *error = NULL;
	char ssid[TETHERING_WIFI_SSID_MAX_LEN + 1] = {0, };

	th = (__tethering_h *)malloc(sizeof(__tethering_h));

	_retvm_if(th == NULL, TETHERING_ERROR_OUT_OF_MEMORY,
			"malloc is failed\n");
	memset(th, 0x00, sizeof(__tethering_h));
	th->sec_type = TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK;
	th->visibility = true;
	th->mac_filter = false;
	th->channel = 6;
	th->mode_type = TETHERING_WIFI_MODE_TYPE_G;

	if (__generate_initial_passphrase(th->passphrase,
			sizeof(th->passphrase)) == 0) {
		ERR("random passphrase generation failed\n"); //LCOV_EXCL_LINE
		free(th);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	if (__get_common_ssid(ssid, sizeof(ssid)) != TETHERING_ERROR_NONE) {
		ERR("common ssid get failed\n"); //LCOV_EXCL_LINE
		free(th);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

#if !GLIB_CHECK_VERSION(2, 36, 0)
	g_type_init();
#endif
	GCancellable *cancellable = g_cancellable_new();
	th->client_bus = g_bus_get_sync(DBUS_BUS_SYSTEM, cancellable, &error);
	if (error) {
		//LCOV_EXCL_START
		ERR("Couldn't connect to the System bus[%s]", error->message);
		g_error_free(error);
		g_cancellable_cancel(cancellable);
		g_object_unref(cancellable);
		free(th);
		return TETHERING_ERROR_OPERATION_FAILED;
		//LCOV_EXCL_STOP
	}
	th->cancellable = cancellable;

	th->client_bus_proxy = g_dbus_proxy_new_sync(th->client_bus, G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START_AT_CONSTRUCTION,
			NULL, TETHERING_SERVICE_NAME, TETHERING_SERVICE_OBJECT_PATH,
			TETHERING_SERVICE_INTERFACE, th->cancellable, &error);
	if (!th->client_bus_proxy) {
		//LCOV_EXCL_START
		if (error)
			ERR("Couldn't create the proxy object because of %s\n", error->message);
		g_cancellable_cancel(th->cancellable);
		g_object_unref(th->cancellable);
		g_object_unref(th->client_bus);
		free(th);
		return TETHERING_ERROR_OPERATION_FAILED;
		//LCOV_EXCL_STOP
	}

	__connect_signals((tethering_h)th);

	*tethering = (tethering_h)th;
	DBG("Tethering Handle : 0x%X\n", th);
	DBG("-\n");
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
	DBG("+\n");
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE);
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	DBG("Tethering Handle : 0x%X\n", th);
	__disconnect_signals(tethering);

	if (th->ssid)
		free(th->ssid);

	g_object_unref(th->cancellable);
	g_object_unref(th->client_bus_proxy);
	g_object_unref(th->client_bus);
	memset(th, 0x00, sizeof(__tethering_h));
	free(th);

	DBG("-\n");
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
	DBG("+ type :  %d\n", type);
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE);
	if (type == TETHERING_TYPE_USB) CHECK_FEATURE_SUPPORTED(TETHERING_USB_FEATURE);
	else if (type == TETHERING_TYPE_WIFI) CHECK_FEATURE_SUPPORTED(TETHERING_WIFI_FEATURE);
	else if (type == TETHERING_TYPE_BT) CHECK_FEATURE_SUPPORTED(TETHERING_BT_FEATURE);

	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	tethering_error_e ret = TETHERING_ERROR_NONE;
	__tethering_h *th = (__tethering_h *)tethering;
	GDBusProxy *proxy = th->client_bus_proxy;
	GDBusConnection *connection = th->client_bus;

	g_dbus_proxy_set_default_timeout(proxy, DBUS_TIMEOUT_INFINITE);

	if (__check_precondition(type) == FALSE) {
		//LCOV_EXCL_START
		DBG("-\n");
		return TETHERING_ERROR_OPERATION_FAILED;
		//LCOV_EXCL_STOP
	}

	switch (type) {
	//LCOV_EXCL_START
	case TETHERING_TYPE_USB:
		g_dbus_connection_signal_unsubscribe(connection,
				sigs[E_SIGNAL_USB_TETHER_ON].sig_id);

		g_dbus_proxy_call(proxy, "enable_usb_tethering", NULL,
				G_DBUS_CALL_FLAGS_NONE, -1, th->cancellable,
				(GAsyncReadyCallback) __usb_enabled_cfm_cb, (gpointer)tethering);
		break;
	//LCOV_EXCL_STOP

	case TETHERING_TYPE_WIFI: {
		_softap_settings_t set = {"", "", "", 0, false};

		ret = __prepare_wifi_settings(tethering, &set);
		if (ret != TETHERING_ERROR_NONE) {
			ERR("softap settings initialization failed\n");
			DBG("-\n");
			return TETHERING_ERROR_OPERATION_FAILED;
		}
		g_dbus_connection_signal_unsubscribe(connection,
				sigs[E_SIGNAL_WIFI_TETHER_ON].sig_id);

		g_dbus_proxy_call(proxy, "enable_wifi_tethering",
				g_variant_new("(sssiiii)", set.ssid, set.key, set.mode, set.channel, set.visibility, set.mac_filter, set.sec_type),
				G_DBUS_CALL_FLAGS_NONE, -1, th->cancellable,
				(GAsyncReadyCallback) __wifi_enabled_cfm_cb, (gpointer)tethering);
		break;
	}

	case TETHERING_TYPE_BT:
		g_dbus_connection_signal_unsubscribe(connection,
				sigs[E_SIGNAL_BT_TETHER_ON].sig_id);

		g_dbus_proxy_call(proxy, "enable_bt_tethering", NULL,
				G_DBUS_CALL_FLAGS_NONE, -1, th->cancellable,
				(GAsyncReadyCallback) __bt_enabled_cfm_cb, (gpointer)tethering);

		break;

	//LCOV_EXCL_START
	case TETHERING_TYPE_ALL: {
		_softap_settings_t set = {"", "", "", 0, false};

		ret = __prepare_wifi_settings(tethering, &set);
		if (ret != TETHERING_ERROR_NONE) {
			ERR("softap settings initialization failed\n");
			return TETHERING_ERROR_OPERATION_FAILED;
		}

		/* TETHERING_TYPE_USB */
		g_dbus_connection_signal_unsubscribe(connection,
				sigs[E_SIGNAL_USB_TETHER_ON].sig_id);

		g_dbus_proxy_call(proxy, "enable_usb_tethering", NULL,
				G_DBUS_CALL_FLAGS_NONE, -1, th->cancellable,
				(GAsyncReadyCallback) __usb_enabled_cfm_cb, (gpointer)tethering);

		/* TETHERING_TYPE_WIFI */
		g_dbus_connection_signal_unsubscribe(connection,
				sigs[E_SIGNAL_WIFI_TETHER_ON].sig_id);

		g_dbus_proxy_call(proxy, "enable_wifi_tethering",
				g_variant_new("(ssii)", set.ssid, set.key, set.visibility, set.sec_type),
				G_DBUS_CALL_FLAGS_NONE, -1, th->cancellable,
				(GAsyncReadyCallback) __wifi_enabled_cfm_cb, (gpointer)tethering);

		/* TETHERING_TYPE_BT */
		g_dbus_connection_signal_unsubscribe(connection,
				sigs[E_SIGNAL_BT_TETHER_ON].sig_id);

		g_dbus_proxy_call(proxy, "enable_usb_tethering", NULL,
				G_DBUS_CALL_FLAGS_NONE, -1, th->cancellable,
				(GAsyncReadyCallback) __bt_enabled_cfm_cb, (gpointer)tethering);
		break;
		//LCOV_EXCL_STOP
	}
	default:
		ERR("Unknown type : %d\n", type);

		g_dbus_proxy_set_default_timeout(proxy, DBUS_TIMEOUT_USE_DEFAULT);

		DBG("-\n");
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	g_dbus_proxy_set_default_timeout(proxy, DBUS_TIMEOUT_USE_DEFAULT);
	DBG("-\n");
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
	DBG("+ type :  %d\n", type);
	if (type == TETHERING_TYPE_USB) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_USB_FEATURE);
	else if (type == TETHERING_TYPE_WIFI) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	else if (type == TETHERING_TYPE_BT) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_BT_FEATURE);

	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	GDBusProxy *proxy = th->client_bus_proxy;
	GDBusConnection *connection = th->client_bus;

	switch (type) {
	case TETHERING_TYPE_USB:
		g_dbus_connection_signal_unsubscribe(connection,
				sigs[E_SIGNAL_USB_TETHER_OFF].sig_id);

		g_dbus_proxy_call(proxy, "disable_usb_tethering",
				NULL, G_DBUS_CALL_FLAGS_NONE, -1, th->cancellable,
				(GAsyncReadyCallback) __disabled_cfm_cb, (gpointer)tethering);

		break;

	case TETHERING_TYPE_WIFI:

		g_dbus_connection_signal_unsubscribe(connection,
				sigs[E_SIGNAL_WIFI_TETHER_OFF].sig_id);

		g_dbus_proxy_call(proxy, "disable_wifi_tethering",
				NULL, G_DBUS_CALL_FLAGS_NONE, -1, th->cancellable,
				(GAsyncReadyCallback) __disabled_cfm_cb, (gpointer)tethering);
		break;

	case TETHERING_TYPE_BT:

		g_dbus_connection_signal_unsubscribe(connection,
				sigs[E_SIGNAL_BT_TETHER_OFF].sig_id);

		g_dbus_proxy_call(proxy, "disable_bt_tethering",
				NULL, G_DBUS_CALL_FLAGS_NONE, -1, th->cancellable,
				(GAsyncReadyCallback) __disabled_cfm_cb, (gpointer)tethering);
		break;

	case TETHERING_TYPE_ALL:
		g_dbus_connection_signal_unsubscribe(connection,
				sigs[E_SIGNAL_USB_TETHER_OFF].sig_id);

		g_dbus_proxy_call(proxy, "disable_usb_tethering",
				NULL, G_DBUS_CALL_FLAGS_NONE, -1, th->cancellable,
				(GAsyncReadyCallback) __disabled_cfm_cb, (gpointer)tethering);

		g_dbus_connection_signal_unsubscribe(connection,
				sigs[E_SIGNAL_WIFI_TETHER_OFF].sig_id);

		g_dbus_proxy_call(proxy, "disable_wifi_tethering",
				NULL, G_DBUS_CALL_FLAGS_NONE, -1, th->cancellable,
				(GAsyncReadyCallback) __disabled_cfm_cb, (gpointer)tethering);

		g_dbus_connection_signal_unsubscribe(connection,
				sigs[E_SIGNAL_BT_TETHER_OFF].sig_id);

		g_dbus_proxy_call(proxy, "disable_bt_tethering",
				NULL, G_DBUS_CALL_FLAGS_NONE, -1, th->cancellable,
				(GAsyncReadyCallback) __disabled_cfm_cb, (gpointer)tethering);
		break;

	default:
		ERR("Not supported tethering type [%d]\n", type);
		DBG("-\n");
		return TETHERING_ERROR_INVALID_PARAMETER;
	}
	DBG("-\n");
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

	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE);

	if (vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &is_on) != 0)
		return FALSE;

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
	if (type == TETHERING_TYPE_USB) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_USB_FEATURE);
	else if (type == TETHERING_TYPE_WIFI) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	else if (type == TETHERING_TYPE_BT) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_BT_FEATURE);

	_retvm_if(tethering_is_enabled(tethering, type) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering type[%d] is not enabled\n", type);
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(mac_address == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(mac_address) is NULL\n");

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
	if (type == TETHERING_TYPE_USB) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_USB_FEATURE);
	else if (type == TETHERING_TYPE_WIFI) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	else if (type == TETHERING_TYPE_BT) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_BT_FEATURE);

	_retvm_if(tethering_is_enabled(tethering, type) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering type[%d] is not enabled\n", type);
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(interface_name == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(interface_name) is NULL\n");

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

	if (type == TETHERING_TYPE_USB) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_USB_FEATURE);
	else if (type == TETHERING_TYPE_WIFI) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	else if (type == TETHERING_TYPE_BT) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_BT_FEATURE);

	_retvm_if(tethering_is_enabled(tethering, type) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering type[%d] is not enabled\n", type);
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(ip_address == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(ip_address) is NULL\n");

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

	if (type == TETHERING_TYPE_USB) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_USB_FEATURE);
	else if (type == TETHERING_TYPE_WIFI) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	else if (type == TETHERING_TYPE_BT) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_BT_FEATURE);

	_retvm_if(tethering_is_enabled(tethering, type) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering type[%d] is not enabled\n", type);
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(gateway_address == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(gateway_address) is NULL\n");

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
	if (type == TETHERING_TYPE_USB) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_USB_FEATURE);
	else if (type == TETHERING_TYPE_WIFI) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	else if (type == TETHERING_TYPE_BT) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_BT_FEATURE);

	_retvm_if(tethering_is_enabled(tethering, type) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering is not enabled\n");
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
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
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE);

	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");
	_retvm_if(__any_tethering_is_enabled(tethering) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering is not enabled\n");

	__tethering_h *th = (__tethering_h *)tethering;
	GDBusProxy *proxy = th->client_bus_proxy;

	th->data_usage_cb = callback;
	th->data_usage_user_data = user_data;

	g_dbus_proxy_call(proxy, "get_data_packet_usage",
			NULL, G_DBUS_CALL_FLAGS_NONE, -1, th->cancellable,
			(GAsyncReadyCallback) __get_data_usage_cb, (gpointer)tethering);

	return TETHERING_ERROR_NONE;
}

/**
 * @internal
 * @brief Gets the client which is connected by tethering "type".
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
	DBG("+\n");
	if (type == TETHERING_TYPE_USB) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_USB_FEATURE);
	else if (type == TETHERING_TYPE_WIFI) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	else if (type == TETHERING_TYPE_BT) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_BT_FEATURE);

	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");
	_retvm_if(__any_tethering_is_enabled(tethering) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering is not enabled\n");

	mobile_ap_type_e interface;
	__tethering_h *th = (__tethering_h *)tethering;
	__tethering_client_h client = {0, };
	gchar *ip = NULL;
	gchar *mac = NULL;
	gchar *hostname = NULL;
	guint timestamp = 0;
	GError *error = NULL;
	GVariant *result = NULL;
	GVariantIter *outer_iter = NULL;
	GVariantIter *inner_iter = NULL;
	GVariant *station = NULL;
	GVariant *value = NULL;
	gchar *key = NULL;

	result = g_dbus_proxy_call_sync(th->client_bus_proxy, "get_station_info",
			NULL, G_DBUS_CALL_FLAGS_NONE,
			-1, th->cancellable, &error);
	if (error)
		ERR("g_dbus_proxy_call_sync is failed and error is %s\n", error->message);
	g_variant_get(result, "(a(a{sv}))", &outer_iter);
	while (g_variant_iter_loop(outer_iter, "(@a{sv})", &station)) {
		g_variant_get(station, "a{sv}", &inner_iter);
		while (g_variant_iter_loop(inner_iter, "{sv}", &key, &value)) {
			if (g_strcmp0(key, "Type") == 0) {
				interface = g_variant_get_int32(value);
				if (interface == MOBILE_AP_TYPE_USB)
					client.interface = TETHERING_TYPE_USB;
				else if (interface == MOBILE_AP_TYPE_WIFI)
					client.interface = TETHERING_TYPE_WIFI;
				else if (interface == MOBILE_AP_TYPE_BT)
					client.interface = TETHERING_TYPE_BT;
				else {
					ERR("Invalid interface\n");
					g_free(key);
					g_variant_unref(value);
					break;
				}
				DBG("interface is %d\n", client.interface);
				if (client.interface != type && (TETHERING_TYPE_ALL != type)) {
					g_free(key);
					g_variant_unref(value);
					break;
				}
			} else if (g_strcmp0(key, "IP") == 0) {
				g_variant_get(value, "s", &ip);
				SDBG("ip is %s\n", ip);
				g_strlcpy(client.ip, ip, sizeof(client.ip));
			} else if (g_strcmp0(key, "MAC") == 0) {
				g_variant_get(value, "s", &mac);
				SDBG("mac is %s\n", mac);
				g_strlcpy(client.mac, mac, sizeof(client.mac));
			} else if (g_strcmp0(key, "Name") == 0) {
				g_variant_get(value, "s", &hostname);
				SDBG("hsotname is %s\n", hostname);
				if (hostname)
					client.hostname = g_strdup(hostname);
			} else if (g_strcmp0(key, "Time") == 0) {
				timestamp = g_variant_get_int32(value);
				DBG("timestamp is %d\n", timestamp);
				client.tm = (time_t)timestamp;
			} else {
				ERR("Key %s not required\n", key);
			}
		}
		g_free(hostname);
		g_free(ip);
		g_free(mac);
		g_variant_iter_free(inner_iter);
		if (callback((tethering_client_h)&client, user_data) == false) {
			DBG("iteration is stopped\n");
			g_free(client.hostname);
			g_variant_iter_free(outer_iter);
			g_variant_unref(station);
			g_variant_unref(result);
			DBG("-\n");
			return TETHERING_ERROR_OPERATION_FAILED;
		}
		g_free(client.hostname);
	}
	g_variant_iter_free(outer_iter);
	g_variant_unref(station);
	g_variant_unref(result);
	DBG("-\n");
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
	if (type == TETHERING_TYPE_USB) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_USB_FEATURE);
	else if (type == TETHERING_TYPE_WIFI) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	else if (type == TETHERING_TYPE_BT) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_BT_FEATURE);

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
	if (type == TETHERING_TYPE_USB) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_USB_FEATURE);
	else if (type == TETHERING_TYPE_WIFI) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	else if (type == TETHERING_TYPE_BT) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_BT_FEATURE);

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
	if (type == TETHERING_TYPE_USB) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_USB_FEATURE);
	else if (type == TETHERING_TYPE_WIFI) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	else if (type == TETHERING_TYPE_BT) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_BT_FEATURE);

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
	if (type == TETHERING_TYPE_USB) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_USB_FEATURE);
	else if (type == TETHERING_TYPE_WIFI) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	else if (type == TETHERING_TYPE_BT) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_BT_FEATURE);

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
	if (type == TETHERING_TYPE_USB) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_USB_FEATURE);
	else if (type == TETHERING_TYPE_WIFI) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	else if (type == TETHERING_TYPE_BT) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_BT_FEATURE);

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
	if (type == TETHERING_TYPE_USB) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_USB_FEATURE);
	else if (type == TETHERING_TYPE_WIFI) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	else if (type == TETHERING_TYPE_BT) CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_BT_FEATURE);

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
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

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
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

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
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

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
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

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
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

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
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

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
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	tethering_error_e ret = TETHERING_ERROR_NONE;

	ret = __set_security_type(type);
	if (ret == TETHERING_ERROR_NONE) {

		__send_dbus_signal(th->client_bus,
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
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

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
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

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
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

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
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	tethering_error_e ret = TETHERING_ERROR_NONE;

	ret = __set_visible(visible);
	if (ret == TETHERING_ERROR_NONE) {

		__send_dbus_signal(th->client_bus,
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
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

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
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(passphrase == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(passphrase) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	GDBusProxy *proxy = th->client_bus_proxy;
	GVariant *parameters;
	GError *error = NULL;
	int passphrase_len = 0;
	int ret = 0;

	DBG("+");
	passphrase_len = strlen(passphrase);
	if (passphrase_len < TETHERING_WIFI_KEY_MIN_LEN ||
			passphrase_len > TETHERING_WIFI_KEY_MAX_LEN) {
		ERR("parameter(passphrase) is too short or long\n");
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	parameters = g_dbus_proxy_call_sync(proxy, "set_wifi_tethering_passphrase",
			g_variant_new("(s)", passphrase), G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

	if (error) {
		//LCOV_EXCL_START
		ERR("g_dbus_proxy_call_sync failed because  %s\n", error->message);

		if (error->code == G_DBUS_ERROR_ACCESS_DENIED)
			ret = TETHERING_ERROR_PERMISSION_DENIED;
		else
			ret = TETHERING_ERROR_OPERATION_FAILED;

		g_error_free(error);
		return ret;
		//LCOV_EXCL_STOP
	}

	g_variant_get(parameters, "(u)", &ret);
	g_variant_unref(parameters);

	if (ret == TETHERING_ERROR_NONE) {
		__send_dbus_signal(th->client_bus,
				SIGNAL_NAME_PASSPHRASE_CHANGED, NULL);
	}

	DBG("-");
	return ret;
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
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(passphrase == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(passphrase) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	GDBusProxy *proxy = th->client_bus_proxy;
	GVariant *parameters;
	GError *error = NULL;
	unsigned int len = 0;
	tethering_error_e ret = TETHERING_ERROR_NONE;

	parameters = g_dbus_proxy_call_sync(proxy, "get_wifi_tethering_passphrase",
			NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

	if (error) {
		//LCOV_EXCL_START
		ERR("g_dbus_proxy_call_sync failed because  %s\n", error->message);

		if (error->code == G_DBUS_ERROR_ACCESS_DENIED)
			ret = TETHERING_ERROR_PERMISSION_DENIED;
		else
			ret = TETHERING_ERROR_OPERATION_FAILED;

		g_error_free(error);
		return ret;
		//LCOV_EXCL_STOP
	}

	if (parameters != NULL) {
		g_variant_get(parameters, "(siu)", passphrase, &len, &ret);
		g_variant_unref(parameters);
	}

	return TETHERING_ERROR_NONE;
}

API int tethering_wifi_set_channel(tethering_h tethering, int channel)
{
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	th->channel = channel;

	return TETHERING_ERROR_NONE;
}

API int tethering_wifi_get_channel(tethering_h tethering, int *channel)
{
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	_retvm_if(channel == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(channel) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	*channel = th->channel;

	return TETHERING_ERROR_NONE;
}

API int tethering_wifi_set_mode(tethering_h tethering, tethering_wifi_mode_type_e type)
{
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	th->mode_type = type;

	return TETHERING_ERROR_NONE;
}

API int tethering_wifi_get_mode(tethering_h tethering, tethering_wifi_mode_type_e *type)
{
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(type == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(type) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	*type = th->mode_type;

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
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	_softap_settings_t set = {"", "", "", 0, false};
	GDBusProxy *proxy = th->client_bus_proxy;
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

	g_dbus_proxy_call(proxy, "reload_wifi_settings",
			g_variant_new("(sssiiii)", set.ssid, set.key, set.mode, set.channel, set.visibility, set.mac_filter, set.sec_type),
			G_DBUS_CALL_FLAGS_NONE, -1, th->cancellable,
			(GAsyncReadyCallback) __settings_reloaded_cb, (gpointer)tethering);

	return TETHERING_ERROR_NONE;
}

API int tethering_wifi_set_mac_filter(tethering_h tethering, bool mac_filter)
{
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	th->mac_filter = mac_filter;

	return TETHERING_ERROR_NONE;
}

API int tethering_wifi_get_mac_filter(tethering_h tethering, bool *mac_filter)
{
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(mac_filter) is NULL\n");
	_retvm_if(mac_filter == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(mac_filter) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	*mac_filter = th->mac_filter;

	return TETHERING_ERROR_NONE;
}

static int __add_mac_to_file(const char *filepath, const char *mac)
{
	FILE *fp = NULL;
	char line[MAX_BUF_SIZE] = "\0";
	bool mac_exist = false;

	fp = fopen(filepath, "a+");
	if (!fp) {
		ERR("fopen is failed\n");
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	while (fgets(line, MAX_BUF_SIZE, fp) != NULL) {
		if (strncmp(mac, line, 17) == 0) {
			DBG("MAC %s already exist in the list\n", mac);
			mac_exist = true;
			break;
		}
	}

	if (!mac_exist)
		fprintf(fp, "%s\n", mac);

	fclose(fp);

	return TETHERING_ERROR_NONE;
}

static int __remove_mac_from_file(const char *filepath, const char *mac)
{
	FILE *fp = NULL;
	FILE *fp1 = NULL;
	char line[MAX_BUF_SIZE] = "\0";

	fp = fopen(filepath, "r");
	if (!fp) {
		ERR("fopen is failed\n");
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	fp1 = fopen(TEMP_LIST, "w+");
	if (!fp1) {
		fclose(fp);
		ERR("fopen is failed\n");
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	while (fgets(line, MAX_BUF_SIZE, fp) != NULL) {
		if (strncmp(mac, line, 17) == 0)
			DBG("MAC %s found in the list\n", mac);
		else
			fprintf(fp1, "%s", line);
	}

	fclose(fp);
	fclose(fp1);

	if ((strcmp(filepath, ALLOWED_LIST) == 0))
		rename(TEMP_LIST, ALLOWED_LIST);
	else if ((strcmp(filepath, BLOCKED_LIST) == 0))
		rename(TEMP_LIST, BLOCKED_LIST);

	return TETHERING_ERROR_NONE;
}

API int tethering_wifi_add_allowed_mac_list(tethering_h tethering, const char *mac)
{
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(mac == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(mac) is NULL\n");

	return __add_mac_to_file(ALLOWED_LIST, mac);
}

API int tethering_wifi_remove_allowed_mac_list(tethering_h tethering, const char *mac)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(mac == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(mac) is NULL\n");

	return __remove_mac_from_file(ALLOWED_LIST, mac);
}

API int tethering_wifi_add_blocked_mac_list(tethering_h tethering, const char *mac)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(mac == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(mac) is NULL\n");

	return __add_mac_to_file(BLOCKED_LIST, mac);
}

API int tethering_wifi_remove_blocked_mac_list(tethering_h tethering, const char *mac)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(mac == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(mac) is NULL\n");

	return __remove_mac_from_file(BLOCKED_LIST, mac);
}

API int tethering_wifi_enable_dhcp(tethering_h tethering, bool enable)
{
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	GVariant *parameters;
	GError *error = NULL;
	guint result;

	__tethering_h *th = (__tethering_h *)tethering;

	GDBusProxy *proxy = th->client_bus_proxy;

	parameters = g_dbus_proxy_call_sync(proxy, "enable_dhcp",
			g_variant_new("(b)", enable),
			G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);

	if (error) {
		ERR("g_dbus_proxy_call_sync failed because  %s\n", error->message);
		if (error->code == G_DBUS_ERROR_ACCESS_DENIED)
			result = TETHERING_ERROR_PERMISSION_DENIED;
		else
			result = TETHERING_ERROR_OPERATION_FAILED;

		g_error_free(error);
		th->dhcp_enabled = false;

		return result;
	}

	g_variant_get(parameters, "(u)", &result);
	g_variant_unref(parameters);

	if (enable)
		th->dhcp_enabled = true;
	else
		th->dhcp_enabled = false;

	return TETHERING_ERROR_NONE;
}

API int tethering_wifi_set_dhcp_range(tethering_h tethering, char *rangestart, char *rangestop)
{
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);

	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(rangestart == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(rangestart) is NULL\n");
	_retvm_if(rangestop == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(rangestop) is NULL\n");

	GVariant *parameters;
	GError *error = NULL;
	guint result;

	__tethering_h *th = (__tethering_h *)tethering;

	GDBusProxy *proxy = th->client_bus_proxy;

	parameters = g_dbus_proxy_call_sync(proxy, "dhcp_range",
			g_variant_new("(ss)", rangestart, rangestop),
			G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (error) {
		ERR("g_dbus_proxy_call_sync failed because  %s\n", error->message);

		if (error->code == G_DBUS_ERROR_ACCESS_DENIED)
			result = TETHERING_ERROR_PERMISSION_DENIED;
		else
			result = TETHERING_ERROR_OPERATION_FAILED;

		g_error_free(error);
		th->dhcp_enabled = false;

		return result;
	}

	g_variant_get(parameters, "(u)", &result);
	g_variant_unref(parameters);

	th->dhcp_enabled = true;

	return TETHERING_ERROR_NONE;
}

API int tethering_wifi_is_dhcp_enabled(tethering_h tethering, bool *dhcp_enabled)
{
	CHECK_FEATURE_SUPPORTED(TETHERING_FEATURE, TETHERING_WIFI_FEATURE);
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(dhcp_enabled == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(dhcp_enabled) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	*dhcp_enabled = th->dhcp_enabled;

	return TETHERING_ERROR_NONE;
}
