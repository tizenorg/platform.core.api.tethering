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

#include <stdlib.h>
#include <string.h>
#include <system_info.h>
#include "tethering_private.h"

static __thread bool is_feature_checked[TETHERING_SUPPORTED_FEATURE_MAX] = {0, };
static __thread bool feature_supported[TETHERING_SUPPORTED_FEATURE_MAX] = {0, };

bool __check_feature_supported(const char *key, tethering_supported_feature_e feature)
{
	if (!is_feature_checked[feature]) {
		if (system_info_get_platform_bool(key, &feature_supported[feature]) < 0) {
			ERR("Get feature is failed");
			return false;
		}

		feature_supported[feature] = true;
	}
	return feature_supported[feature];
}

int _tethering_check_feature_supported(const char* feature, ...)
{
	va_list list;
	const char *key;
	bool value = false;
	bool supported = false;

	va_start(list, feature);
	key = feature;
	while (1) {
		if ((strcmp(key, TETHERING_FEATURE) == 0))
			value = __check_feature_supported(key, TETHERING_SUPPORTED_FEATURE);
		if ((strcmp(key, TETHERING_WIFI_FEATURE) == 0))
			value = __check_feature_supported(key, TETHERING_SUPPORTED_FEATURE);
		if ((strcmp(key, TETHERING_BT_FEATURE) == 0))
			value = __check_feature_supported(key, TETHERING_SUPPORTED_FEATURE);
		if ((strcmp(key, TETHERING_USB_FEATURE) == 0))
			value = __check_feature_supported(key, TETHERING_SUPPORTED_FEATURE);

		supported |= value;
		key = va_arg(list, const char *);
		if (!key) break;
	}

	if (!supported) {
		ERR("Not supported feature");
		set_last_result(TETHERING_ERROR_NOT_SUPPORT_API);
		return TETHERING_ERROR_NOT_SUPPORT_API;
	}
	va_end(list);
	set_last_result(TETHERING_ERROR_NONE);

	return TETHERING_ERROR_NONE;
}