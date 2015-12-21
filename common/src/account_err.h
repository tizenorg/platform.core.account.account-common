/*
 *
 * Copyright (c) 2012 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
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
 *
 */

#ifndef __ACCOUNT_ERR_H__
#define __ACCOUNT_ERR_H__

#include <tizen.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum {
	_ACCOUNT_ERROR_NONE = TIZEN_ERROR_NONE,                   /**< Successful */
	_ACCOUNT_ERROR_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY,              /**< Out of memory */
	_ACCOUNT_ERROR_INVALID_PARAMETER = TIZEN_ERROR_INVALID_PARAMETER,        /**< Invalid parameter */

	_ACCOUNT_ERROR_DUPLICATED = TIZEN_ERROR_ACCOUNT | 0x01, /**< Same user name exists in your application */
	_ACCOUNT_ERROR_NO_DATA  = TIZEN_ERROR_NO_DATA, /**< Empty data */

	_ACCOUNT_ERROR_RECORD_NOT_FOUND = TIZEN_ERROR_ACCOUNT | 0x03, /**< Related record does not exist */
	_ACCOUNT_ERROR_DB_FAILED = TIZEN_ERROR_ACCOUNT | 0x04, /**< DB operation failed */
	_ACCOUNT_ERROR_DB_NOT_OPENED = TIZEN_ERROR_ACCOUNT | 0x05, /**< DB is not connected */
	_ACCOUNT_ERROR_QUERY_SYNTAX_ERROR = TIZEN_ERROR_ACCOUNT | 0x06, /**< DB query syntax error */
	_ACCOUNT_ERROR_ITERATOR_END = TIZEN_ERROR_ACCOUNT | 0x07, /**< Iterator has reached the end */
	_ACCOUNT_ERROR_NOTI_FAILED = TIZEN_ERROR_ACCOUNT | 0x08, /**< Notification failed */
	_ACCOUNT_ERROR_PERMISSION_DENIED = TIZEN_ERROR_PERMISSION_DENIED, /**< Permission denied */
	_ACCOUNT_ERROR_XML_PARSE_FAILED = TIZEN_ERROR_ACCOUNT | 0x0a, /**< XML parse failed */
	_ACCOUNT_ERROR_XML_FILE_NOT_FOUND = TIZEN_ERROR_ACCOUNT | 0x0b, /**< XML file does not exist */
	_ACCOUNT_ERROR_EVENT_SUBSCRIPTION_FAIL = TIZEN_ERROR_ACCOUNT | 0x0c, /**< Subscription failed */
	_ACCOUNT_ERROR_NOT_REGISTERED_PROVIDER = TIZEN_ERROR_ACCOUNT | 0x0d, /**< Account provider is not registered */
	_ACCOUNT_ERROR_NOT_ALLOW_MULTIPLE = TIZEN_ERROR_ACCOUNT | 0x0e, /**< Multiple accounts are not supported */
	_ACCOUNT_ERROR_DATABASE_BUSY = TIZEN_ERROR_ACCOUNT | 0x10, /**< SQLite busy handler expired */
} _ACCOUNT_ERROR_e;

#ifdef __cplusplus
}
#endif

#endif /* __ACCOUNT_ERR_H__*/
