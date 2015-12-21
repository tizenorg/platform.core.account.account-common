
/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 *
 *
 * @file        account_key_handler.c
 * @brief       a c file for key manupulatation.
 */

#include <tizen.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <ckmc/ckmc-manager.h>
#include <ckmc/ckmc-error.h>
#include "account-private.h"
#include "dbg.h"
#include "account_err.h"
#include "account_key_handler.h"

#define ACCOUNT_MANAGER_MKEY_ALIAS "ACCOUNT_MANAGER_MKEY"
#define ACCOUNT_MANAGER_DEK_ALIAS_PFX "ACCOUNT_MANAGER_DEK_"
#define MKEY_LEN 32
#define DEK_LEN 32

#define RANDOM_FILE    "/dev/urandom"

static int _get_random(int length, unsigned char **random)
{
	FILE *f;
	int ret = -1;
	/* read random file */
	if ((f = fopen(RANDOM_FILE, "r")) != NULL) {
		ret = fread(*random, 1, length, f);
		if (fclose(f) != 0 || ret != length)
			return CKMC_ERROR_UNKNOWN;
	}
	return CKMC_ERROR_NONE;
}

static int _get_app_mkey(unsigned char **mkey, int *mkey_len)
{
	int ret = CKMC_ERROR_NONE;

	const char *password = "password";
	ckmc_raw_buffer_s *mkey_buffer = NULL;
	const char *alias = ACCOUNT_MANAGER_MKEY_ALIAS;

	_INFO("start _get_app_mkey");

	_INFO("before ckmc_get_data");
	ret = ckmc_get_data(alias, password, &mkey_buffer);
	_INFO("after ckmc_get_data");
	if (CKMC_ERROR_NONE != ret) {
		_INFO("before mkey_buffer free");
		if (mkey_buffer)
			ckmc_buffer_free(mkey_buffer);
		_INFO("after mkey_buffer free");
		return ret;
	}

	if (!mkey_buffer)
		return CKMC_ERROR_UNKNOWN;

	_INFO("before mkey_buffer->size=[%d]", mkey_buffer->size);
	*mkey_len = mkey_buffer->size;
	*mkey = (unsigned char *)malloc((*mkey_len)+1);
	if (*mkey == NULL) {
		ACCOUNT_FATAL("Memory Allocation Failed");
		return CKMC_ERROR_OUT_OF_MEMORY;
	}

	memset(*mkey, 0, (*mkey_len)+1);
	memcpy(*mkey, mkey_buffer->data, *mkey_len);
	_INFO("before mkey_buffer free");
	if (mkey_buffer)
		ckmc_buffer_free(mkey_buffer);
	_INFO("after mkey_buffer free");

	_INFO("end _get_app_mkey, mkey_address=[%x]", *mkey);
	return CKMC_ERROR_NONE;
}

static int _create_app_mkey(unsigned char **mkey, int *mkey_len)
{
	unsigned char *random;
	int ret = CKMC_ERROR_NONE;
	const char *alias = ACCOUNT_MANAGER_MKEY_ALIAS;
	ckmc_raw_buffer_s data;
	ckmc_policy_s policy;

	_INFO("start _create_app_mkey");

	random = (unsigned char *)malloc(MKEY_LEN);
	if (random == NULL) {
		ACCOUNT_FATAL("Memory Allocation Failed");
		return CKMC_ERROR_OUT_OF_MEMORY;
	}

	_INFO("before _get_random");
	ret = _get_random(MKEY_LEN, &random);
	if (CKMC_ERROR_NONE != ret) {
		if (random)
			free(random);
		return CKMC_ERROR_UNKNOWN;
	}

	policy.password = "password";
	policy.extractable = true;

	data.data = random;
	data.size = MKEY_LEN;

	_INFO("before ckmc_save_data");
	ret = ckmc_save_data(alias, data, policy);
	if (CKMC_ERROR_NONE != ret) {
		if (random)
			free(random);
		return ret;
	}

	*mkey = random;
	*mkey_len = MKEY_LEN;

	_INFO("end _create_app_mkey");
	return CKMC_ERROR_NONE;
}

static int _get_app_dek(char *mkey, const char *pkg_id, unsigned char **dek, int *dek_len)
{
	int ret = CKMC_ERROR_NONE;
	_INFO("start _get_app_dek");

	const char *password = mkey;
	ckmc_raw_buffer_s *dek_buffer = NULL;
	char alias[128] = {0,};

	snprintf(alias, sizeof(alias), "%s%s", ACCOUNT_MANAGER_DEK_ALIAS_PFX, pkg_id);

	ret = ckmc_get_data(alias, password, &dek_buffer);
	if (CKMC_ERROR_DB_ALIAS_UNKNOWN == ret) {
		ckmc_buffer_free(dek_buffer);
		return ret;
	} else if (CKMC_ERROR_NONE != ret) {
		ckmc_buffer_free(dek_buffer);
		return ret;
	}

	*dek_len = dek_buffer->size;
	*dek = (unsigned char *)malloc((*dek_len)+1);
	if (*dek == NULL) {
		ACCOUNT_FATAL("Memory Allocation Failed");
		return CKMC_ERROR_OUT_OF_MEMORY;
	}

	_INFO("before memcpy dek_buffer");
	memcpy(*dek, dek_buffer->data, (*dek_len)+1);
	_INFO("before dek_buffer free");
	ckmc_buffer_free(dek_buffer);

	_INFO("end _get_app_dek");
	return CKMC_ERROR_NONE;
}

static int _create_app_dek(char *mkey, const char *pkg_id, unsigned char **dek, int *dek_len)
{
	unsigned char *random;
	int ret = CKMC_ERROR_NONE;
	ckmc_raw_buffer_s data;
	ckmc_policy_s policy;
	char alias[128] = {0,};

	_INFO("start _create_app_dek");

	snprintf(alias, sizeof(alias), "%s%s", ACCOUNT_MANAGER_DEK_ALIAS_PFX, pkg_id);

	random = (unsigned char *)malloc(DEK_LEN);
	if (random == NULL) {
		ACCOUNT_FATAL("Memory Allocation Failed");
		return CKMC_ERROR_OUT_OF_MEMORY;
	}

	ret = _get_random(DEK_LEN, &random);
	if (CKMC_ERROR_NONE != ret) {
		if (random)
			free(random);
		return CKMC_ERROR_UNKNOWN;
	}

	policy.password = mkey;
	policy.extractable = true;

	data.data = random;
	data.size = DEK_LEN;

	_INFO("before ckmc_save_data");
	/* save app_dek in key_manager */
	ret = ckmc_save_data(alias, data, policy);
	if (CKMC_ERROR_NONE != ret) {
		if (random)
			free(random);
		return ret;
	}

	*dek = random;
	*dek_len = DEK_LEN;

	_INFO("end _create_app_dek");

	return CKMC_ERROR_NONE;
}

int account_key_handler_get_account_dek(const char *alias, unsigned char **account_dek, int *dek_len)
{
	int ret;
	unsigned char *account_mkey = NULL;
	int mkey_len = 0;

	if (alias == NULL || account_dek == NULL || dek_len == NULL)
		return _ACCOUNT_ERROR_INVALID_PARAMETER;

	_INFO("before _get_app_mkey");
	ret = _get_app_mkey(&account_mkey, &mkey_len);
	_INFO("after _get_app_mkey ret=[%d]", ret);
	if (ret != CKMC_ERROR_NONE) {
		_INFO("before _create_app_mkey");
		ret = _create_app_mkey(&account_mkey, &mkey_len);
		if (ret != CKMC_ERROR_NONE) {
			_ERR("_create_app_mkey failed ret=[%d]", ret);
			if (account_mkey)
				free(account_mkey);
			return ret;
		}
	}

	_INFO("before _get_app_mkey");
	ret = _get_app_dek((char *)account_mkey, alias, account_dek, dek_len);
	_INFO("after _get_app_mkey, ret=[%d]", ret);
	if (ret != CKMC_ERROR_NONE) {
		ret = _create_app_dek((char *)account_mkey, alias, account_dek, dek_len);
		_ACCOUNT_FREE(account_mkey);
		if (ret != CKMC_ERROR_NONE) {
			_ERR("_create_app_dek failed ret=[%d]", ret);
			return ret;
		}
	}

	_INFO("end account_key_hander_get_account_dek");

	return _ACCOUNT_ERROR_NONE;
}

/*
static int clear_test_keys(const char* pkg_id)
{
	int ret = CKMC_ERROR_NONE;
	char alias[128] = {0,};

	ret = ckmc_remove_alias(ACCOUNT_MANAGER_MKEY_ALIAS);
	if(CKMC_ERROR_NONE != ret) {
		return ret;
	}

	snprintf(alias, sizeof(alias), "%s%s", ACCOUNT_MANAGER_DEK_ALIAS_PFX, pkg_id);
	ret = ckmc_remove_alias(alias);
	if(CKMC_ERROR_NONE != ret) {
		return ret;
	}

	return CKMC_ERROR_NONE;
}
*/
