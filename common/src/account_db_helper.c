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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <glib.h>
#include <db-util.h>
#include <pthread.h>
#include <vconf.h>

#include <pkgmgr-info.h>
#include <aul.h>
#include <tzplatform_config.h>

#include "dbg.h"
#include "account_free.h"
#include "account-private.h"
#include "account_err.h"
#include "account_crypto_service.h"
#include "account_db_helper.h"

#define EMAIL_SERVICE_CMDLINE "/usr/bin/email-service"

#define EMAIL_APPID "email-setting-efl"

#define ACCESS_TOKEN_ALIAS	"access_token"

#define ACCOUNT_DB_OPEN_READONLY 0
#define ACCOUNT_DB_OPEN_READWRITE 1

#define MAX_TEXT 4096

#define _TIZEN_PUBLIC_
#ifndef _TIZEN_PUBLIC_

#endif

//static sqlite3* g_hAccountDB = NULL;
//static sqlite3* g_hAccountDB2 = NULL;
//static sqlite3* g_hAccountGlobalDB = NULL;
//static sqlite3* g_hAccountGlobalDB2 = NULL;
//pthread_mutex_t account_mutex = PTHREAD_MUTEX_INITIALIZER;
//pthread_mutex_t account_global_mutex = PTHREAD_MUTEX_INITIALIZER;

char *_account_dup_text(const char *text_data)
{
	char *text_value = NULL;

	if (text_data != NULL) {
		text_value = strdup(text_data);
	}
	return text_value;
}


static inline int __read_proc(const char *path, char *buf, int size)
{
	int fd = 0, ret = 0;

	if (buf == NULL || path == NULL) {
		ACCOUNT_ERROR("path and buffer is mandatory\n");
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ACCOUNT_ERROR("fd open error(%d)\n", fd);
		return -1;
	}

	ret = read(fd, buf, size - 1);
	if (ret <= 0) {
		ACCOUNT_ERROR("fd read error(%d)\n", fd);
		close(fd);
		return -1;
	} else
		buf[ret] = 0;

	close(fd);

	return ret;
}

static inline char *_account_get_proc_cmdline_bypid(int pid)
{
	char buf[128];
	int ret = 0;

	ACCOUNT_SNPRINTF(buf, sizeof(buf), "/proc/%d/cmdline", pid);
	ret = __read_proc(buf, buf, sizeof(buf));
	if (ret <= 0) {
		ACCOUNT_DEBUG("No proc directory (%d)\n", pid);
		return NULL;
	}

	return strdup(buf);
}

char* _account_get_current_appid(int pid, uid_t uid)
{
	_INFO("getting caller appid with pid=[%d], uid=[%d]", pid, uid);

	int ret=0;
	char appid[128]={0,};
	char* appid_ret = NULL;

	ret = aul_app_get_appid_bypid_for_uid(pid, appid, sizeof(appid), uid);

	if(ret < 0){
		ACCOUNT_ERROR("fail to get current appid ret=[%d], appid=%s\n", ret, appid);
	}

	_INFO("");

	// SLP platform core exception
	if(strlen(appid) == 0){
		_INFO("");
		char* cmdline = NULL;
		cmdline = _account_get_proc_cmdline_bypid(pid);
		ACCOUNT_SLOGD("cmdline (%s)!!!!!!\n", cmdline);
		if (!g_strcmp0(cmdline, EMAIL_SERVICE_CMDLINE)) {
			appid_ret = _account_dup_text(EMAIL_APPID);
			_ACCOUNT_FREE(cmdline);

			if (appid_ret == NULL) {
				ACCOUNT_FATAL("Memory Allocation Failed");
				return NULL;
			}

			return appid_ret;
		} else {
			ACCOUNT_DEBUG("No app id\n");
			_ACCOUNT_FREE(cmdline);
			return NULL;
		}
	}

	appid_ret = _account_dup_text(appid);
	if (appid_ret == NULL) {
		ACCOUNT_FATAL("Memory Allocation Failed");
	}

	return appid_ret;
}


int _remove_sensitive_info_from_non_owning_account(account_s *account, int caller_pid, uid_t uid)
{
	if (account == NULL)
	{
		_ERR("Null input");
		return _ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	if (account->package_name)
	{
		char *caller_package_name = _account_get_current_appid(caller_pid, uid);
		if (caller_package_name == NULL)
		{
			_ERR("Could not get caller app id, so removing sensitive info from account id [%d]", account->id);
			return _ACCOUNT_ERROR_INVALID_PARAMETER;
		}

		if (g_strcmp0(caller_package_name, account->package_name) != 0)
		{
			// packages dont match, so remove sensitive info
			_INFO("Removing sensitive info from account id [%d]", account->id);
			free (account->access_token);
			account->access_token = NULL;

		} else {
			int ret = decrypt_access_token(account);
			if (ret != _ACCOUNT_ERROR_NONE)
			{
				_ERR("decrypt_access_token error");
				return ret;
			}
		}
		_ACCOUNT_FREE(caller_package_name);
		return _ACCOUNT_ERROR_NONE;
	}
	return _ACCOUNT_ERROR_INVALID_PARAMETER;
}

int _remove_sensitive_info_from_non_owning_account_list(GList *account_list, int caller_pid, uid_t uid)
{
	int return_code = _ACCOUNT_ERROR_NONE;

	if (account_list == NULL)
	{
		_ERR("Null input");
		return _ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	GList *list_iter = NULL;
	for (list_iter = account_list; list_iter != NULL; list_iter = g_list_next(list_iter))
	{
		account_s *account = (account_s *) list_iter->data;
		int ret = _remove_sensitive_info_from_non_owning_account(account, caller_pid, uid);
		if( ret != _ACCOUNT_ERROR_NONE)
			return_code = ret;
	}
	return return_code;
}

int _remove_sensitive_info_from_non_owning_account_slist(GSList *account_list, int caller_pid, uid_t uid)
{
	int return_code = _ACCOUNT_ERROR_NONE;

	if (account_list == NULL)
	{
		_ERR("Null input");
		return _ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	GSList *list_iter = NULL;
	for (list_iter = account_list; list_iter != NULL; list_iter = g_slist_next(list_iter))
	{
		account_s *account = (account_s *) list_iter->data;
		int ret = _remove_sensitive_info_from_non_owning_account(account, caller_pid, uid);
		if( ret != _ACCOUNT_ERROR_NONE)
			return_code = ret;
	}
	return return_code;
}


const char *_account_db_err_msg(sqlite3 *account_db_handle)
{
	return sqlite3_errmsg(account_db_handle);
}

int _account_db_err_code(sqlite3 *account_db_handle)
{
	return sqlite3_errcode(account_db_handle);
}

int _account_execute_query(sqlite3 *account_db_handle, const char *query)
{
	int rc = -1;
	char* pszErrorMsg = NULL;

	if(!query){
		ACCOUNT_ERROR("NULL query\n");
		return _ACCOUNT_ERROR_QUERY_SYNTAX_ERROR;
	}

	if(!account_db_handle){
		ACCOUNT_ERROR("DB is not opened\n");
		return _ACCOUNT_ERROR_DB_NOT_OPENED;
	}

	rc = sqlite3_exec(account_db_handle, query, NULL, NULL, &pszErrorMsg);
	if (SQLITE_OK != rc) {
		ACCOUNT_ERROR("sqlite3_exec rc(%d) query(%s) failed(%s).", rc, query, pszErrorMsg);
		sqlite3_free(pszErrorMsg);
	}

	return rc;
}

int _account_begin_transaction(sqlite3 *account_db_handle)
{
	ACCOUNT_DEBUG("_account_begin_transaction start");
	int ret = -1;

	ret = _account_execute_query(account_db_handle, "BEGIN IMMEDIATE TRANSACTION");

	if (ret == SQLITE_BUSY) {
		ACCOUNT_ERROR(" sqlite3 busy = %d", ret);
		return _ACCOUNT_ERROR_DATABASE_BUSY;
	} else if(ret != SQLITE_OK) {
		ACCOUNT_ERROR("_account_svc_begin_transaction fail :: %d", ret);
		return _ACCOUNT_ERROR_DB_FAILED;
	}

	ACCOUNT_DEBUG("_account_begin_transaction end");
	return _ACCOUNT_ERROR_NONE;
}

int _account_end_transaction(sqlite3 *account_db_handle, bool is_success)
{
	ACCOUNT_DEBUG("_account_end_transaction start");

	int ret = -1;

	if (is_success == true) {
		ret = _account_execute_query(account_db_handle, "COMMIT TRANSACTION");
		ACCOUNT_DEBUG("_account_end_transaction COMMIT");
	} else {
		ret = _account_execute_query(account_db_handle, "ROLLBACK TRANSACTION");
		ACCOUNT_DEBUG("_account_end_transaction ROLLBACK");
	}

	if(ret == SQLITE_PERM){
		ACCOUNT_ERROR("Account permission denied :: %d", ret);
		return _ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if (ret == SQLITE_BUSY){
		ACCOUNT_DEBUG(" sqlite3 busy = %d", ret);
		return _ACCOUNT_ERROR_DATABASE_BUSY;
	}

	if (ret != SQLITE_OK) {
		ACCOUNT_ERROR("_account_svc_end_transaction fail :: %d", ret);
		return _ACCOUNT_ERROR_DB_FAILED;
	}

	ACCOUNT_DEBUG("_account_end_transaction end");
	return _ACCOUNT_ERROR_NONE;
}

int _account_get_next_sequence(sqlite3 *account_db_handle, const char *pszName)
{
	int 			rc = 0;
	account_stmt	pStmt = NULL;
	int 			max_seq = 0;
	char 			szQuery[ACCOUNT_SQL_LEN_MAX] = {0,};

	ACCOUNT_MEMSET(szQuery, 0x00, sizeof(szQuery));
	ACCOUNT_SNPRINTF(szQuery, sizeof(szQuery),  "SELECT max(seq) FROM %s where name = '%s' ", ACCOUNT_SQLITE_SEQ, pszName);
	rc = sqlite3_prepare_v2(account_db_handle, szQuery, strlen(szQuery), &pStmt, NULL);
	if (SQLITE_OK != rc) {
		ACCOUNT_SLOGE("sqlite3_prepare_v2() failed(%d, %s).", rc, _account_db_err_msg(account_db_handle));
		sqlite3_finalize(pStmt);
		return _ACCOUNT_ERROR_DB_FAILED;
	}

	rc = sqlite3_step(pStmt);
	max_seq = sqlite3_column_int(pStmt, 0);
	max_seq++;

	/*Finalize Statement*/
	rc = sqlite3_finalize(pStmt);
	pStmt = NULL;

	return max_seq;
}

account_stmt _account_prepare_query(sqlite3 *account_db_handle, char *query)
{
	int 			rc = -1;
	account_stmt 	pStmt = NULL;

	ACCOUNT_RETURN_VAL((query != NULL), {}, NULL, ("query is NULL"));

	rc = sqlite3_prepare_v2(account_db_handle, query, strlen(query), &pStmt, NULL);

	ACCOUNT_RETURN_VAL((SQLITE_OK == rc), {}, NULL, ("sqlite3_prepare_v2(%s) failed(%s).", query, _account_db_err_msg(account_db_handle)));

	return pStmt;
}


int _account_query_bind_int(account_stmt pStmt, int pos, int num)
{
	if(!pStmt){
		ACCOUNT_ERROR("statement is null");
		return -1;
	}

	if(pos < 0){
		ACCOUNT_ERROR("invalid pos");
		return -1;
	}

	return sqlite3_bind_int(pStmt, pos, num);
}

int _account_query_bind_text(account_stmt pStmt, int pos, const char *str)
{
	_INFO("_account_query_bind_text");

	if(!pStmt)
	{
		_ERR("statement is null");
		return -1;
	}

	if(str)
	{
		_INFO("sqlite3_bind_text");
		return sqlite3_bind_text(pStmt, pos, (const char*)str, strlen(str), SQLITE_STATIC);
	}
	else
	{
		_INFO("sqlite3_bind_null");
		return sqlite3_bind_null(pStmt, pos);
	}
}

int _account_query_finalize(account_stmt pStmt)
{
	int rc = -1;

	if (!pStmt) {
		ACCOUNT_ERROR( "pStmt is NULL");
		return _ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	rc = sqlite3_finalize(pStmt);
	if (rc == SQLITE_BUSY){
		ACCOUNT_ERROR(" sqlite3 busy = %d", rc);
		return _ACCOUNT_ERROR_DATABASE_BUSY;
	} else if (rc != SQLITE_OK) {
		//ACCOUNT_ERROR( "sqlite3_finalize fail, rc : %d, db_error : %s\n", rc, _account_db_err_msg());
		ACCOUNT_ERROR( "sqlite3_finalize fail, rc : %d\n", rc);
		return _ACCOUNT_ERROR_DB_FAILED;
	}

	return _ACCOUNT_ERROR_NONE;
}

int _account_query_step(account_stmt pStmt)
{
	if(!pStmt){
		ACCOUNT_ERROR( "pStmt is NULL");
		return -1;
	}

	return sqlite3_step(pStmt);
}


static int _account_query_table_column_int(account_stmt pStmt, int pos)
{
	if(!pStmt){
		ACCOUNT_ERROR("statement is null");
		return -1;
	}

	if(pos < 0){
		ACCOUNT_ERROR("invalid pos");
		return -1;
	}

	return sqlite3_column_int(pStmt, pos);
}

static const char *_account_query_table_column_text(account_stmt pStmt, int pos)
{
	if(!pStmt){
		ACCOUNT_ERROR("statement is null");
		return NULL;
	}

	if(pos < 0){
		ACCOUNT_ERROR("invalid pos");
		return NULL;
	}

	return (const char*)sqlite3_column_text(pStmt, pos);
}

static void _account_db_data_to_text(const char *textbuf, char **output)
{
	if (textbuf && strlen(textbuf)>0) {
		if (*output) {
			free(*output);
			*output = NULL;
		}
		*output = strdup(textbuf);
	}
}

int _account_convert_account_to_sql(account_s *account, account_stmt hstmt, char *sql_value)
{
	_INFO("start");

	int count = 1;

	/*Caution : Keep insert query orders.*/

	/* 1. user name*/
	_account_query_bind_text(hstmt, count++, (char*)account->user_name);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], user_name=%s", account->id, account->user_name);

	/* 2. email address*/
	_account_query_bind_text(hstmt, count++, (char*)account->email_address);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], email_address=%s", account->id, account->email_address);

	/* 3. display name*/
	_account_query_bind_text(hstmt, count++, (char*)account->display_name);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], display_name=%s", account->id, account->display_name);

	/* 4. icon path*/
	_account_query_bind_text(hstmt, count++, (char*)account->icon_path);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], icon_path=%s", account->id, account->icon_path);

	/* 5. source*/
	_account_query_bind_text(hstmt, count++, (char*)account->source);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], source=%s", account->id, account->source);

	/* 6. package name*/
	_account_query_bind_text(hstmt, count++, (char*)account->package_name);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], package_name=%s", account->id, account->package_name);

	/* 7. access token*/
	_account_query_bind_text(hstmt, count++, (char*)account->access_token);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], access_token=%s", account->id, account->access_token);

	/* 8. domain name*/
	_account_query_bind_text(hstmt, count++, (char*)account->domain_name);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], domain_name=%s", account->id, account->domain_name);

	/* 9. auth type*/
	_account_query_bind_int(hstmt, count++, account->auth_type);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], auth_type=%d", account->id, account->auth_type);

	/* 10. secret */
	_account_query_bind_int(hstmt, count++, account->secret);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], secret=%d", account->id, account->secret);

	/* 11. sync_support */
	_account_query_bind_int(hstmt, count++, account->sync_support);
	_INFO("account_update_to_db_by_id_ex_p : after convert() : account_id[%d], sync_support=%d", account->id, account->sync_support);

	int i;

	/* 12. user text*/
	for(i=0; i< USER_TXT_CNT; i++)
		_account_query_bind_text(hstmt, count++, (char*)account->user_data_txt[i]);

	/* 13. user integer	*/
	for(i=0; i< USER_INT_CNT; i++)
	{
		_account_query_bind_int(hstmt, count++, account->user_data_int[i]);
	_INFO("convert user_data_int : marshal_user_int data_int[%d]=%d", i, account->user_data_int[i]);
	}

	_INFO("end");

	return count;
}

void _account_convert_column_to_account(account_stmt hstmt, account_s *account_record)
{
	const char *textbuf = NULL;

	account_record->id = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_ID);
	ACCOUNT_DEBUG("account_record->id =[%d]", account_record->id);

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_USER_NAME);
	_account_db_data_to_text(textbuf, &(account_record->user_name));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_EMAIL_ADDRESS);
	_account_db_data_to_text(textbuf, &(account_record->email_address));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_DISPLAY_NAME);
	_account_db_data_to_text(textbuf, &(account_record->display_name));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_ICON_PATH);
	_account_db_data_to_text(textbuf, &(account_record->icon_path));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_SOURCE);
	_account_db_data_to_text(textbuf, &(account_record->source));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_PACKAGE_NAME);
	_account_db_data_to_text(textbuf, &(account_record->package_name));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_ACCESS_TOKEN);
	_account_db_data_to_text(textbuf, &(account_record->access_token));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_DOMAIN_NAME);
	_account_db_data_to_text(textbuf, &(account_record->domain_name));

	account_record->auth_type = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_AUTH_TYPE);

	account_record->secret = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_SECRET);

	account_record->sync_support = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_SYNC_SUPPORT);

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_USER_TEXT_0);
	_account_db_data_to_text(textbuf, &(account_record->user_data_txt[0]));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_USER_TEXT_1);
	_account_db_data_to_text(textbuf, &(account_record->user_data_txt[1]));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_USER_TEXT_2);
	_account_db_data_to_text(textbuf, &(account_record->user_data_txt[2]));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_USER_TEXT_3);
	_account_db_data_to_text(textbuf, &(account_record->user_data_txt[3]));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_FIELD_USER_TEXT_4);
	_account_db_data_to_text(textbuf, &(account_record->user_data_txt[4]));

	account_record->user_data_int[0] = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_USER_INT_0);
	account_record->user_data_int[1] = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_USER_INT_1);
	account_record->user_data_int[2] = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_USER_INT_2);
	account_record->user_data_int[3] = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_USER_INT_3);
	account_record->user_data_int[4] = _account_query_table_column_int(hstmt, ACCOUNT_FIELD_USER_INT_4);
}

void _account_convert_column_to_capability(account_stmt hstmt, account_capability_s *capability_record)
{
	const char *textbuf = NULL;

	_INFO("start _account_convert_column_to_capability()");
	capability_record->id = _account_query_table_column_int(hstmt, CAPABILITY_FIELD_ID);

	textbuf = _account_query_table_column_text(hstmt, CAPABILITY_FIELD_KEY);
	_account_db_data_to_text(textbuf, &(capability_record->type));

	capability_record->value = _account_query_table_column_int(hstmt, CAPABILITY_FIELD_VALUE);

	textbuf = _account_query_table_column_text(hstmt, CAPABILITY_FIELD_PACKAGE_NAME);
	_account_db_data_to_text(textbuf, &(capability_record->package_name));

	textbuf = _account_query_table_column_text(hstmt, CAPABILITY_FIELD_USER_NAME);
	_account_db_data_to_text(textbuf, &(capability_record->user_name));

	capability_record->account_id = _account_query_table_column_int(hstmt, CAPABILITY_FIELD_ACCOUNT_ID);
	_INFO("type = %s, value = %d", capability_record->type, capability_record->value);
	_INFO("end _account_convert_column_to_capability()");
}

void _account_convert_column_to_custom(account_stmt hstmt, account_custom_s *custom_record)
{
	_INFO("start _account_convert_column_to_custom()");
	const char *textbuf = NULL;

	custom_record->account_id = _account_query_table_column_int(hstmt, ACCOUNT_CUSTOM_FIELD_ACCOUNT_ID);

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_CUSTOM_FIELD_APP_ID);
	_account_db_data_to_text(textbuf, &(custom_record->app_id));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_CUSTOM_FIELD_KEY);
	_account_db_data_to_text(textbuf, &(custom_record->key));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_CUSTOM_FIELD_VALUE);
	_account_db_data_to_text(textbuf, &(custom_record->value));
	_INFO("key = %s, value = %s", custom_record->key, custom_record->value);
	_INFO("end _account_convert_column_to_custom()");
}


int _account_get_record_count(sqlite3 *account_db_handle, const char* query)
{
	_INFO("_account_get_record_count query=[%s]", query);

	int rc = -1;
	int ncount = 0;
	account_stmt pStmt = NULL;

	if(!query){
		_ERR("NULL query\n");
		return _ACCOUNT_ERROR_QUERY_SYNTAX_ERROR;
	}

	if(!account_db_handle){
		_ERR("DB is not opened\n");
		return _ACCOUNT_ERROR_DB_NOT_OPENED;
	}

	rc = sqlite3_prepare_v2(account_db_handle, query, strlen(query), &pStmt, NULL);

	if (SQLITE_BUSY == rc){
		_ERR("sqlite3_prepare_v2() failed(%d, %s).", rc, _account_db_err_msg(account_db_handle));
		sqlite3_finalize(pStmt);
		return _ACCOUNT_ERROR_DATABASE_BUSY;
	} else if (SQLITE_OK != rc) {
		_ERR("sqlite3_prepare_v2() failed(%d, %s).", rc, _account_db_err_msg(account_db_handle));
		sqlite3_finalize(pStmt);
		return _ACCOUNT_ERROR_DB_FAILED;
	}

	rc = sqlite3_step(pStmt);
	if (SQLITE_BUSY == rc) {
		_ERR("sqlite3_step() failed(%d, %s).", rc, _account_db_err_msg(account_db_handle));
		sqlite3_finalize(pStmt);
		return _ACCOUNT_ERROR_DATABASE_BUSY;
	} else if (SQLITE_ROW != rc) {
		_ERR("sqlite3_step() failed(%d, %s).", rc, _account_db_err_msg(account_db_handle));
		sqlite3_finalize(pStmt);
		return _ACCOUNT_ERROR_DB_FAILED;
	}

	ncount = sqlite3_column_int(pStmt, 0);

	_INFO("account record count [%d]", ncount);
	sqlite3_finalize(pStmt);

	return ncount;
}

int _account_create_all_tables(sqlite3 *account_db_handle)
{
	int rc = -1;
	int error_code = _ACCOUNT_ERROR_NONE;
	char	query[ACCOUNT_SQL_LEN_MAX] = {0, };

	_INFO("create all table - BEGIN");
	ACCOUNT_MEMSET(query, 0, sizeof(query));

	// Create the account table
	ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from sqlite_master where name in ('%s')", ACCOUNT_TABLE);
	rc = _account_get_record_count(account_db_handle, query);
	if (rc <= 0) {
		rc = _account_execute_query(account_db_handle, ACCOUNT_SCHEMA);
		if(rc == SQLITE_BUSY) return _ACCOUNT_ERROR_DATABASE_BUSY;
		ACCOUNT_RETURN_VAL((SQLITE_OK == rc), {}, _ACCOUNT_ERROR_DB_FAILED, ("_account_execute_query(account_db_handle, %s) failed(%d, %s).\n", ACCOUNT_SCHEMA, rc, _account_db_err_msg(account_db_handle)));

	}

	// Create capability table
	ACCOUNT_MEMSET(query, 0, sizeof(query));
	ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from sqlite_master where name in ('%s')", CAPABILITY_TABLE);
	rc = _account_get_record_count(account_db_handle, query);
	if (rc <= 0) {
		rc = _account_execute_query(account_db_handle, CAPABILITY_SCHEMA);
		if(rc == SQLITE_BUSY) return _ACCOUNT_ERROR_DATABASE_BUSY;
		ACCOUNT_RETURN_VAL((SQLITE_OK == rc), {}, _ACCOUNT_ERROR_DB_FAILED, ("_account_execute_query(account_db_handle, %s) failed(%d, %s).\n", CAPABILITY_SCHEMA, rc, _account_db_err_msg(account_db_handle)));
	}

	// Create account custom table
	ACCOUNT_MEMSET(query, 0, sizeof(query));
	ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from sqlite_master where name in ('%s')", ACCOUNT_CUSTOM_TABLE);
	rc = _account_get_record_count(account_db_handle, query);
	if (rc <= 0) {
		rc = _account_execute_query(account_db_handle, ACCOUNT_CUSTOM_SCHEMA);
		if(rc == SQLITE_BUSY) return _ACCOUNT_ERROR_DATABASE_BUSY;
		ACCOUNT_RETURN_VAL((SQLITE_OK == rc), {}, _ACCOUNT_ERROR_DB_FAILED, ("_account_execute_query(account_db_handle, %s) failed(%d, %s).\n", query, rc, _account_db_err_msg(account_db_handle)));
	}

	// Create account type table
	ACCOUNT_MEMSET(query, 0, sizeof(query));
	ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from sqlite_master where name in ('%s')", ACCOUNT_TYPE_TABLE);
	rc = _account_get_record_count(account_db_handle, query);
	if (rc <= 0) {
		rc = _account_execute_query(account_db_handle, ACCOUNT_TYPE_SCHEMA);
		if(rc == SQLITE_BUSY) return _ACCOUNT_ERROR_DATABASE_BUSY;
		ACCOUNT_RETURN_VAL((SQLITE_OK == rc), {}, _ACCOUNT_ERROR_DB_FAILED, ("_account_execute_query(account_db_handle, %s) failed(%d, %s).\n", ACCOUNT_TYPE_SCHEMA, rc, _account_db_err_msg(account_db_handle)));
	}

	// Create label table
	ACCOUNT_MEMSET(query, 0, sizeof(query));
	ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from sqlite_master where name in ('%s')", LABEL_TABLE);
	rc = _account_get_record_count(account_db_handle, query);
	if (rc <= 0) {
		rc = _account_execute_query(account_db_handle, LABEL_SCHEMA);
		if(rc == SQLITE_BUSY) return _ACCOUNT_ERROR_DATABASE_BUSY;
		ACCOUNT_RETURN_VAL((SQLITE_OK == rc), {}, _ACCOUNT_ERROR_DB_FAILED, ("_account_execute_query(account_db_handle, %s) failed(%d, %s).\n", LABEL_SCHEMA, rc, _account_db_err_msg(account_db_handle)));
	}

	// Create account feature table
	ACCOUNT_MEMSET(query, 0, sizeof(query));
	ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from sqlite_master where name in ('%s')", PROVIDER_FEATURE_TABLE);
	rc = _account_get_record_count(account_db_handle, query);
	if (rc <= 0) {
		rc = _account_execute_query(account_db_handle, PROVIDER_FEATURE_SCHEMA);
		if(rc == SQLITE_BUSY) return _ACCOUNT_ERROR_DATABASE_BUSY;
		ACCOUNT_RETURN_VAL((SQLITE_OK == rc), {}, _ACCOUNT_ERROR_DB_FAILED, ("_account_execute_query(account_db_handle, %s) failed(%d, %s).\n", PROVIDER_FEATURE_SCHEMA, rc, _account_db_err_msg(account_db_handle)));
	}

	_INFO("create all table - END");
	return error_code;
}

int _account_check_is_all_table_exists(sqlite3 *account_db_handle)
{
	int 	rc = 0;
	char	query[ACCOUNT_SQL_LEN_MAX] = {0,};
	ACCOUNT_MEMSET(query, 0, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from sqlite_master where name in ('%s', '%s', '%s', '%s', '%s', '%s')",
			ACCOUNT_TABLE, CAPABILITY_TABLE, ACCOUNT_CUSTOM_TABLE, ACCOUNT_TYPE_TABLE, LABEL_TABLE, PROVIDER_FEATURE_TABLE);
	rc = _account_get_record_count(account_db_handle, query);

	if (rc != ACCOUNT_TABLE_TOTAL_COUNT) {
		ACCOUNT_ERROR("Table count is not matched rc=%d\n", rc);
	}

	return rc;
}

int _account_db_handle_close(sqlite3* account_db_handle)
{
	int rc = 0;
	int ret = _ACCOUNT_ERROR_NONE;
	if(account_db_handle)
	{
		rc = db_util_close(account_db_handle);
		if(  rc == SQLITE_OK )
			ret = _ACCOUNT_ERROR_NONE;
		else if(  rc == SQLITE_PERM )
			ret = _ACCOUNT_ERROR_PERMISSION_DENIED;
		else if ( rc == SQLITE_BUSY )
			ret = _ACCOUNT_ERROR_DATABASE_BUSY;
		else
			ret = _ACCOUNT_ERROR_DB_FAILED;
	}
	return ret;
}



static int _account_get_current_appid_cb(const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	char* appid = NULL;
	char* item = NULL;
	GSList** appid_list = (GSList**)user_data;
	int pkgmgr_ret = -1;

	pkgmgr_ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);

	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_get_appid(%d)", pkgmgr_ret);
	}

	item = _account_dup_text(appid);
	if (item == NULL) {
		ACCOUNT_FATAL("Memory Allocation Failed");
		return _ACCOUNT_ERROR_OUT_OF_MEMORY;
	}

	*appid_list = g_slist_append(*appid_list, item);

	return _ACCOUNT_ERROR_NONE;
}

static int _account_type_query_app_id_exist(sqlite3 *account_db_handle, const char* app_id)
{
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;

	ACCOUNT_RETURN_VAL((app_id != 0), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("APP ID IS NULL"));
	ACCOUNT_RETURN_VAL((account_db_handle != NULL), {}, _ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) FROM %s WHERE AppId = '%s'", ACCOUNT_TYPE_TABLE, app_id);
	rc = _account_get_record_count(account_db_handle, query);

	if( _account_db_err_code(account_db_handle) == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg(account_db_handle));
		return _ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if (rc <= 0) {
		return _ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	return _ACCOUNT_ERROR_NONE;
}

int _account_type_query_app_id_exist_from_all_db(sqlite3 *account_user_db, sqlite3 *account_global_db, const char *app_id)
{
	_INFO("_account_type_query_app_id_exist_from_all_db start app_id=%s", app_id);
	ACCOUNT_RETURN_VAL((account_user_db != NULL), {}, _ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));
	ACCOUNT_RETURN_VAL((account_global_db != NULL), {}, _ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));
	int return_code = _ACCOUNT_ERROR_NONE;

	return_code = _account_type_query_app_id_exist(account_user_db, app_id);

	if (return_code == _ACCOUNT_ERROR_RECORD_NOT_FOUND) {
		return_code = _account_type_query_app_id_exist(account_global_db, app_id);
	} else {
		return return_code;
	}
	_INFO("_account_type_query_app_id_exist end");
	return return_code;
}

int _account_get_represented_appid_from_db(sqlite3 *account_user_db, sqlite3 *account_global_db, const char* appid, uid_t uid, char** verified_appid)
{
	int error_code = _ACCOUNT_ERROR_NOT_REGISTERED_PROVIDER;
	pkgmgrinfo_appinfo_h ahandle=NULL;
	pkgmgrinfo_pkginfo_h phandle=NULL;
	char* package_id = NULL;
	GSList* appid_list = NULL;
	GSList* iter = NULL;

	if(!appid){
		ACCOUNT_ERROR("input param is null\n");
		return _ACCOUNT_ERROR_NOT_REGISTERED_PROVIDER;
	}

	if(!verified_appid){
		ACCOUNT_ERROR("output param is null\n");
		return _ACCOUNT_ERROR_NOT_REGISTERED_PROVIDER;
	}

	if(!strcmp(appid, "com.samsung.setting")){
		ACCOUNT_DEBUG("Setting exception\n");
		*verified_appid = _account_dup_text("com.samsung.setting");
		if (*verified_appid == NULL) {
			ACCOUNT_FATAL("Memory Allocation Failed");
			return _ACCOUNT_ERROR_OUT_OF_MEMORY;
		}
		return _ACCOUNT_ERROR_NONE;
	}

	if(!strcmp(appid, "com.samsung.samsung-account-front")){
		ACCOUNT_DEBUG("Setting exception\n");
		*verified_appid = _account_dup_text("com.samsung.samsung-account-front");
		if (*verified_appid == NULL) {
			ACCOUNT_FATAL("Memory Allocation Failed");
			return _ACCOUNT_ERROR_OUT_OF_MEMORY;
		}
		return _ACCOUNT_ERROR_NONE;
	}

	// Get app id family which is stored in account database
	int pkgmgr_ret = -1;

	if (uid == OWNER_ROOT || uid == GLOBAL_USER) {
		pkgmgr_ret = pkgmgrinfo_appinfo_get_appinfo(appid, &ahandle);
	} else {
		pkgmgr_ret = pkgmgrinfo_appinfo_get_usr_appinfo(appid, uid, &ahandle);
	}
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_get_appinfo(%d)", pkgmgr_ret);
	}

	pkgmgr_ret = pkgmgrinfo_appinfo_get_pkgid(ahandle, &package_id);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_get_pkgid(%d)", pkgmgr_ret);
	}

	if (uid == OWNER_ROOT || uid == GLOBAL_USER) {
		pkgmgr_ret = pkgmgrinfo_pkginfo_get_pkginfo(package_id, &phandle);
	} else {
		pkgmgr_ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(package_id, uid, &phandle);
	}
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_pkginfo_get_pkginfo(%d)", pkgmgr_ret);
	}

	if (uid == OWNER_ROOT || uid == GLOBAL_USER) {
		pkgmgr_ret = pkgmgrinfo_appinfo_get_list(phandle, PMINFO_ALL_APP, _account_get_current_appid_cb, (void *)&appid_list);
	} else {
		pkgmgr_ret = pkgmgrinfo_appinfo_get_usr_list(phandle, PMINFO_ALL_APP, _account_get_current_appid_cb, (void *)&appid_list, uid);
	}
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_get_list(%d)", pkgmgr_ret);
	}

	// Compare current app id with the stored app id family
	for(iter=appid_list;iter!=NULL;iter=g_slist_next(iter)){
		char* tmp = (char*)iter->data;
		if(tmp) {
			if(_account_type_query_app_id_exist_from_all_db(account_user_db, account_global_db, tmp) ==  _ACCOUNT_ERROR_NONE) {
				*verified_appid = _account_dup_text(tmp);
				if (*verified_appid == NULL) {
					ACCOUNT_FATAL("Memory Allocation Failed");
					error_code = _ACCOUNT_ERROR_OUT_OF_MEMORY;
					break;
				}
				error_code = _ACCOUNT_ERROR_NONE;
				_ACCOUNT_FREE(tmp);
				break;
			} else {
				ACCOUNT_SLOGD("not matched owner group app id(%s), current appid(%s)\n", tmp, appid);
			}
		}
		_ACCOUNT_FREE(tmp);
	}

	g_slist_free(appid_list);
	pkgmgr_ret = pkgmgrinfo_pkginfo_destroy_pkginfo(phandle);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_pkginfo_destroy_pkginfo(%d)", pkgmgr_ret);
	}

	pkgmgr_ret = pkgmgrinfo_appinfo_destroy_appinfo(ahandle);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_destroy_appinfo(%d)", pkgmgr_ret);
	}

	return error_code;
}

int _account_check_appid_group_with_package_name(const char* appid, char* package_name, uid_t uid)
{
	int error_code = _ACCOUNT_ERROR_PERMISSION_DENIED;
	pkgmgrinfo_appinfo_h ahandle=NULL;
	pkgmgrinfo_pkginfo_h phandle=NULL;
	char* package_id = NULL;
	GSList* appid_list = NULL;
	GSList* iter = NULL;

	if(!appid){
		ACCOUNT_ERROR("input param -appid is null\n");
		return _ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	if(!package_name){
		ACCOUNT_ERROR("input param - package name is null\n");
		return _ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	// Get app id family which is stored in account database
	int pkgmgr_ret = -1;
	if (uid == OWNER_ROOT || uid == GLOBAL_USER) {
		pkgmgr_ret = pkgmgrinfo_appinfo_get_appinfo(appid, &ahandle);
	} else {
		pkgmgr_ret = pkgmgrinfo_appinfo_get_usr_appinfo(appid, uid, &ahandle);
	}
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_get_appinfo(%d)", pkgmgr_ret);
	}

	pkgmgr_ret = pkgmgrinfo_appinfo_get_pkgid(ahandle, &package_id);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_get_pkgid(%d)", pkgmgr_ret);
	}

	if (uid == OWNER_ROOT || uid == GLOBAL_USER) {
		pkgmgr_ret = pkgmgrinfo_pkginfo_get_pkginfo(package_id, &phandle);
	} else {
		pkgmgr_ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(package_id, uid, &phandle);
	}
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_pkginfo_get_pkginfo(%d)", pkgmgr_ret);
	}

	if (uid == OWNER_ROOT || uid == GLOBAL_USER) {
		pkgmgr_ret = pkgmgrinfo_appinfo_get_list(phandle, PMINFO_ALL_APP, _account_get_current_appid_cb, (void *)&appid_list);
	} else {
		pkgmgr_ret = pkgmgrinfo_appinfo_get_usr_list(phandle, PMINFO_ALL_APP, _account_get_current_appid_cb, (void *)&appid_list, uid);
	}
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_get_list(%d)", pkgmgr_ret);
	}

	// Compare current app id with the stored app id family
	for(iter=appid_list;iter!=NULL;iter=g_slist_next(iter)){
		char* tmp = (char*)iter->data;
		if(tmp) {
			//ACCOUNT_ERROR("tmp(%s)package_name(%s)\n\n", tmp, package_name);	// TODO: NEED TO REMOVE, debug log.
			if( strcmp(tmp, package_name) == 0) {
				error_code = _ACCOUNT_ERROR_NONE;
				_ACCOUNT_FREE(tmp);
				break;
			} else if ( strcmp(tmp, "com.samsung.samsung-account-front") == 0 &&
						strcmp(package_name, "com.samsung.samsungaccount") == 0 ) {
				// Samung Account Exception
				error_code = _ACCOUNT_ERROR_NONE;
				_ACCOUNT_FREE(tmp);
				break;
			} else {
				ACCOUNT_SLOGD("not matched owner group app id(%s), current appid(%s)\n", tmp, appid);
			}
		}
		_ACCOUNT_FREE(tmp);
	}

	g_slist_free(appid_list);
	pkgmgr_ret = pkgmgrinfo_pkginfo_destroy_pkginfo(phandle);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_pkginfo_destroy_pkginfo(%d)", pkgmgr_ret);
	}

	pkgmgr_ret = pkgmgrinfo_appinfo_destroy_appinfo(ahandle);
	if( pkgmgr_ret != PMINFO_R_OK ){
		ACCOUNT_DEBUG("pkgmgrinfo_appinfo_destroy_appinfo(%d)", pkgmgr_ret);
	}

	return error_code;
}

static bool _account_add_capability_to_account_cb(const char* capability_type, int capability_value, account_s *account)
{
	account_capability_s *cap_data = (account_capability_s*)malloc(sizeof(account_capability_s));
	if (cap_data == NULL) {
		ACCOUNT_FATAL("Memory Allocation Failed");
		return FALSE;
	}

	ACCOUNT_MEMSET(cap_data, 0, sizeof(account_capability_s));

	cap_data->type = _account_dup_text(capability_type);
	if (cap_data->type == NULL) {
		ACCOUNT_FATAL("_account_add_capability_to_account_cb :: malloc fail");
		return FALSE;
	}

	cap_data->value = capability_value;
	_INFO("cap_data->type = %s, cap_data->value = %d", cap_data->type, cap_data->value);

	account->capablity_list = g_slist_append(account->capablity_list, (gpointer)cap_data);

	return TRUE;
}

static bool _account_add_custom_to_account_cb(const char* key, const char* value, account_s *account)
{
	account_custom_s *custom_data = (account_custom_s*)malloc(sizeof(account_custom_s));

	if (custom_data == NULL) {
		ACCOUNT_FATAL("_account_add_custom_to_account_cb :: malloc fail\n");
		return FALSE;
	}
	ACCOUNT_MEMSET(custom_data, 0, sizeof(account_custom_s));

	custom_data->account_id = account->id;
	custom_data->app_id = _account_dup_text(account->package_name);
	if (custom_data->app_id == NULL) {
		ACCOUNT_FATAL("Memory Allocation Failed");
		return FALSE;
	}

	custom_data->key = _account_dup_text(key);
	if (custom_data->key == NULL) {
		ACCOUNT_FATAL("Memory Allocation Failed");
		return FALSE;
	}

	custom_data->value = _account_dup_text(value);
	if (custom_data->value == NULL) {
		ACCOUNT_FATAL("Memory Allocation Failed");
		return FALSE;
	}

	_INFO("custom_data->key = %s, custom_data->value = %s", custom_data->key, custom_data->value);

	account->custom_list = g_slist_append(account->custom_list, (gpointer)custom_data);

	return TRUE;
}

int _account_query_capability_by_account_id(sqlite3 *account_db_handle, account_add_capability_cb callback, int account_id, void *user_data )
{
	int 			error_code = _ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;

	ACCOUNT_RETURN_VAL((account_id > 0), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT INDEX IS LESS THAN 0"));
	ACCOUNT_RETURN_VAL((callback != NULL), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("NO CALLBACK FUNCTION"));
	ACCOUNT_RETURN_VAL((account_db_handle != NULL), {}, _ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE account_id = %d", CAPABILITY_TABLE, account_id);
	hstmt = _account_prepare_query(account_db_handle, query);

	if( _account_db_err_code(account_db_handle) == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg(account_db_handle));
		return _ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_ROW, {}, _ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	account_capability_s* capability_record = NULL;

	while (rc == SQLITE_ROW) {
		bool cb_ret = FALSE;
		capability_record = (account_capability_s*) malloc(sizeof(account_capability_s));

		if (capability_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}

		ACCOUNT_MEMSET(capability_record, 0x00, sizeof(account_capability_s));

		_account_convert_column_to_capability(hstmt, capability_record);

		cb_ret = callback(capability_record->type, capability_record->value, (account_s *)user_data);

		_account_free_capability_with_items(capability_record);

		ACCOUNT_CATCH_ERROR(cb_ret == TRUE, {}, _ACCOUNT_ERROR_NONE, ("Callback func returs FALSE, its iteration is stopped!!!!\n"));

		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == _ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	error_code = _ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == _ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	return error_code;
}

int _account_query_custom_by_account_id(sqlite3 *account_db_handle, account_add_custom_cb callback, int account_id, void *user_data )
{
	int 			error_code = _ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;

	ACCOUNT_RETURN_VAL((account_id > 0), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT INDEX IS LESS THAN 0"));
	ACCOUNT_RETURN_VAL((callback != NULL), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("NO CALLBACK FUNCTION"));
	ACCOUNT_RETURN_VAL((account_db_handle != NULL), {}, _ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE AccountId = %d", ACCOUNT_CUSTOM_TABLE, account_id);
	hstmt = _account_prepare_query(account_db_handle, query);

	if( _account_db_err_code(account_db_handle) == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg(account_db_handle));
		return _ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	rc = _account_query_step(hstmt);

	ACCOUNT_CATCH_ERROR(rc == SQLITE_ROW, {}, _ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	account_custom_s* custom_record = NULL;

	while (rc == SQLITE_ROW) {
		bool cb_ret = FALSE;
		custom_record = (account_custom_s*) malloc(sizeof(account_custom_s));

		if (custom_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}

		ACCOUNT_MEMSET(custom_record, 0x00, sizeof(account_custom_s));

		_account_convert_column_to_custom(hstmt, custom_record);

		cb_ret = callback(custom_record->key, custom_record->value, (account_s *)user_data);

		_account_free_custom_with_items(custom_record);

		ACCOUNT_CATCH_ERROR(cb_ret == TRUE, {}, _ACCOUNT_ERROR_NONE, ("Callback func returs FALSE, its iteration is stopped!!!!\n"));

		rc = _account_query_step(hstmt);
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == _ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	error_code = _ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == _ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	return error_code;
}

GList* _account_query_account_by_package_name(sqlite3 *account_db_handle, const char* package_name, int *error_code, int pid, uid_t uid)
{
	_INFO("_account_query_account_by_package_name");

	*error_code = _ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;

	ACCOUNT_RETURN_VAL((package_name != NULL), {*error_code = _ACCOUNT_ERROR_INVALID_PARAMETER;}, NULL, ("PACKAGE NAME IS NULL"));
	ACCOUNT_RETURN_VAL((account_db_handle != NULL), {*error_code = _ACCOUNT_ERROR_DB_NOT_OPENED;}, NULL, ("The database isn't connected."));

	ACCOUNT_MEMSET(query, 0x00, ACCOUNT_SQL_LEN_MAX);

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT * FROM %s WHERE package_name=?", ACCOUNT_TABLE);

	hstmt = _account_prepare_query(account_db_handle, query);

	if( _account_db_err_code(account_db_handle) == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg(account_db_handle));
		*error_code = _ACCOUNT_ERROR_PERMISSION_DENIED;
		return NULL;
	}

	int binding_count = 1;
	_account_query_bind_text(hstmt, binding_count++, package_name);

	rc = _account_query_step(hstmt);

	account_s* account_head = NULL;

	ACCOUNT_CATCH_ERROR_P(rc == SQLITE_ROW, {}, _ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.(%s)\n", package_name));

	int tmp = 0;

	account_head = (account_s*) malloc(sizeof(account_s));
	if (account_head == NULL) {
		ACCOUNT_FATAL("malloc Failed");
		if (hstmt != NULL) {
			rc = _account_query_finalize(hstmt);
			ACCOUNT_RETURN_VAL((rc == _ACCOUNT_ERROR_NONE), {*error_code = rc;}, NULL, ("finalize error"));
			hstmt = NULL;
		}
		*error_code = _ACCOUNT_ERROR_OUT_OF_MEMORY;
		return NULL;
	}
	ACCOUNT_MEMSET(account_head, 0x00, sizeof(account_s));

	while (rc == SQLITE_ROW) {
		account_s* account_record = NULL;

		account_record = (account_s*) malloc(sizeof(account_s));

		if (account_record == NULL) {
			ACCOUNT_FATAL("malloc Failed");
			break;
		}
		ACCOUNT_MEMSET(account_record, 0x00, sizeof(account_s));

		_account_convert_column_to_account(hstmt, account_record);

		_INFO("Adding account_list");
		account_head->account_list = g_list_append(account_head->account_list, account_record);

		rc = _account_query_step(hstmt);
		tmp++;
	}

	rc = _account_query_finalize(hstmt);
	ACCOUNT_CATCH_ERROR_P((rc == _ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	GList *iter;

	tmp = g_list_length(account_head->account_list);

	for (iter = account_head->account_list; iter != NULL; iter = g_list_next(iter)) {
		account_s* testaccount = (account_s*)iter->data;

		_account_query_capability_by_account_id(account_db_handle, _account_add_capability_to_account_cb, testaccount->id, (void*)testaccount);
		_account_query_custom_by_account_id(account_db_handle, _account_add_custom_to_account_cb, testaccount->id, (void*)testaccount);
	}

	*error_code = _ACCOUNT_ERROR_NONE;

CATCH:
	if (hstmt != NULL)
	{
		rc = _account_query_finalize(hstmt);
		if (rc != _ACCOUNT_ERROR_NONE) {
			*error_code = rc;
			_ERR("finalize error");
		}
		hstmt = NULL;
	}

	if( (*error_code != _ACCOUNT_ERROR_NONE) && account_head ) {
		_account_glist_account_free(account_head->account_list);
		_ACCOUNT_FREE(account_head);
		account_head = NULL;
	}

	if ((*error_code == _ACCOUNT_ERROR_NONE) && account_head != NULL)
	{
		_INFO("Returning account_list");
		_remove_sensitive_info_from_non_owning_account_list(account_head->account_list, pid, uid);
		GList* result = account_head->account_list;
		_ACCOUNT_FREE(account_head);
		return result;
	}
	return NULL;
}

int _account_check_duplicated(sqlite3 *account_db_handle, account_s *data, const char* verified_appid, uid_t uid)
{
	char query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int count = 0;
	int ret = -1;

	ACCOUNT_MEMSET(query, 0x00, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "select count(*) from %s where package_name='%s' and (user_name='%s' or display_name='%s' or email_address='%s')"
			, ACCOUNT_TABLE, verified_appid, data->user_name, data->display_name, data->email_address);

	count = _account_get_record_count(account_db_handle, query);

	if (count<=0) {
		return _ACCOUNT_ERROR_NONE;
	}

	//check whether duplicated account or not.
	//1. check user_name
	//2. check display_name
	//3. check email_address
	GList* account_list_temp = _account_query_account_by_package_name(account_db_handle, verified_appid, &ret, getpid(), uid);
	if (account_list_temp == NULL)
	{
		_ERR("_account_query_account_by_package_name returned NULL");
		return _ACCOUNT_ERROR_DB_FAILED;
	}

	if( _account_db_err_code(account_db_handle) == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg(account_db_handle));
		return _ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if(ret != _ACCOUNT_ERROR_NONE){
		return ret;
	}

	account_list_temp = g_list_first(account_list_temp);
	_INFO("account_list_temp length=[%d]",g_list_length(account_list_temp));

	GList* iter = NULL;
	for (iter = account_list_temp; iter != NULL; iter = g_list_next(iter))
	{
		_INFO("iterating account_list_temp");
		account_s *account = NULL;
		_INFO("Before iter->data");
		account = (account_s*)iter->data;
		_INFO("After iter->data");
		if (account != NULL)
		{
			if(account->user_name!=NULL && data->user_name!=NULL && strcmp(account->user_name, data->user_name)==0)
			{
				_INFO("duplicated account(s) exist!, same user_name=%s", data->user_name);
				return _ACCOUNT_ERROR_DUPLICATED;
			}
			//when user_name is not NULL and display_name is same.
			if(account->user_name==NULL && data->user_name==NULL && account->display_name!=NULL && data->display_name!=NULL && strcmp(account->display_name, data->display_name)==0)
			{
				_INFO("duplicated account(s) exist!, same display_name=%s", data->display_name);
				return _ACCOUNT_ERROR_DUPLICATED;
			}
			//when user_name and display_name are not NULL and email_address is same.
			if(account->user_name==NULL && data->user_name==NULL && account->display_name==NULL && data->display_name==NULL && account->email_address!=NULL && data->email_address!=NULL && strcmp(account->email_address, data->email_address)==0)
			{
				_INFO("duplicated account(s) exist!, same email_address=%s", data->email_address);
				return _ACCOUNT_ERROR_DUPLICATED;
			}
		}
	}

	return _ACCOUNT_ERROR_NONE;
}



int _account_delete_account_by_package_name(sqlite3 *account_db_handle, const char *package_name, gboolean permission, int pid, uid_t uid)
{
	_INFO("_account_delete_account_by_package_name");
	int 			error_code = _ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0;
	int 			ret_transaction = 0;
	bool			is_success = FALSE;
	int 			binding_count = 1;
	GSList			*account_id_list = NULL;
	int				ret = -1;

	ACCOUNT_RETURN_VAL((account_db_handle != NULL), {}, _ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));
	ACCOUNT_RETURN_VAL((package_name != NULL), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("package_name is null!"));

	// It only needs list of ids, does not need to query sensitive info. So sending 0
	GList* account_list_temp = _account_query_account_by_package_name(account_db_handle, package_name, &ret, pid, uid);
	if( _account_db_err_code(account_db_handle) == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg(account_db_handle));
		return _ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if(ret != _ACCOUNT_ERROR_NONE){
		_ERR("_account_query_account_by_package_name failed ret=[%d]", ret);
		return ret;
	}

	if (account_list_temp == NULL)
	{
		_ERR("_account_query_account_by_package_name returned NULL");
		return _ACCOUNT_ERROR_DB_FAILED;
	}

	// Check permission of requested appid
	if(permission){
		char* current_appid = NULL;
		char* package_name_temp = NULL;

		current_appid = _account_get_current_appid(pid, uid);

		package_name_temp = _account_dup_text(package_name);
		if (package_name_temp == NULL) {
			ACCOUNT_FATAL("Memory Allocation Failed");
			return _ACCOUNT_ERROR_OUT_OF_MEMORY;
		}

		ACCOUNT_DEBUG( "DELETE: current_appid[%s], package_name[%s]", current_appid, package_name_temp);

		error_code = _account_check_appid_group_with_package_name(current_appid, package_name_temp, uid);

		_ACCOUNT_FREE(current_appid);
		_ACCOUNT_FREE(package_name_temp);

		if(error_code != _ACCOUNT_ERROR_NONE){
			ACCOUNT_ERROR("No permission to delete\n");
			_account_glist_account_free(account_list_temp);
			return _ACCOUNT_ERROR_PERMISSION_DENIED;
		}
	}

	GList *account_list = g_list_first(account_list_temp);
	_INFO("account_list_temp length=[%d]",g_list_length(account_list));

	GList* iter = NULL;
	for (iter = account_list; iter != NULL; iter = g_list_next(iter))
	{
		_INFO("iterating account_list");
		account_s *account = NULL;
		_INFO("Before iter->data");
		account = (account_s*)iter->data;
		_INFO("After iter->data");
		if (account != NULL)
		{
			char id[256] = {0, };

			ACCOUNT_MEMSET(id, 0, 256);

			ACCOUNT_SNPRINTF(id, 256, "%d", account->id);

			_INFO("Adding account id [%s]", id);
			account_id_list = g_slist_append(account_id_list, g_strdup(id));
		}
	}

	_account_glist_account_free(account_list_temp);

	// transaction control required
	ret_transaction = _account_begin_transaction(account_db_handle);
	_INFO("after _account_begin_trasaction");

	if( _account_db_err_code(account_db_handle) == SQLITE_PERM ){
//		pthread_mutex_unlock(&account_mutex);
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg(account_db_handle));
		return _ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if( ret_transaction == _ACCOUNT_ERROR_DATABASE_BUSY ){
		ACCOUNT_ERROR( "database busy(%s)", _account_db_err_msg(account_db_handle));
//		pthread_mutex_unlock(&account_mutex);
		return _ACCOUNT_ERROR_DATABASE_BUSY;
	}else if (ret_transaction != _ACCOUNT_ERROR_NONE) {
		ACCOUNT_ERROR("account_delete:_account_begin_transaction fail %d\n", ret_transaction);
//		pthread_mutex_unlock(&account_mutex);
		return ret_transaction;
	}

	_INFO("start delete custom table");
	// delete custom table
	ACCOUNT_MEMSET(query, 0, sizeof(query));
	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE AppId = ?", ACCOUNT_CUSTOM_TABLE);

	hstmt = _account_prepare_query(account_db_handle, query);

	if( _account_db_err_code(account_db_handle) == SQLITE_PERM ){
		_account_end_transaction(account_db_handle, false);
//		pthread_mutex_unlock(&account_mutex);
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg(account_db_handle));
		return _ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, _ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg(account_db_handle)));

	binding_count = 1;
	_account_query_bind_text(hstmt, binding_count++, package_name);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, _ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == _ACCOUNT_ERROR_NONE), {_account_end_transaction(account_db_handle, false);}, rc, ("finalize error"));
	hstmt = NULL;

	_INFO("start delete capability table");
	// delete capability table
	ACCOUNT_MEMSET(query, 0, sizeof(query));
	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE package_name = ?", CAPABILITY_TABLE);

	hstmt = _account_prepare_query(account_db_handle, query);

	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, _ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg(account_db_handle)));

	binding_count = 1;
	_account_query_bind_text(hstmt, binding_count++, package_name);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, _ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == _ACCOUNT_ERROR_NONE), {_account_end_transaction(account_db_handle, false);}, rc, ("finalize error"));
	hstmt = NULL;

	_INFO("start delete account table");
	// delete account table
	ACCOUNT_MEMSET(query, 0, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE package_name = ?", ACCOUNT_TABLE);

	hstmt = _account_prepare_query(account_db_handle, query);
	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, _ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg(account_db_handle)));

	binding_count = 1;
	_account_query_bind_text(hstmt, binding_count++, package_name);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, _ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found. package_name=%s, rc=%d\n", package_name, rc));

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == _ACCOUNT_ERROR_NONE), {_account_end_transaction(account_db_handle, false);}, rc, ("finalize error"));
	is_success = TRUE;

	hstmt = NULL;

CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == _ACCOUNT_ERROR_NONE), {_account_end_transaction(account_db_handle, false);}, rc, ("finalize error"));
		hstmt = NULL;
	}

	ret_transaction = _account_end_transaction(account_db_handle, is_success);

	if (ret_transaction != _ACCOUNT_ERROR_NONE) {
		ACCOUNT_ERROR("account_delete:_account_end_transaction fail %d, is_success=%d\n", ret_transaction, is_success);
	} else {
		if (is_success == true) {
			GSList* gs_iter = NULL;
			for (gs_iter = account_id_list; gs_iter != NULL; gs_iter = g_slist_next(gs_iter)) {
				char* p_tmpid = NULL;
				p_tmpid = (char*)gs_iter->data;
//				char buf[64]={0,};
//				ACCOUNT_SNPRINTF(buf, sizeof(buf), "%s:%s", ACCOUNT_NOTI_NAME_DELETE, p_tmpid);
//				ACCOUNT_SLOGD("%s", buf);
//				_account_insert_delete_update_notification_send(buf);
				_ACCOUNT_FREE(p_tmpid);
			}
			g_slist_free(account_id_list);
		}
	}

//	pthread_mutex_unlock(&account_mutex);

	_INFO("_account_delete_account_by_package_name end");
	return error_code;
}



int _account_type_convert_account_to_sql(account_type_s *account_type, account_stmt hstmt, char *sql_value)
{
	_INFO("");

	int count = 1;

	// Caution : Keep insert query orders.

	_account_query_bind_text(hstmt, count++, (char*)account_type->app_id);

	_account_query_bind_text(hstmt, count++, (char*)account_type->service_provider_id);

	_account_query_bind_text(hstmt, count++, (char*)account_type->icon_path);

	_account_query_bind_text(hstmt, count++, (char*)account_type->small_icon_path);

	_account_query_bind_int(hstmt, count++, account_type->multiple_account_support);

	_INFO("");

	return count;
}

void _account_type_convert_column_to_provider_feature(account_stmt hstmt, provider_feature_s *feature_record)
{
	const char *textbuf = NULL;

	textbuf = _account_query_table_column_text(hstmt, PROVIDER_FEATURE_FIELD_APP_ID);
	_account_db_data_to_text(textbuf, &(feature_record->app_id));

	textbuf = _account_query_table_column_text(hstmt, PROVIDER_FEATURE_FIELD_KEY);
	_account_db_data_to_text(textbuf, &(feature_record->key));

}

void _account_type_convert_column_to_label(account_stmt hstmt, label_s *label_record)
{
	const char *textbuf = NULL;

	textbuf = _account_query_table_column_text(hstmt, LABEL_FIELD_APP_ID);
	_account_db_data_to_text(textbuf, &(label_record->app_id));

	textbuf = _account_query_table_column_text(hstmt, LABEL_FIELD_LABEL);
	_account_db_data_to_text(textbuf, &(label_record->label));

	textbuf = _account_query_table_column_text(hstmt, LABEL_FIELD_LOCALE);
	_account_db_data_to_text(textbuf, &(label_record->locale));

}

void _account_type_convert_column_to_account_type(account_stmt hstmt, account_type_s *account_type_record)
{
	const char *textbuf = NULL;

	account_type_record->id = _account_query_table_column_int(hstmt, ACCOUNT_TYPE_FIELD_ID);

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_TYPE_FIELD_APP_ID);
	_account_db_data_to_text(textbuf, &(account_type_record->app_id));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_TYPE_FIELD_SERVICE_PROVIDER_ID);
	_account_db_data_to_text(textbuf, &(account_type_record->service_provider_id));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_TYPE_FIELD_ICON_PATH);
	_account_db_data_to_text(textbuf, &(account_type_record->icon_path));

	textbuf = _account_query_table_column_text(hstmt, ACCOUNT_TYPE_FIELD_SMALL_ICON_PATH);
	_account_db_data_to_text(textbuf, &(account_type_record->small_icon_path));

	account_type_record->multiple_account_support = _account_query_table_column_int(hstmt, ACCOUNT_TYPE_FIELD_MULTIPLE_ACCOUNT_SUPPORT);

}


gboolean _account_type_check_duplicated(sqlite3 * account_db_handle, const char *app_id)
{
	char query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int count = 0;

	ACCOUNT_RETURN_VAL((account_db_handle != NULL), {}, _ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));
	ACCOUNT_RETURN_VAL((app_id != NULL), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("app_id is NULL."));
	ACCOUNT_MEMSET(query, 0x00, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) FROM %s WHERE AppId='%s'"
			, ACCOUNT_TYPE_TABLE, app_id);

	count = _account_get_record_count(account_db_handle, query);
	if (count > 0) {
		_INFO("query=[%s]", query);
		return true;
	}

	return false;
}

static int _account_type_execute_insert_query(sqlite3 *account_db_handle, account_type_s *account_type)
{
	_INFO("");

	int				rc = 0;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int				error_code = _ACCOUNT_ERROR_NONE;
	account_stmt 	hstmt = NULL;

	// check mandatory field
	// app id & service provider id
	if (!account_type->app_id) {
		return _ACCOUNT_ERROR_INVALID_PARAMETER;
	}

	ACCOUNT_MEMSET(query, 0x00, sizeof(query));
	ACCOUNT_SNPRINTF(query, sizeof(query), "INSERT INTO %s( AppId, ServiceProviderId , IconPath , SmallIconPath , MultipleAccountSupport ) values "
			"(?, ?, ?, ?, ?)",	ACCOUNT_TYPE_TABLE);

	_INFO("");
	hstmt = _account_prepare_query(account_db_handle, query);
	_INFO("");

	if( _account_db_err_code(account_db_handle) == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg(account_db_handle));
		return _ACCOUNT_ERROR_PERMISSION_DENIED;
	} else if( _account_db_err_code(account_db_handle) == SQLITE_BUSY ){
		ACCOUNT_ERROR( "Database Busy(%s)", _account_db_err_msg(account_db_handle));
		return _ACCOUNT_ERROR_DATABASE_BUSY;
	}

	ACCOUNT_RETURN_VAL((hstmt != NULL), {}, _ACCOUNT_ERROR_DB_FAILED, ("_account_prepare_query() failed(%s).\n", _account_db_err_msg(account_db_handle)));

	_INFO("");
	_account_type_convert_account_to_sql(account_type, hstmt, query);
	_INFO("");

	rc = _account_query_step(hstmt);
	if (rc == SQLITE_BUSY) {
		ACCOUNT_ERROR( "account_db_query_step() failed(%d, %s)", rc, _account_db_err_msg(account_db_handle));
		error_code = _ACCOUNT_ERROR_DATABASE_BUSY;
	} else if (rc != SQLITE_DONE) {
		ACCOUNT_ERROR( "account_db_query_step() failed(%d, %s)", rc, _account_db_err_msg(account_db_handle));
		error_code = _ACCOUNT_ERROR_DB_FAILED;
	}

	_INFO("");
	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == _ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	_INFO("");
	return error_code;
}

static int _account_type_insert_label(sqlite3 *account_db_handle, account_type_s *account_type)
{
	int 			rc, count = 1;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	account_stmt 	hstmt = NULL;

	ACCOUNT_RETURN_VAL((account_type != NULL), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT HANDLE IS NULL"));

	if (g_slist_length( account_type->label_list)==0) {
		ACCOUNT_ERROR( "_account_type_insert_label, no label\n");
		return _ACCOUNT_ERROR_NONE;
	}

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) from %s where AppId = '%s'", ACCOUNT_TYPE_TABLE, account_type->app_id);

	rc = _account_get_record_count(account_db_handle, query);

	if( _account_db_err_code(account_db_handle) == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg(account_db_handle));
		return _ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if (rc <= 0) {
		return _ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	GSList *iter;

	for (iter = account_type->label_list; iter != NULL; iter = g_slist_next(iter)) {
		int ret;
		count = 1;
		ACCOUNT_MEMSET(query, 0x00, sizeof(query));
		ACCOUNT_SNPRINTF(query, sizeof(query), "INSERT INTO %s(AppId, Label, Locale) VALUES "
				"(?, ?, ?) ", LABEL_TABLE);

		hstmt = _account_prepare_query(account_db_handle, query);

		ACCOUNT_RETURN_VAL((hstmt != NULL), {}, _ACCOUNT_ERROR_DB_FAILED, ("_account_prepare_query() failed(%s).\n", _account_db_err_msg(account_db_handle)));

		label_s* label_data = NULL;
		label_data = (label_s*)iter->data;

		ret = _account_query_bind_text(hstmt, count++, account_type->app_id);
		ACCOUNT_RETURN_VAL((ret == _ACCOUNT_ERROR_NONE), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_text(hstmt, count++, label_data->label);
		ACCOUNT_RETURN_VAL((ret == _ACCOUNT_ERROR_NONE), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_text(hstmt, count++, (char*)label_data->locale);
		ACCOUNT_RETURN_VAL((ret == _ACCOUNT_ERROR_NONE), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));

		rc = _account_query_step(hstmt);

		if (rc != SQLITE_DONE) {
			ACCOUNT_ERROR( "_account_query_step() failed(%d, %s)", rc, _account_db_err_msg(account_db_handle));
			break;
		}

		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == _ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;

	}

	return _ACCOUNT_ERROR_NONE;
}

static int _account_type_insert_provider_feature(sqlite3 * account_db_handle, account_type_s *account_type, const char* app_id)
{
	int 			rc, count = 1;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	account_stmt 	hstmt = NULL;

	ACCOUNT_RETURN_VAL((account_type != NULL), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT HANDLE IS NULL"));
	ACCOUNT_RETURN_VAL((app_id != NULL), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("APP ID IS NULL"));

	if (g_slist_length( account_type->provider_feature_list)==0) {
		ACCOUNT_ERROR( "no capability\n");
		return _ACCOUNT_ERROR_NONE;
	}

	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) from %s where AppId='%s'", ACCOUNT_TYPE_TABLE, app_id);

	rc = _account_get_record_count(account_db_handle, query);

	if( _account_db_err_code(account_db_handle) == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg(account_db_handle));
		return _ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if (rc <= 0) {
		ACCOUNT_SLOGI( "related account type item is not existed rc=%d , %s", rc, _account_db_err_msg(account_db_handle));
		return _ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	GSList *iter;

	for (iter = account_type->provider_feature_list; iter != NULL; iter = g_slist_next(iter)) {
		int ret;
		count = 1;
		ACCOUNT_MEMSET(query, 0x00, sizeof(query));
		ACCOUNT_SNPRINTF(query, sizeof(query), "INSERT INTO %s(app_id, key) VALUES "
				"(?, ?) ", PROVIDER_FEATURE_TABLE);

		hstmt = _account_prepare_query(account_db_handle, query);

		ACCOUNT_RETURN_VAL((hstmt != NULL), {}, _ACCOUNT_ERROR_DB_FAILED, ("_account_prepare_query() failed(%s).\n", _account_db_err_msg(account_db_handle)));

		provider_feature_s* feature_data = NULL;
		feature_data = (provider_feature_s*)iter->data;

		ret = _account_query_bind_text(hstmt, count++, app_id);
		ACCOUNT_RETURN_VAL((ret == _ACCOUNT_ERROR_NONE), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("Text binding fail"));
		ret = _account_query_bind_text(hstmt, count++, feature_data->key);
		ACCOUNT_RETURN_VAL((ret == _ACCOUNT_ERROR_NONE), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("Integer binding fail"));

		rc = _account_query_step(hstmt);

		if (rc != SQLITE_DONE) {
			ACCOUNT_ERROR( "_account_query_step() failed(%d, %s)", rc, _account_db_err_msg(account_db_handle));
			break;
		}

		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == _ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;

	}

	return _ACCOUNT_ERROR_NONE;
}

int _account_type_insert_to_db(sqlite3 *account_db_handle, account_type_s* account_type, int* account_type_id)
{
	_INFO("");

	int error_code = _ACCOUNT_ERROR_NONE;
//	int ret_transaction = 0;

	ACCOUNT_RETURN_VAL((account_type != NULL), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT TYPE HANDLE IS NULL"));
	ACCOUNT_RETURN_VAL((account_type->app_id != NULL), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("APP ID OF ACCOUNT TYPE IS NULL"));
	ACCOUNT_RETURN_VAL((account_type_id != NULL), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("ACCOUNT TYPE ID POINTER IS NULL"));

//	account_type_s *data = (account_type_s*)account_type;

//	pthread_mutex_lock(&account_mutex);


	// transaction control required
//	ret_transaction = _account_begin_transaction(account_db_handle);

//	_INFO("");

//	if( _account_db_err_code(account_db_handle) == SQLITE_PERM ){
//		pthread_mutex_unlock(&account_mutex);
//		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg(account_db_handle));
//		return _ACCOUNT_ERROR_PERMISSION_DENIED;
//	}

//	_INFO("");
//	if( ret_transaction == _ACCOUNT_ERROR_DATABASE_BUSY ){
//		ACCOUNT_ERROR( "database busy(%s)", _account_db_err_msg(account_db_handle));
//		pthread_mutex_unlock(&account_mutex);
//		return _ACCOUNT_ERROR_DATABASE_BUSY;
//	} else if (ret_transaction != _ACCOUNT_ERROR_NONE) {
//		ACCOUNT_ERROR("_account_begin_transaction fail %d\n", ret_transaction);
//		pthread_mutex_unlock(&account_mutex);
//		return ret_transaction;
//	}

	_INFO("");
	*account_type_id = _account_get_next_sequence(account_db_handle, ACCOUNT_TYPE_TABLE);

	error_code = _account_type_execute_insert_query(account_db_handle, account_type);

	if (error_code != _ACCOUNT_ERROR_NONE){
		error_code = _ACCOUNT_ERROR_DUPLICATED;
//		ret_transaction = _account_end_transaction(account_db_handle, FALSE);
//		ACCOUNT_ERROR("Insert fail, rollback insert query(%x)!!!!\n", ret_transaction);
		*account_type_id = -1;
//		pthread_mutex_unlock(&account_mutex);
		return error_code;
	}

	_INFO("");
	error_code = _account_type_insert_provider_feature(account_db_handle, account_type, account_type->app_id);
	if(error_code != _ACCOUNT_ERROR_NONE) {
//		_INFO("");
//		ret_transaction = _account_end_transaction(account_db_handle, FALSE);
//		ACCOUNT_ERROR("Insert provider feature fail(%x), rollback insert query(%x)!!!!\n", error_code, ret_transaction);
//		pthread_mutex_unlock(&account_mutex);
		return error_code;
	}
	_INFO("");
	error_code = _account_type_insert_label(account_db_handle, account_type);
	if(error_code != _ACCOUNT_ERROR_NONE) {
		_INFO("");
//		ret_transaction = _account_end_transaction(account_db_handle, FALSE);
//		ACCOUNT_ERROR("Insert label fail(%x), rollback insert query(%x)!!!!\n", error_code, ret_transaction);
//		pthread_mutex_unlock(&account_mutex);
		return error_code;
	}

//	ret_transaction = _account_end_transaction(account_db_handle, TRUE);
//	_INFO("");
//	pthread_mutex_unlock(&account_mutex);

	_INFO("");
	return _ACCOUNT_ERROR_NONE;
}


int _account_type_delete_by_app_id(sqlite3 * account_db_handle, const char* app_id)
{
	int 			error_code = _ACCOUNT_ERROR_NONE;
	account_stmt	hstmt = NULL;
	char			query[ACCOUNT_SQL_LEN_MAX] = {0, };
	int 			rc = 0, count = -1;
	int 			ret_transaction = 0;
	int				binding_count = 1;
	bool			is_success = FALSE;

	ACCOUNT_RETURN_VAL((account_db_handle != NULL), {}, _ACCOUNT_ERROR_DB_NOT_OPENED, ("The database isn't connected."));
	ACCOUNT_RETURN_VAL((app_id != NULL), {}, _ACCOUNT_ERROR_INVALID_PARAMETER, ("The database isn't connected."));

	// Check requested ID to delete
	ACCOUNT_SNPRINTF(query, sizeof(query), "SELECT COUNT(*) FROM %s WHERE AppId = '%s'", ACCOUNT_TYPE_TABLE, app_id);

	count = _account_get_record_count(account_db_handle, query);

	if( _account_db_err_code(account_db_handle) == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg(account_db_handle));
		return _ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	if (count <= 0) {
		ACCOUNT_SLOGE("app id(%s) is not exist. count(%d)\n", app_id, count);
		return _ACCOUNT_ERROR_RECORD_NOT_FOUND;
	}

	// transaction control required
	ret_transaction = _account_begin_transaction(account_db_handle);

	if( ret_transaction == _ACCOUNT_ERROR_DATABASE_BUSY ){
		ACCOUNT_ERROR( "database busy(%s)", _account_db_err_msg(account_db_handle));
//		pthread_mutex_unlock(&account_mutex);
		return _ACCOUNT_ERROR_DATABASE_BUSY;
	}else if (ret_transaction != _ACCOUNT_ERROR_NONE) {
		ACCOUNT_ERROR("account_delete:_account_begin_transaction fail %d\n", ret_transaction);
//		pthread_mutex_unlock(&account_mutex);
		return ret_transaction;
	}

	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE AppId = ?", LABEL_TABLE);

	hstmt = _account_prepare_query(account_db_handle, query);

	if( _account_db_err_code(account_db_handle) == SQLITE_PERM ){
		ACCOUNT_ERROR( "Access failed(%s)", _account_db_err_msg(account_db_handle));
//		pthread_mutex_unlock(&account_mutex);
		return _ACCOUNT_ERROR_PERMISSION_DENIED;
	}

	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, _ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg(account_db_handle)));

	_account_query_bind_text(hstmt, binding_count++, app_id);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, _ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found.\n"));

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == _ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	hstmt = NULL;

	binding_count = 1;
	ACCOUNT_MEMSET(query, 0, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE app_id = ? ", PROVIDER_FEATURE_TABLE);

	hstmt = _account_prepare_query(account_db_handle, query);
	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, _ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg(account_db_handle)));

	_account_query_bind_text(hstmt, binding_count++, app_id);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, _ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found. AppId=%s, rc=%d\n", app_id, rc));

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == _ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	is_success = TRUE;

	hstmt = NULL;

	binding_count = 1;
	ACCOUNT_MEMSET(query, 0, sizeof(query));

	ACCOUNT_SNPRINTF(query, sizeof(query), "DELETE FROM %s WHERE AppId = ? ", ACCOUNT_TYPE_TABLE);

	hstmt = _account_prepare_query(account_db_handle, query);
	ACCOUNT_CATCH_ERROR(hstmt != NULL, {}, _ACCOUNT_ERROR_DB_FAILED,
			("_account_svc_query_prepare(%s) failed(%s).\n", query, _account_db_err_msg(account_db_handle)));

	_account_query_bind_text(hstmt, binding_count++, app_id);

	rc = _account_query_step(hstmt);
	ACCOUNT_CATCH_ERROR(rc == SQLITE_DONE, {}, _ACCOUNT_ERROR_RECORD_NOT_FOUND, ("The record isn't found. AppId=%s, rc=%d\n", app_id, rc));

	rc = _account_query_finalize(hstmt);
	ACCOUNT_RETURN_VAL((rc == _ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
	is_success = TRUE;

	hstmt = NULL;

	CATCH:
	if (hstmt != NULL) {
		rc = _account_query_finalize(hstmt);
		ACCOUNT_RETURN_VAL((rc == _ACCOUNT_ERROR_NONE), {}, rc, ("finalize error"));
		hstmt = NULL;
	}

	ret_transaction = _account_end_transaction(account_db_handle, is_success);

	if (ret_transaction != _ACCOUNT_ERROR_NONE) {
		ACCOUNT_ERROR("account_svc_delete:_account_svc_end_transaction fail %d, is_success=%d\n", ret_transaction, is_success);
	}

//	pthread_mutex_unlock(&account_mutex);

	return error_code;
}
