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

#include <glib.h>
#include <db-util.h>
#include <pkgmgr-info.h>
#include <tzplatform_config.h>

#include "account-private.h"

/* ACCOUNT_TABLE */
#define ACCOUNT_SCHEMA  "create table account \n"\
	    "(\n"\
"_id INTEGER PRIMARY KEY AUTOINCREMENT, "\
"user_name TEXT, "\
"email_address TEXT, "\
"display_name TEXT, "\
"icon_path TEXT, "\
"source TEXT, "\
"package_name TEXT, "\
"access_token TEXT, "\
"domain_name TEXT, "\
"auth_type INTEGER, "\
"secret INTEGER, "\
"sync_support INTEGER, "\
"txt_custom0 TEXT, "\
"txt_custom1 TEXT, "\
"txt_custom2 TEXT, "\
"txt_custom3 TEXT, "\
"txt_custom4 TEXT, "\
"int_custom0 INTEGER, "\
"int_custom1 INTEGER, "\
"int_custom2 INTEGER, "\
"int_custom3 INTEGER, "\
"int_custom4 INTEGER "\
");"

/* CAPABILITY_TABLE */
#define CAPABILITY_SCHEMA  "create table capability \n"\
	    "(\n"\
"_id INTEGER PRIMARY KEY AUTOINCREMENT, "\
"key TEXT, "\
"value INTEGER, "\
"package_name TEXT, "\
"user_name TEXT, "\
"account_id INTEGER, "\
"FOREIGN KEY (account_id) REFERENCES account(_id) "\
");"

/* ACCOUNT_CUSTOM_TABLE */
#define ACCOUNT_CUSTOM_SCHEMA  "create table account_custom \n"\
	    "(\n"\
"AccountId INTEGER, "\
"AppId TEXT, "\
"Key TEXT, "\
"Value TEXT "\
");"

/* ACCOUNT_TYPE_TABLE */
#define ACCOUNT_TYPE_SCHEMA "create table account_type \n"\
	    "(\n"\
"_id INTEGER PRIMARY KEY AUTOINCREMENT, "\
"AppId TEXT, "\
"ServiceProviderId TEXT, "\
"IconPath TEXT, "\
"SmallIconPath TEXT, "\
"MultipleAccountSupport INTEGER "\
");"

/* LABEL_TABLE */
#define LABEL_SCHEMA "create table label \n"\
	    "(\n"\
"AppId TEXT, "\
"Label TEXT, "\
"Locale TEXT"\
");"

/* PROVIDER_FEATURE_TABLE */
#define PROVIDER_FEATURE_SCHEMA "create table provider_feature \n"\
	    "(\n"\
"app_id TEXT, "\
"key TEXT "\
");"

#define OWNER_ROOT 0
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

#define ACCOUNT_GET_USER_DB_DIR(dest, size, uid) \
	    do { \
			snprintf(dest, size-1, "%s%d", tzplatform_mkpath(TZ_SYS_DB, "/"), uid); \
		} while (0)
#define ACCOUNT_GET_GLOBAL_DB_PATH(dest, size) \
	    do { \
			snprintf(dest, size-1, "%s", tzplatform_mkpath(TZ_SYS_DB, "/.account.db")); \
		} while (0)
#define ACCOUNT_GET_GLOBAL_JN_PATH(dest, size) \
	    do { \
			snprintf(dest, size-1, "%s", tzplatform_mkpath(TZ_SYS_DB, "/.account.db-journal")); \
		} while (0)
#define ACCOUNT_GET_USER_DB_PATH(dest, size, uid) \
	    do { \
			snprintf(dest, size-1, "%s%d%s", tzplatform_mkpath(TZ_SYS_DB, "/"), uid, "/.account.db"); \
		} while (0)
#define ACCOUNT_GET_USER_JN_PATH(dest, size, uid) \
	    do { \
			snprintf(dest, size-1, "%s%d%s", tzplatform_mkpath(TZ_SYS_DB, "/"), uid, "/.account.db-journal"); \
		} while (0)
#define ACCOUNT_TABLE "account"
#define CAPABILITY_TABLE "capability"
#define ACCOUNT_CUSTOM_TABLE "account_custom"
#define ACCOUNT_TYPE_TABLE "account_type"
#define LABEL_TABLE "label"
#define PROVIDER_FEATURE_TABLE "provider_feature"
#define ACCOUNT_SQLITE_SEQ "sqlite_sequence"
#define ACCOUNT_SQL_LEN_MAX     1024
#define ACCOUNT_TABLE_TOTAL_COUNT   6


typedef sqlite3_stmt * account_stmt;
typedef bool (*account_add_capability_cb)(const char *capability_type, int capability_state, account_s *account);
typedef bool (*account_add_custom_cb)(const char *key, const char *value, account_s *account);

char *_account_dup_text(const char *text_data);

char *_account_get_current_appid(int pid, uid_t uid);

int _remove_sensitive_info_from_non_owning_account(account_s *account, int caller_pid, uid_t uid);
int _remove_sensitive_info_from_non_owning_account_list(GList *account_list, int caller_pid, uid_t uid);
int _remove_sensitive_info_from_non_owning_account_slist(GSList *account_list, int caller_pid, uid_t uid);


const char *_account_db_err_msg(sqlite3 *account_db_handle);
int _account_db_err_code(sqlite3 *account_db_handle);
int _account_execute_query(sqlite3 *account_db_handle, const char *query);
int _account_begin_transaction(sqlite3 *account_db_handle);
int _account_end_transaction(sqlite3 *account_db_handle, bool is_success);
int _account_get_next_sequence(sqlite3 *account_db_handle, const char *pszName);
account_stmt _account_prepare_query(sqlite3 *account_db_handle, char *query);

int _account_query_bind_int(account_stmt pStmt, int pos, int num);
int _account_query_bind_text(account_stmt pStmt, int pos, const char *str);
int _account_query_finalize(account_stmt pStmt);
int _account_query_step(account_stmt pStmt);

int _account_convert_account_to_sql(account_s *account, account_stmt hstmt, char *sql_value);
void _account_convert_column_to_account(account_stmt hstmt, account_s *account_record);
void _account_convert_column_to_capability(account_stmt hstmt, account_capability_s *capability_record);
void _account_convert_column_to_custom(account_stmt hstmt, account_custom_s *custom_record);


int _account_get_record_count(sqlite3 *account_db_handle, const char *query);
int _account_create_all_tables(sqlite3 *account_db_handle);
int _account_check_is_all_table_exists(sqlite3 *account_db_handle);
int _account_db_handle_close(sqlite3 *account_db_handle);


int _account_type_query_app_id_exist_from_all_db(sqlite3 *account_user_db, sqlite3 *account_global_db, const char *app_id);
int _account_get_represented_appid_from_db(sqlite3 *account_user_db, sqlite3 *account_global_db, const char *appid, uid_t uid, char **verified_appid);
int _account_check_appid_group_with_package_name(const char *appid, char *package_name, uid_t uid);

int _account_query_capability_by_account_id(sqlite3 *account_db_handle, account_add_capability_cb callback, int account_id, void *user_data);
int _account_query_custom_by_account_id(sqlite3 *account_db_handle, account_add_custom_cb callback, int account_id, void *user_data);
GList *_account_query_account_by_package_name(sqlite3 *account_db_handle, const char *package_name, int *error_code, int pid, uid_t uid);

int _account_check_duplicated(sqlite3 *account_db_handle, account_s *data, const char *verified_appid, uid_t uid);

int _account_delete_account_by_package_name(sqlite3 *account_db_handle, const char *package_name, gboolean permission, int pid, uid_t uid);


int _account_type_convert_account_to_sql(account_type_s *account_type, account_stmt hstmt, char *sql_value);
void _account_type_convert_column_to_provider_feature(account_stmt hstmt, provider_feature_s *feature_record);
void _account_type_convert_column_to_label(account_stmt hstmt, label_s *label_record);
void _account_type_convert_column_to_account_type(account_stmt hstmt, account_type_s *account_type_record);

gboolean _account_type_check_duplicated(sqlite3 *account_db_handle, const char *app_id);
int _account_type_insert_to_db(sqlite3 *account_db_handle, account_type_s *account_type, int *account_type_id);
int _account_type_delete_by_app_id(sqlite3 *account_db_handle, const char *app_id);
