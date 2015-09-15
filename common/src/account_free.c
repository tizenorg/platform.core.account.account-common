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

#include "account-private.h"
#include "dbg.h"
#include "account_free.h"

int _account_glist_account_free(GList* list)
{
	if(!list){
		return -1;
	}

	GList* iter;

	for (iter = list; iter != NULL; iter = g_list_next(iter)) {
		account_s *account_record = (account_s*)iter->data;
		_account_free_account_with_items(account_record);
	}

	g_list_free(list);
	list = NULL;

	return 0;
}

int _account_gslist_account_free(GSList *list)
{
	if(!list){
		return -1;
	}

	GSList* iter;

	for (iter = list; iter != NULL; iter = g_slist_next(iter)) {
		account_s *account_data = (account_s*)iter->data;
		_account_free_account_with_items(account_data);
	}

	g_slist_free(list);
	list = NULL;

	return 0;
}

int _account_gslist_capability_free(GSList* list)
{
	if(!list){
		return -1;
	}

	GSList* iter;

	for (iter = list; iter != NULL; iter = g_slist_next(iter)) {
		account_capability_s *cap_data = (account_capability_s*)iter->data;
		_account_free_capability_with_items(cap_data);
	}

	g_slist_free(list);
	list = NULL;

	return 0;
}

int _account_gslist_custom_free(GSList* list)
{
	if(!list){
		return -1;
	}

	GSList* iter;

	for (iter = list; iter != NULL; iter = g_slist_next(iter)) {
		account_custom_s *custom_data = (account_custom_s*)iter->data;
		_account_free_custom_with_items(custom_data);
	}

	g_slist_free(list);
	list = NULL;

	return 0;
}

int _account_free_capability_with_items(account_capability_s *data)
{
	if(!data)
		return -1;

	_ACCOUNT_FREE(data->type);
	_ACCOUNT_FREE(data->package_name);
	_ACCOUNT_FREE(data->user_name);

	_ACCOUNT_FREE(data);

	return 0;
}

int _account_free_custom_with_items(account_custom_s *data)
{
	if(!data)
		return -1;

	_ACCOUNT_FREE(data->app_id);
	_ACCOUNT_FREE(data->key);
	_ACCOUNT_FREE(data->value);

	_ACCOUNT_FREE(data);

	return 0;
}

int _account_free_account_with_items(account_s *data)
{
	if(!data)
		return -1;

	_ACCOUNT_FREE(data->user_name);
	_ACCOUNT_FREE(data->email_address);
	_ACCOUNT_FREE(data->display_name);
	_ACCOUNT_FREE(data->icon_path);
	_ACCOUNT_FREE(data->source);
	_ACCOUNT_FREE(data->package_name);
	_ACCOUNT_FREE(data->domain_name);
	_ACCOUNT_FREE(data->access_token);

	int i;
	for(i=0;i<USER_TXT_CNT;i++)
		_ACCOUNT_FREE(data->user_data_txt[i]);

	_account_gslist_capability_free(data->capablity_list);
	_account_glist_account_free(data->account_list);
	_account_gslist_custom_free(data->custom_list);

	_ACCOUNT_FREE(data);

	return 0;
}

int _account_type_free_label_with_items(label_s *data)
{
	if(!data)
		return -1;

	_ACCOUNT_FREE(data->app_id);
	_ACCOUNT_FREE(data->label);
	_ACCOUNT_FREE(data->locale);

	_ACCOUNT_FREE(data);

	return 0;
}

int _account_type_free_feature_with_items(provider_feature_s *data)
{
	if(!data)
		return -1;

	_ACCOUNT_FREE(data->app_id);
	_ACCOUNT_FREE(data->key);

	_ACCOUNT_FREE(data);
	return 0;
}

int _account_type_gslist_feature_free(GSList* list)
{
	if(!list)
		return -1;

	GSList* iter;

	for (iter = list; iter != NULL; iter = g_slist_next(iter)) {
		provider_feature_s *feature_data = (provider_feature_s*)iter->data;
		_account_type_free_feature_with_items(feature_data);
	}

	g_slist_free(list);
	list = NULL;

	return 0;
}

int _account_type_gslist_label_free(GSList* list)
{
	if(!list)
		return -1;

	GSList* iter;

	for (iter = list; iter != NULL; iter = g_slist_next(iter)) {
		label_s *label_data = (label_s*)iter->data;
		_account_type_free_label_with_items(label_data);
	}

	g_slist_free(list);
	list = NULL;

	return 0;
}

int _account_type_item_free(account_type_s *data)
{
	if(!data)
		return -1;

	_ACCOUNT_FREE(data->app_id);
	_ACCOUNT_FREE(data->service_provider_id);
	_ACCOUNT_FREE(data->icon_path);
	_ACCOUNT_FREE(data->small_icon_path);

	return 0;
}
/*
int _account_type_glist_free(GList* list)
{
	if(!list)
		return -1;

	GList* iter;

	for (iter = list; iter != NULL; iter = g_list_next(iter)) {
		account_type_s *account_type_record = (account_type_s*)iter->data;
		_account_type_item_free(account_type_record);
		_ACCOUNT_FREE(account_type_record);
	}

	g_list_free(list);
	list = NULL;

	return 0;
}
*/
int _account_type_free_account_type_with_items(account_type_s *data)
{
	if(!data)
		return -1;

	_account_type_item_free(data);

	_account_type_gslist_label_free(data->label_list);
	_account_type_gslist_feature_free(data->provider_feature_list);
//	_account_type_glist_free(data->account_type_list);

	_ACCOUNT_FREE(data);

	return 0;
}

int _account_type_gslist_account_type_free(GSList* list)
{
	_INFO("_account_type_gslist_account_type_free(GSList* list) start");
	if(!list)
		return -1;

	GSList* iter;

	for (iter = list; iter != NULL; iter = g_slist_next(iter)) {
		account_type_s *account_type_data = (account_type_s*)iter->data;
		_INFO("before _account_type_free_account_type_with_items(account_type_data)");
		_account_type_free_account_type_with_items(account_type_data);
		_INFO("after _account_type_free_account_type_with_items(account_type_data)");
	}

	g_slist_free(list);
	list = NULL;

	_INFO("_account_type_gslist_account_type_free(GSList* list) end");
	return 0;
}
