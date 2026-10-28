/*
 * xml parsing routines
 *
 * Copyright (C) 2014-2024 LastPass.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * See LICENSE.OpenSSL for more details regarding this exception.
 */
#include "xml.h"
#include "util.h"
#include "blob.h"
#include "feature-flag.h"
#include <string.h>
#include <strings.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <errno.h>

struct session *xml_ok_session(const char *buf, unsigned const char key[KDF_HASH_LEN])
{
	struct session *session = NULL;
	xmlDoc *doc = NULL;
	xmlNode *root;
	doc = xmlReadMemory(buf, strlen(buf), NULL, NULL, 0);

	if (!doc)
		goto out;

	root = xmlDocGetRootElement(doc);
	if (root && !xmlStrcmp(root->name, BAD_CAST "response")) {
		for (root = root->children; root; root = root->next) {
			if (!xmlStrcmp(root->name, BAD_CAST "ok"))
				break;
		}
	}
	if (root && !xmlStrcmp(root->name, BAD_CAST "ok")) {
		session = session_new();
		for (xmlAttrPtr attr = root->properties; attr; attr = attr->next) {
			if (!xmlStrcmp(attr->name, BAD_CAST "uid"))
				session->uid = (char *)xmlNodeListGetString(doc, attr->children, 1);
			if (!xmlStrcmp(attr->name, BAD_CAST "sessionid"))
				session->sessionid = (char *)xmlNodeListGetString(doc, attr->children, 1);
			if (!xmlStrcmp(attr->name, BAD_CAST "token"))
				session->token = (char *)xmlNodeListGetString(doc, attr->children, 1);
			if (!xmlStrcmp(attr->name, BAD_CAST "privatekeyenc")) {
				_cleanup_free_ char *private_key = (char *)xmlNodeListGetString(doc, attr->children, 1);
				session_set_private_key(session, key, private_key);
			}

			feature_flag_load_xml_attr(&session->feature_flag, doc, attr);
		}
	}
out:
	if (doc)
		xmlFreeDoc(doc);
	if (!session_is_valid(session)) {
		session_free(session);
		return NULL;
	}
	return session;
}

unsigned long long xml_login_check(const char *buf, struct session *session)
{
	_cleanup_free_ char *versionstr = NULL;
	unsigned long long version = 0;
	xmlDoc *doc = NULL;
	xmlNode *root, *child = NULL;

	doc = xmlReadMemory(buf, strlen(buf), NULL, NULL, 0);

	if (!doc)
		goto out;

	root = xmlDocGetRootElement(doc);
	if (root && !xmlStrcmp(root->name, BAD_CAST "response")) {
		for (child = root->children; child; child = child->next) {
			if (!xmlStrcmp(child->name, BAD_CAST "ok"))
				break;
		}
	}
	if (child) {
		for (xmlAttrPtr attr = child->properties; attr; attr = attr->next) {
			if (!xmlStrcmp(attr->name, BAD_CAST "uid")) {
				free(session->uid);
				session->uid = (char *)xmlNodeListGetString(doc, attr->children, 1);
			} else if (!xmlStrcmp(attr->name, BAD_CAST "sessionid")) {
				free(session->sessionid);
				session->sessionid = (char *)xmlNodeListGetString(doc, attr->children, 1);
			} else if (!xmlStrcmp(attr->name, BAD_CAST "token")) {
				free(session->token);
				session->token = (char *)xmlNodeListGetString(doc, attr->children, 1);
			} else if (!xmlStrcmp(attr->name, BAD_CAST "accts_version")) {
				versionstr = (char *)xmlNodeListGetString(doc, attr->children, 1);
				version = strtoull(versionstr, NULL, 10);
			}

			feature_flag_load_xml_attr(&session->feature_flag, doc, attr);
		}
	}
out:
	if (doc)
		xmlFreeDoc(doc);
	return version;
}

char *xml_error_cause(const char *buf, const char *what)
{
	char *result = NULL;
	xmlDoc *doc = NULL;
	xmlNode *root;

	doc = xmlReadMemory(buf, strlen(buf), NULL, NULL, 0);

	if (!doc)
		goto out;

	root = xmlDocGetRootElement(doc);
	if (root && !xmlStrcmp(root->name, BAD_CAST "response")) {
		for (xmlNode *child = root->children; child; child = child->next) {
			if (!xmlStrcmp(child->name, BAD_CAST "error")) {
				for (xmlAttrPtr attr = child->properties; attr; attr = attr->next) {
					if (!xmlStrcmp(attr->name, BAD_CAST what)) {
						result = (char *)xmlNodeListGetString(doc, attr->children, 1);
						goto out;
					}
				}
				break;
			}
		}
	}
out:
	if (doc)
		xmlFreeDoc(doc);
	if (!result)
		result = xstrdup("unknown");

	return result;
}

/*
 * Check if node has the tag "name", and interpret as a string
 * if so.
 *
 * Return true and update the string pointed to by ptr if the node
 * matches name.
 */
static bool
xml_parse_str(xmlDoc *doc, xmlNode *parent, const char *name, char **ptr)
{
	if (xmlStrcmp(parent->name, BAD_CAST name))
		return false;

	*ptr = (char *) xmlNodeListGetString(doc, parent->xmlChildrenNode, 1);
	if (!*ptr)
		return false;

	return true;
}

/*
 * Check if node has the tag "name", and interpret as an int if so.
 *
 * Return true and update the int pointed to by ptr if the node
 * matches name.
 */
static bool
xml_parse_int(xmlDoc *doc, xmlNode *parent, const char *name, int *ptr)
{
	if (xmlStrcmp(parent->name, BAD_CAST name))
		return false;

	_cleanup_free_ char *str = (char *)
		xmlNodeListGetString(doc, parent->xmlChildrenNode, 1);

	if (!str)
		return false;

	*ptr = atoi(str);
	return true;
}

/*
 * Check if node is for the boolean "name", and interpret as a boolean
 * if so.
 *
 * Return true and update the boolean pointed to by ptr if the node
 * matches name.
 */
static bool
xml_parse_bool(xmlDoc *doc, xmlNode *parent, const char *name, bool *ptr)
{
	int intval;

	if (!xml_parse_int(doc, parent, name, &intval))
		return false;

	*ptr = intval;
	return true;
}

static void
xml_parse_share_permissions(xmlDoc *doc, xmlNode *item, struct share_user *user)
{
	bool tmp;

	for (xmlNode *child = item->children; child; child = child->next) {
		if (xml_parse_bool(doc, child, "canadminister", &user->admin))
			continue;
		if (xml_parse_bool(doc, child, "readonly", &user->read_only))
			continue;
		if (xml_parse_bool(doc, child, "give", &tmp)) {
			user->hide_passwords = !tmp;
			continue;
		}
	}
}

static void
xml_parse_share_user(xmlDoc *doc, xmlNode *item, struct share_user *user)
{
	char *tmp;

	/* process a user item */
	for (xmlNode *child = item->children; child; child = child->next) {
		if (xml_parse_str(doc, child, "realname", &user->realname))
			continue;
		if (xml_parse_str(doc, child, "username", &user->username))
			continue;
		if (xml_parse_str(doc, child, "uid", &user->uid))
			continue;
		if (xml_parse_bool(doc, child, "group", &user->is_group))
			continue;
		if (xml_parse_bool(doc, child, "outsideenterprise", &user->outside_enterprise))
			continue;
		if (xml_parse_bool(doc, child, "accepted", &user->accepted))
			continue;
		if (xml_parse_str(doc, child, "sharingkey", &tmp)) {
			int ret = hex_to_bytes(tmp, &user->sharing_key.key);
			if (ret == 0)
				user->sharing_key.len = strlen(tmp) / 2;
			free(tmp);
			continue;
		}
		if (!xmlStrcmp(child->name, BAD_CAST "permissions"))
			xml_parse_share_permissions(doc, child, user);
	}
}

static int
xml_parse_share_key_entry(xmlDoc *doc, xmlNode *root,
			  struct share_user *user, int idx)
{
	char *tmp;

	_cleanup_free_ char *pubkey = NULL;
	_cleanup_free_ char *username = NULL;
	_cleanup_free_ char *uid = NULL;
	_cleanup_free_ char *cgid = NULL;

	xasprintf(&pubkey, "pubkey%d", idx);
	xasprintf(&username, "username%d", idx);
	xasprintf(&uid, "uid%d", idx);
	xasprintf(&cgid, "cgid%d", idx);

	memset(user, 0, sizeof(*user));

	for (xmlNode *item = root->children; item; item = item->next) {
		if (xml_parse_str(doc, item, pubkey, &tmp)) {
			int ret = hex_to_bytes(tmp, &user->sharing_key.key);
			if (ret == 0)
				user->sharing_key.len = strlen(tmp) / 2;
			free(tmp);
			continue;
		}
		if (xml_parse_str(doc, item, username, &user->username))
			continue;
		if (xml_parse_str(doc, item, uid, &user->uid))
			continue;
		if (xml_parse_str(doc, item, cgid, &user->cgid))
			continue;
	}

	if (!user->uid) {
		free(user->cgid);
		free(user->username);
		free(user->sharing_key.key);
		return -ENOENT;
	}
	return 0;
}


int xml_parse_share_getinfo(const char *buf, struct list_head *users)
{
	int ret;
	xmlDoc *doc = xmlReadMemory(buf, strlen(buf), NULL, NULL, 0);

	if (!doc)
		return -EINVAL;

	/*
	 * XML fields are as follows:
	 * xmlresponse
	 *   users
	 *     item
	 *       realname
	 *       uid
	 *       group
	 *       username
	 *       permissions
	 *         readonly
	 *         canadminister
	 *         give
	 *       outsideenterprise
	 *       accepted
	 *     item...
	 */
	xmlNode *root = xmlDocGetRootElement(doc);
	if (!root ||
	    xmlStrcmp(root->name, BAD_CAST "xmlresponse") ||
	    !root->children ||
	    xmlStrcmp(root->children->name, BAD_CAST "users")) {
		ret = -EINVAL;
		goto free_doc;
	}

	xmlNode *usernode = root->children;
	for (xmlNode *item = usernode->children; item; item = item->next) {
		if (xmlStrcmp(item->name, BAD_CAST "item"))
			continue;

		struct share_user *new_user = xcalloc(1, sizeof(*new_user));
		xml_parse_share_user(doc, item, new_user);
		list_add_tail(&new_user->list, users);
	}
	ret = 0;
free_doc:
	xmlFreeDoc(doc);
	return ret;
}

int xml_parse_share_getpubkeys(const char *buf, struct list_head *user_list)
{
	int ret;
	xmlDoc *doc = xmlReadMemory(buf, strlen(buf), NULL, NULL, 0);

	if (!doc)
		return -EINVAL;

	/*
	 * XML fields are as follows:
	 * xmlresponse
	 *   success
	 *   pubkey0
	 *   uid0
	 *   username0
	 *   cgid0 (if group)
	 */
	xmlNode *root = xmlDocGetRootElement(doc);
	if (!root || xmlStrcmp(root->name, BAD_CAST "xmlresponse") ||
	    !root->children) {
		ret = -EINVAL;
		goto free_doc;
	}

	for (int count = 0; ; count++) {
		struct share_user *user = new0(struct share_user, 1);
		ret = xml_parse_share_key_entry(doc, root, user, count);
		if (ret) {
			free(user);
			break;
		}
		list_add(&user->list, user_list);
	}
	if (list_empty(user_list))
		ret = -ENOENT;
	else
		ret = 0;
free_doc:
	xmlFreeDoc(doc);
	return ret;
}

static
int xml_parse_su_key_entry(xmlDoc *doc, xmlNode *parent,
			   struct pwchange_su_key *su_key, int idx)
{
	char *tmp;
	_cleanup_free_ char *pubkey = NULL;
	_cleanup_free_ char *uid = NULL;

	xasprintf(&pubkey, "sukey%d", idx);
	xasprintf(&uid, "suuid%d", idx);

	memset(su_key, 0, sizeof(*su_key));
	for (xmlAttrPtr attr = parent->properties; attr; attr = attr->next) {
		if (!xmlStrcmp(attr->name, BAD_CAST pubkey)) {
			tmp = (char *) xmlNodeListGetString(doc, attr->children, 1);
			int ret = hex_to_bytes(tmp, &su_key->sharing_key.key);
			if (ret == 0)
				su_key->sharing_key.len = strlen(tmp) / 2;
			free(tmp);
			continue;
		}
		if (!xmlStrcmp(attr->name, BAD_CAST uid)) {
			tmp = (char *) xmlNodeListGetString(doc, attr->children, 1);
			su_key->uid = tmp;
			continue;
		}
	}
	if (!su_key->sharing_key.len || !su_key->uid) {
		free(su_key->uid);
		free(su_key->sharing_key.key);
		return -ENOENT;
	}
	return 0;
}

static
int xml_parse_pwchange_su_keys(xmlDoc *doc, xmlNode *parent,
			       struct pwchange_info *info)
{
	for (int count = 0; ; count++) {
		struct pwchange_su_key *su_key = new0(struct pwchange_su_key,1);
		int ret = xml_parse_su_key_entry(doc, parent, su_key, count);
		if (ret) {
			free(su_key);
			break;
		}
		list_add(&su_key->list, &info->su_keys);
	}
	return 0;
}

static
int xml_parse_pwchange_data(char *data, struct pwchange_info *info)
{
	char *token, *end;
	struct pwchange_field *field;

	/*
	 * read the first two lines without strtok: in case there are
	 * empty lines we don't want to skip them.
	 */
#define next_line(x) { \
	end = strchr(data, '\n'); \
	if (!end) \
		return -ENOENT; \
	*end++ = 0; \
	info->x = xstrdup(data); \
	data = end; \
}
	next_line(reencrypt_id);
	next_line(privkey_encrypted);

#undef next_line

	for (token = strtok(data, "\n"); token; token = strtok(NULL, "\n")) {

		if (!strncmp(token, "endmarker", 9))
			break;

		field = new0(struct pwchange_field, 1);

		char *delim = strchr(token, '\t');
		if (delim) {
			*delim = 0;
			field->optional = *(delim + 1) == '0';
		}
		field->old_ctext = xstrdup(token);
		list_add_tail(&field->list, &info->fields);
	}
	return 0;
}

int xml_api_err(const char *buf)
{
	int ret;
	xmlDoc *doc = xmlReadMemory(buf, strlen(buf), NULL, NULL, 0);

	xmlNode *root = xmlDocGetRootElement(doc);
	if (!root || xmlStrcmp(root->name, BAD_CAST "lastpass") ||
			       !root->children) {
		ret = -EINVAL;
		goto free_doc;
	}

	for (xmlAttrPtr attr = root->properties; attr; attr = attr->next) {
		if (!xmlStrcmp(attr->name, BAD_CAST "rc")) {
			_cleanup_free_ char *val = (char *)
				xmlNodeListGetString(doc, attr->children, 1);
			if (strcmp(val, "OK") != 0) {
				ret = -EPERM;
				goto free_doc;
			}
		}
	}
	ret = 0;
free_doc:
	xmlFreeDoc(doc);
	return ret;
}

int xml_parse_pwchange(const char *buf, struct pwchange_info *info)
{
	int ret;
	xmlDoc *doc = xmlReadMemory(buf, strlen(buf), NULL, NULL, 0);

	INIT_LIST_HEAD(&info->fields);
	INIT_LIST_HEAD(&info->su_keys);

	xmlNode *root = xmlDocGetRootElement(doc);
	if (!root || xmlStrcmp(root->name, BAD_CAST "lastpass") ||
			       !root->children) {
		ret = -EINVAL;
		goto free_doc;
	}

	for (xmlAttrPtr attr = root->properties; attr; attr = attr->next) {
		if (!xmlStrcmp(attr->name, BAD_CAST "rc")) {
			_cleanup_free_ char *val = (char *)
				xmlNodeListGetString(doc, attr->children, 1);
			if (strcmp(val, "OK") != 0) {
				ret = -EPERM;
				goto free_doc;
			}
		}
	}

	for (xmlNode *item = root->children; item; item = item->next) {
		if (xmlStrcmp(item->name, BAD_CAST "data"))
			continue;

		for (xmlAttrPtr attr = item->properties; attr; attr = attr->next) {
			if (!xmlStrcmp(attr->name, BAD_CAST "xml")) {
				_cleanup_free_ char *data = (char *)
					xmlNodeListGetString(doc, attr->children, 1);

				ret = xml_parse_pwchange_data(data, info);
				if (ret)
					goto free_doc;
			}
			if (!xmlStrcmp(attr->name, BAD_CAST "token"))
				info->token = (char *)xmlNodeListGetString(doc, attr->children, 1);
		}
		xml_parse_pwchange_su_keys(doc, item, info);
	}

	ret = 0;
free_doc:
	xmlFreeDoc(doc);
	return ret;
}

int xml_parse_share_getpubkey(const char *buf, struct share_user *user)
{
	struct list_head users;
	struct share_user *share_user, *tmp;
	int ret;

	INIT_LIST_HEAD(&users);
	ret = xml_parse_share_getpubkeys(buf, &users);
	if (ret)
		return ret;

	if (list_empty(&users))
		return -ENOENT;

	share_user = list_first_entry(&users, struct share_user, list);
	*user = *share_user;

	list_for_each_entry_safe(share_user, tmp, &users, list)
		free(share_user);

	return 0;
}

static
void xml_parse_share_limit_aids(xmlDoc *doc, xmlNode *parent,
				struct list_head *list)
{
	for (xmlNode *item = parent->children; item; item = item->next) {
		if (xmlStrncmp(item->name, BAD_CAST "aid", 3))
			continue;

		struct share_limit_aid *aid = new0(struct share_limit_aid, 1);

		aid->aid = (char *) xmlNodeListGetString(doc,
				item->xmlChildrenNode, 1);

		list_add_tail(&aid->list, list);
	}
}

int xml_parse_share_get_limits(const char *buf, struct share_limit *limit)
{
	int ret;

	memset(limit, 0, sizeof(*limit));
	INIT_LIST_HEAD(&limit->aid_list);

	xmlDoc *doc = xmlReadMemory(buf, strlen(buf), NULL, NULL, 0);

	if (!doc)
		return -EINVAL;

	xmlNode *root = xmlDocGetRootElement(doc);
	if (!root || xmlStrcmp(root->name, BAD_CAST "xmlresponse") ||
	    !root->children) {
		ret = -EINVAL;
		goto free_doc;
	}

	for (xmlNode *item = root->children; item; item = item->next) {
		if (xml_parse_bool(doc, item, "hidebydefault",
				   &limit->whitelist))
			continue;

		if (!xmlStrcmp(item->name, BAD_CAST "aids")) {
			xml_parse_share_limit_aids(doc, item, &limit->aid_list);
		}
	}
	ret = 0;
free_doc:
	xmlFreeDoc(doc);
	return ret;
}

/*
 * Classify one share.php status word.
 * Return 1 for an OK value, -1 for a failure, and 0 when the text
 * is not a status (for example a numeric id).
 */
static int share_status_value(const char *val)
{
	size_t i;

	if (!val || !val[0])
		return 0;

	if (!strcasecmp(val, "ok") || !strcasecmp(val, "success") ||
	    !strcasecmp(val, "true") || !strcasecmp(val, "yes") ||
	    !strcmp(val, "1"))
		return 1;

	if (!strcasecmp(val, "fail") || !strcasecmp(val, "failed") ||
	    !strcasecmp(val, "failure") || !strcasecmp(val, "error") ||
	    !strcasecmp(val, "denied") || !strcasecmp(val, "no") ||
	    !strcasecmp(val, "false") || !strcmp(val, "0"))
		return -1;

	for (i = 0; val[i]; i++) {
		if (val[i] < '0' || val[i] > '9')
			return -1;
	}
	return 0;
}

static bool xml_tag_is(const xmlChar *tag, const char *name)
{
	return tag && !strcasecmp((const char *)tag, name);
}

static void trim_inplace(char *text)
{
	char *start;
	char *end;

	if (!text)
		return;

	start = text;
	while (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r')
		start++;
	if (start != text)
		memmove(text, start, strlen(start) + 1);

	end = text + strlen(text);
	while (end > text && (end[-1] == ' ' || end[-1] == '\t' ||
			      end[-1] == '\n' || end[-1] == '\r'))
		end--;
	*end = '\0';
}

static char *xml_node_text(xmlDoc *doc, xmlNode *node)
{
	if (!node)
		return NULL;
	return (char *)xmlNodeListGetString(doc, node->children, 1);
}

static char *xml_attr_text(xmlDoc *doc, xmlNode *node, const char *name)
{
	for (xmlAttrPtr attr = node->properties; attr; attr = attr->next) {
		if (xml_tag_is(attr->name, name))
			return (char *)xmlNodeListGetString(doc, attr->children, 1);
	}
	return NULL;
}

struct share_reply_scan {
	bool failed;
	bool from_error;
	char *message;
};

static void share_reply_set_message(struct share_reply_scan *scan, char *text,
				    bool from_error)
{
	if (!text)
		return;

	trim_inplace(text);
	if (!text[0]) {
		free(text);
		return;
	}

	if (!scan->message) {
		scan->message = text;
		scan->from_error = from_error;
		return;
	}
	if (from_error && !scan->from_error) {
		free(scan->message);
		scan->message = text;
		scan->from_error = true;
		return;
	}
	free(text);
}

static void share_reply_note_status(struct share_reply_scan *scan, char *val)
{
	int status;

	if (!val)
		return;

	trim_inplace(val);
	status = share_status_value(val);
	if (status < 0) {
		scan->failed = true;
		share_reply_set_message(scan, val, false);
		return;
	}
	free(val);
}

static void scan_share_reply_node(xmlDoc *doc, xmlNode *node,
				  struct share_reply_scan *scan)
{
	for (; node; node = node->next) {
		char *err_attr;

		if (node->type != XML_ELEMENT_NODE)
			continue;

		if (xml_tag_is(node->name, "error")) {
			char *message;

			scan->failed = true;
			message = xml_attr_text(doc, node, "message");
			trim_inplace(message);
			if (!message || !message[0]) {
				free(message);
				message = xml_node_text(doc, node);
				trim_inplace(message);
			}
			if (!message || !message[0]) {
				free(message);
				message = xml_attr_text(doc, node, "cause");
				trim_inplace(message);
			}
			if (!message || !message[0]) {
				free(message);
				message = xml_attr_text(doc, node, "reason");
				trim_inplace(message);
			}
			share_reply_set_message(scan, message, true);
		} else if (xml_tag_is(node->name, "result") ||
			   xml_tag_is(node->name, "status")) {
			share_reply_note_status(scan, xml_node_text(doc, node));
		} else if (xml_tag_is(node->name, "success")) {
			char *text = xml_node_text(doc, node);

			trim_inplace(text);
			if (text && share_status_value(text) < 0) {
				scan->failed = true;
				share_reply_set_message(scan, text, false);
			} else {
				free(text);
			}
		}

		share_reply_note_status(scan, xml_attr_text(doc, node, "rc"));
		if (!xml_tag_is(node->name, "error")) {
			share_reply_note_status(scan,
						xml_attr_text(doc, node, "status"));
			share_reply_note_status(scan,
						xml_attr_text(doc, node, "result"));
			err_attr = xml_attr_text(doc, node, "error");
			if (err_attr) {
				trim_inplace(err_attr);
				if (err_attr[0]) {
					scan->failed = true;
					share_reply_set_message(scan, err_attr, true);
				} else {
					free(err_attr);
				}
			}
		}

		if (node->children)
			scan_share_reply_node(doc, node->children, scan);
	}
}

int xml_share_reply_err(const char *buf, char **message)
{
	xmlDoc *doc;
	struct share_reply_scan scan;

	if (message)
		*message = NULL;

	if (!buf || !buf[0]) {
		if (message)
			*message = xstrdup("empty reply");
		return -EINVAL;
	}

	doc = xmlReadMemory(buf, strlen(buf), NULL, NULL,
			   XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
	if (!doc) {
		if (message)
			*message = xstrdup(buf);
		return -EINVAL;
	}

	memset(&scan, 0, sizeof(scan));
	scan_share_reply_node(doc, xmlDocGetRootElement(doc), &scan);
	xmlFreeDoc(doc);

	if (!scan.failed) {
		free(scan.message);
		return 0;
	}

	if (message) {
		if (scan.message)
			*message = scan.message;
		else
			*message = xstrdup(buf);
	} else {
		free(scan.message);
	}
	return -EPERM;
}
