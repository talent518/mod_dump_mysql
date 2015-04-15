/* ====================================================================
 * Copyright (c) 1995 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * IT'S CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */


/*
 * Module definition information - the part between the -START and -END
 * lines below is used by Configure. This could be stored in a separate
 * instead.
 *
 * MODULE-DEFINITION-START
 * Name: dump_mysql_module
 * ConfigStart
     MYSQL_LIB="-L/usr/local/lib/mysql -lmysqlclient -lm -lz"
     if [ "X$MYSQL_LIB" != "X" ]; then
         LIBS="$LIBS $MYSQL_LIB"
         echo " + using $MYSQL_LIB for Mysql support"
     fi
 * ConfigEnd
 * MODULE-DEFINITION-END
 */

#define STRING(x) STR(x)		/* Used to build strings from compile options */
#define STR(x) #x

#include "ap_mmn.h"			/* For MODULE_MAGIC_NUMBER */

/* set any defaults not specified at compile time */
#ifdef HOST				/* Host to use */
  #define _HOST STRING(HOST)
#else
  #define _HOST 0			/* Will default to localhost */
#endif

/* Apache 1.x defines the port as a string, but Apache 2.x uses an integer */
#ifdef PORT				/* The port to use */
    #define _PORT PORT
#else
    #define _PORT MYSQL_PORT		/* Use the one from Mysql */
#endif

#ifdef SOCKET				/* UNIX socket */
  #define _SOCKET STRING(SOCKET)
#else
  #define _SOCKET MYSQL_UNIX_ADDR
#endif

#ifdef USER				/* Authorized user */
  #define _USER STRING(USER)
#else
  #define _USER 0			/* User must be specified in config */
#endif

#ifdef PASSWORD				/* Default password */
  #define _PASSWORD STRING(PASSWORD)
#else
  #define _PASSWORD 0			/* Password must be specified in config */
#endif

#ifdef DB				/* Default database */
  #define _DB STRING(DB)
#else
  #define _DB "test"			/* Test database */
#endif

#ifdef ADTABLE				/* Password table */
  #define _ADTABLE STRING(ADTABLE)
#else
  #define _ADTABLE "apache_dump" 		/* Default is apache_dump */
#endif

#ifdef KEEPALIVE			/* Keep the connection alive */
  #define _KEEPALIVE KEEPALIVE
#else
  #define _KEEPALIVE 0			/* Do not keep it alive */
#endif

#ifdef ENABLE				/* If we are to be enabled */
  #define _ENABLE ENABLE
#else
  #define _ENABLE 0			/* Assume we are */
#endif

#ifdef CHARACTERSET
  #define _CHARACTERSET STRING(CHARACTERSET)
#else
  #define _CHARACTERSET "utf8"		/* Default is utf8 */
#endif

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"

#define PCALLOC apr_pcalloc
#define SNPRINTF apr_snprintf
#define PSTRDUP apr_pstrdup
#define PSTRNDUP apr_pstrndup
#define STRCAT apr_pstrcat
#define POOL apr_pool_t
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/
#include "ap_compat.h"
#include "apr_strings.h"
#include "apr_sha1.h"
#include "apr_base64.h"
#include "apr_lib.h"
#define ISSPACE apr_isspace
#ifdef CRYPT
#include "crypt.h"
#else
#include "unistd.h"
#endif
#define LOG_ERROR(lvl, stat, rqst, msg)  \
  ap_log_rerror (APLOG_MARK, lvl, stat, rqst, msg)
#define LOG_ERROR_1(lvl, stat, rqst, msg, parm)  \
  ap_log_rerror (APLOG_MARK, lvl, stat, rqst, msg, parm)
#define LOG_ERROR_2(lvl, stat, rqst, msg, parm1, parm2)  \
  ap_log_rerror (APLOG_MARK, lvl, stat, rqst, msg, parm1, parm2)
#define LOG_ERROR_3(lvl, stat, rqst, msg, parm1, parm2, parm3)  \
  ap_log_rerror (APLOG_MARK, lvl, stat, rqst, msg, parm1, parm2, parm3)
#define APACHE_FUNC static apr_status_t
#define APACHE_FUNC_RETURN(rc) return rc
#define NOT_AUTHORIZED HTTP_UNAUTHORIZED
#define TABLE_GET apr_table_get

#include <mysql.h>

#define APR_ARRAY_FOREACH_INIT() apr_table_entry_t *apr_foreach_elts;int apr_foreach_i;char *key,*val

#define APR_ARRAY_FOREACH_OPEN(arr, key, val) 								\
{																			\
	apr_foreach_elts = (apr_table_entry_t *) arr->elts;						\
	for (apr_foreach_i = 0; apr_foreach_i < arr->nelts; apr_foreach_i++) {	\
		key = apr_foreach_elts[apr_foreach_i].key;							\
		val = apr_foreach_elts[apr_foreach_i].val;

#define APR_ARRAY_FOREACH_CLOSE() }}


/*
 * structure to hold the configuration details for the request
 */
typedef struct  {
  char *mysqlhost;		/* host name of db server */
  int  mysqlport;		/* port number of db server */
  char *mysqlsocket;		/* socket path of db server */
  char *mysqluser;		/* user ID to connect to db server */
  char *mysqlpasswd;		/* password to connect to db server */
  char *mysqlDB;		/* DB name */
  char *mysqltable;		/* user group table */
  int  mysqlKeepAlive;		/* keep connection persistent? */
  int  mysqlEnable;		/* do we bother trying to auth at all? */
  char *postText;		/* do we bother trying to auth at all? */
  int postTextLength;
  char *mysqlCharacterSet;	/* Mysql character set to use */
} dump_mysql_config_rec;

/*
 * Global information for the database connection.  Contains
 * the host name, userid and database name used to open the
 * connection.  If handle is not null, assume it is
 * still valid.  Mysql in recent incarnations will re-connect
 * automaticaly if the connection is closed, so we don't have
 * to worry about that here.
 */
typedef struct {
  MYSQL * handle;
  char host [255];
  char user [255];
  char db [255];
  time_t last_used;
} mysql_connection;

static mysql_connection connection = {NULL, "", "", ""};

static const char dump_mysql_filter_name[] = "dump_mysql";

/*
 * Global handle to db.  If not null, assume it is still valid.
 * Mysql in recent incarnations will re-connect automatically if the
 * connection is closed, so we don't worry about that here.
 */
/* static MYSQL *mysql_handle = NULL; */

static void close_connection() {
  if (connection.handle)
    mysql_close(connection.handle);
  connection.handle = NULL;		/* make sure we don't try to use it later */
  return;
}

/*
 * Callback to close mysql handle when necessary.  Also called when a
 * child httpd process is terminated.
 */
APACHE_FUNC
mod_auth_mysql_cleanup (void *notused)
{
  close_connection();
  APACHE_FUNC_RETURN(0);
}

/*
 * empty function necessary because register_cleanup requires it as one
 * of its parameters
 */
APACHE_FUNC
mod_auth_mysql_cleanup_child (void *data)
{
  /* nothing */
  APACHE_FUNC_RETURN(0);
}

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/*
 * open connection to DB server if necessary.  Return TRUE if connection
 * is good, FALSE if not able to connect.  If false returned, reason
 * for failure has been logged to error_log file already.
 */
static int
open_db_handle(request_rec *r, dump_mysql_config_rec *m)
{
  static MYSQL mysql_conn;
  char query[MAX_STRING_LEN];
  short host_match = FALSE;
  short user_match = FALSE;

  if (connection.handle) {

    /* See if the host has changed */
    if (!m->mysqlhost || (strcmp(m->mysqlhost, "localhost") == 0)) {
      if (connection.host[0] == '\0')
        host_match = TRUE;
    }
    else
      if (m->mysqlhost && (strcmp(m->mysqlhost, connection.host) == 0))
	host_match = TRUE;

    /* See if the user has changed */
    if (m->mysqluser) {
      if (strcmp(m->mysqluser, connection.user) == 0)
	user_match = TRUE;
    }
    else
      if (connection.user[0] == '\0')
        user_match = TRUE;

    /* if the host, or user have changed, need to close and reopen database connection */
    if (host_match && user_match) {
      /* If the database hasn't changed, we can just return */
      if (m->mysqlDB && strcmp(m->mysqlDB, connection.db) == 0)
	return TRUE; /* already open */

      /* Otherwise we need to reselect the database */
      else {
	if (mysql_select_db(connection.handle,m->mysqlDB) != 0) {
	  LOG_ERROR_1(APLOG_ERR, 0, r, "Mysql ERROR: %s", mysql_error(connection.handle));
	  return FALSE;
	}
	else {
	  strcpy (connection.db, m->mysqlDB);
	  return TRUE;
	}
      }
    }
    else
      close_connection();
  }

  connection.handle = mysql_init(&mysql_conn);
  if (! connection.handle) {
    LOG_ERROR_1(APLOG_ERR, 0, r, "Mysql ERROR: %s", mysql_error(&mysql_conn));
  }

  if (!m->mysqlhost || strcmp(m->mysqlhost,"localhost") == 0) {
    connection.host[0] = '\0';
  } else {
    strcpy(connection.host, m->mysqlhost);
  }

  connection.handle=mysql_real_connect(&mysql_conn,connection.host,m->mysqluser,
		  		  m->mysqlpasswd, NULL, m->mysqlport,
				  m->mysqlsocket, 0);
  if (!connection.handle) {
    LOG_ERROR_1(APLOG_ERR, 0, r, "Mysql ERROR: %s", mysql_error(&mysql_conn));
    return FALSE;
  }

  if (!m->mysqlKeepAlive) {
    /* close when request done */
    apr_pool_cleanup_register(r->pool, (void *)NULL, mod_auth_mysql_cleanup, mod_auth_mysql_cleanup_child);
  }

  if (m->mysqluser)
    strcpy(connection.user, m->mysqluser);
  else
    connection.user[0] = '\0';

  if (mysql_select_db(connection.handle,m->mysqlDB) != 0) {
    LOG_ERROR_1(APLOG_ERR, 0, r, "Mysql ERROR: %s", mysql_error(connection.handle));
    return FALSE;
  }
  else {
    strcpy (connection.db, m->mysqlDB);
  }
  if (m->mysqlCharacterSet) {	/* If a character set was specified */
    SNPRINTF(query, sizeof(query)-1, "SET NAMES %s", m->mysqlCharacterSet);
    if (mysql_query(connection.handle, query) != 0) {
      LOG_ERROR_2(APLOG_ERR, 0, r, "Mysql ERROR: %s: %s", mysql_error(connection.handle), r->unparsed_uri);
      return FALSE;
    }
  }

  return TRUE;
}

static void * create_dump_mysql_dir_config (POOL *p, char *d)
{
	dump_mysql_config_rec *m = PCALLOC(p, sizeof(dump_mysql_config_rec));
	if (!m) return NULL;		/* failure to get memory is a bad thing */

	/* default values */
	m->mysqlhost = _HOST;
	m->mysqlport = _PORT;
	m->mysqlsocket = _SOCKET;
	m->mysqluser = _USER;
	m->mysqlpasswd = _PASSWORD;
	m->mysqlDB = _DB;
	m->mysqltable = _ADTABLE;
	m->mysqlKeepAlive = _KEEPALIVE;         	    /* do not keep persistent connection */
	m->mysqlEnable = _ENABLE;		    	    /* authorization on by default */
	m->mysqlCharacterSet = _CHARACTERSET;		    /* default characterset to use */
	m->postText = NULL;
	m->postTextLength = 0;
	return (void *)m;
}

#include "apr_general.h"
#define APR_XtOffsetOf(s_type,field) APR_OFFSETOF(s_type,field)

static command_rec dump_mysql_cmds[] = {
	AP_INIT_TAKE1("DumpMysqlHost", ap_set_string_slot, (void *) APR_XtOffsetOf(dump_mysql_config_rec, mysqlhost), OR_AUTHCFG, "mysql server host name"),

	AP_INIT_TAKE1("DumpMysqlPort", ap_set_int_slot, (void *) APR_XtOffsetOf(dump_mysql_config_rec, mysqlport), OR_AUTHCFG, "mysql server port number"),

	AP_INIT_TAKE1("DumpMysqlSocket", ap_set_string_slot, (void *) APR_XtOffsetOf(dump_mysql_config_rec, mysqlsocket), OR_AUTHCFG, "mysql server socket path"),

	AP_INIT_TAKE1("DumpMysqlUser", ap_set_string_slot, (void *) APR_XtOffsetOf(dump_mysql_config_rec, mysqluser), OR_AUTHCFG, "mysql server user name"),

	AP_INIT_TAKE1("DumpMysqlPassword", ap_set_string_slot, (void *) APR_XtOffsetOf(dump_mysql_config_rec, mysqlpasswd), OR_AUTHCFG, "mysql server user password"),

	AP_INIT_TAKE1("DumpMysqlDB", ap_set_string_slot, (void *) APR_XtOffsetOf(dump_mysql_config_rec, mysqlDB), OR_AUTHCFG, "mysql database name"),

	AP_INIT_TAKE1("DumpMysqlTable", ap_set_string_slot, (void *) APR_XtOffsetOf(dump_mysql_config_rec, mysqltable), OR_AUTHCFG, "mysql user table name"),

//	AP_INIT_FLAG("DumpMysqlKeepAlive", ap_set_flag_slot, (void *) APR_XtOffsetOf(dump_mysql_config_rec, mysqlKeepAlive), OR_AUTHCFG, "mysql connection kept open across requests if On"),

	AP_INIT_FLAG("DumpMysqlEnable", ap_set_flag_slot, (void *) APR_XtOffsetOf(dump_mysql_config_rec, mysqlEnable), OR_AUTHCFG, "enable mysql authorization"),

	AP_INIT_TAKE1("DumpMysqlCharacterSet", ap_set_string_slot, (void *) APR_XtOffsetOf(dump_mysql_config_rec, mysqlCharacterSet), OR_AUTHCFG, "mysql character set to be used"),

	{ NULL }
};

module dump_mysql_module;

/*
 * Fetch and return password string from database for named user.
 * If we are in NoPasswd mode, returns user name instead.
 * If user or password not found, returns NULL
 */
static void insert_dump_mysql(request_rec *r, dump_mysql_config_rec *m, char *responseText, unsigned long responseTextLength) {
	MYSQL_STMT    *stmt;
	MYSQL_BIND    binds[7];
	char query[MAX_STRING_LEN];
	const apr_array_header_t *arr;
	char *requestHeader,*responseHeader,*ptr;
	unsigned long requestHeaderLength=0,responseHeaderLength=0;
	unsigned long requestDateline;
	unsigned long uri_len;
	unsigned long method_len;
	unsigned long client_ip;
	unsigned long client_ip_len;
	APR_ARRAY_FOREACH_INIT();

	if(!open_db_handle(r,m)) {
		return;		/* failure reason already logged */
	}

	requestDateline = (unsigned long)apr_time_sec(r->request_time);

	// get request header info
	arr = apr_table_elts(r->headers_in);
	APR_ARRAY_FOREACH_OPEN(arr, key, val)
		if (!val) val = "";
		requestHeaderLength+=3;
		requestHeaderLength+=strlen(key);
		requestHeaderLength+=strlen(val);
	APR_ARRAY_FOREACH_CLOSE();
	
	requestHeader = (char *) apr_palloc(r->pool, requestHeaderLength + 1);
	ptr = requestHeader;
	APR_ARRAY_FOREACH_OPEN(arr, key, val)
		sprintf(ptr, "%s: %s\n", key, val);
		ptr+=3;
		ptr+=strlen(key);
		ptr+=strlen(val);
	APR_ARRAY_FOREACH_CLOSE();

	// get response header info
	arr = apr_table_elts(r->headers_out);
	APR_ARRAY_FOREACH_OPEN(arr, key, val)
		if (!val) val = "";
		responseHeaderLength+=3;
		responseHeaderLength+=strlen(key);
		responseHeaderLength+=strlen(val);
	APR_ARRAY_FOREACH_CLOSE();
	
	responseHeader = (char *) apr_palloc(r->pool, responseHeaderLength + 1);
	ptr = responseHeader;
	APR_ARRAY_FOREACH_OPEN(arr, key, val)
		sprintf(ptr, "%s: %s\n", key, val);
		ptr+=3;
		ptr+=strlen(key);
		ptr+=strlen(val);
	APR_ARRAY_FOREACH_CLOSE();

	client_ip = apr_table_get(r->headers_in, "X-Forwarded-For");
	if(client_ip) {
		if(ptr = strchr(client_ip,',')) {
			client_ip_len = ptr-client_ip;
		} else {
			client_ip_len = strlen(client_ip);
		}
	} else {
		client_ip = r->useragent_ip?r->useragent_ip:"127.0.0.1";
		client_ip_len = strlen(client_ip);
	}

	stmt = mysql_stmt_init(connection.handle);
	if (!stmt)
	{
		LOG_ERROR_1(APLOG_ERR, 0, r, "mysql_stmt_init(), out of memory: %s", r->uri);
		return;
	}

	SNPRINTF(query,sizeof(query)-1,"INSERT INTO %s SET url=?, method=?, requestDateline=%d, requestTime=FROM_UNIXTIME(%d), requestHeader=?, responseCode=%d,responseHeader=?, responseText=?, postText=?, ip=?, runTime=%d/1000, dateline=UNIX_TIMESTAMP(), createTime=NOW()", m->mysqltable, requestDateline, requestDateline, r->status, (apr_time_now() - r->request_time));

	if (mysql_stmt_prepare(stmt, query, strlen(query)))
	{
		LOG_ERROR_3(APLOG_ERR, 0, r, "mysql_stmt_prepare(stmt, query, strlen(query)): %s: %s: %s", mysql_stmt_error(stmt), query, r->uri);
		return;
	}

	memset(binds, 0, sizeof(binds));

	uri_len= strlen(r->unparsed_uri);
	binds[0].buffer_type= MYSQL_TYPE_STRING;
	binds[0].buffer= r->unparsed_uri;
	binds[0].buffer_length= uri_len;
	binds[0].is_null= 0;
	binds[0].length= &uri_len;

	method_len= strlen(r->method);
	binds[1].buffer_type= MYSQL_TYPE_STRING;
	binds[1].buffer= r->method;
	binds[1].buffer_length= method_len;
	binds[1].is_null= 0;
	binds[1].length= &method_len;

	binds[2].buffer_type= MYSQL_TYPE_STRING;
	binds[2].buffer= requestHeader;
	binds[2].buffer_length= requestHeaderLength;
	binds[2].is_null= 0;
	binds[2].length= &requestHeaderLength;

	binds[3].buffer_type= MYSQL_TYPE_STRING;
	binds[3].buffer= responseHeader;
	binds[3].buffer_length= responseHeaderLength;
	binds[3].is_null= 0;
	binds[3].length= &responseHeaderLength;

	binds[4].buffer_type= MYSQL_TYPE_STRING;
	binds[4].buffer= responseText;
	binds[4].buffer_length= responseTextLength;
	binds[4].is_null= 0;
	binds[4].length= &responseTextLength;

	binds[5].buffer_type= MYSQL_TYPE_STRING;
	binds[5].buffer= m->postText;
	binds[5].buffer_length= m->postTextLength;
	binds[5].is_null= 0;
	binds[5].length= &m->postTextLength;

	binds[6].buffer_type= MYSQL_TYPE_STRING;
	binds[6].buffer= client_ip;
	binds[6].buffer_length= client_ip_len;
	binds[6].is_null= 0;
	binds[6].length= &client_ip_len;

	if (mysql_stmt_bind_param(stmt, binds))
	{
		LOG_ERROR_3(APLOG_ERR, 0, r, "mysql_stmt_bind_param(stmt, binds): %s: %s: %s", mysql_stmt_error(stmt), query, r->uri);
		return;
	}

	if (mysql_stmt_execute(stmt))
	{
		LOG_ERROR_3(APLOG_ERR, 0, r, "mysql_stmt_execute(stmt): %s: %s: %s", mysql_stmt_error(stmt), query, r->uri);
		return;
	}

	if (mysql_stmt_close(stmt))
	{
		LOG_ERROR_3(APLOG_ERR, 0, r, "mysql_stmt_close(stmt): %s: %s: %s", mysql_stmt_error(stmt), query, r->uri);
		return;
	}
}

/*
 * callback from Apache to do the authentication of the user to his
 * password.
 */
static void dump_mysql_insert_filter (request_rec *r)
{
  dump_mysql_config_rec *sec =
    (dump_mysql_config_rec *)ap_get_module_config (r->per_dir_config,
						   &dump_mysql_module);

  if (!sec->mysqlEnable)	/* no mysql authorization */
    return;

	ap_add_input_filter(dump_mysql_filter_name, NULL, r, r->connection);
	ap_add_output_filter(dump_mysql_filter_name, NULL, r, r->connection);
}

/*
 * callback from Apache to do the authentication of the user to his
 * password.
 */
static int dump_mysql_input_filter (ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
	request_rec *r = f->r;
	dump_mysql_config_rec *sec = (dump_mysql_config_rec *)ap_get_module_config (r->per_dir_config, &dump_mysql_module);

	if (r->method_number == M_POST && r->method[0] == 'P' && sec->postText == NULL) {
		ap_get_brigade(f->next, bb, mode, block, readbytes);
		apr_brigade_length(bb, 0, &sec->postTextLength );
		sec->postText = apr_palloc(r->pool, sec->postTextLength + 1);
		apr_brigade_flatten(bb, sec->postText, (apr_size_t)&sec->postTextLength );
	}

	ap_remove_input_filter(f);

	return ap_pass_brigade(f->next, bb);
}

/*
 * callback from Apache to do the authentication of the user to his
 * password.
 */
static int dump_mysql_output_filter (ap_filter_t *f,apr_bucket_brigade *bb)
{
	request_rec *r = f->r;
	dump_mysql_config_rec *sec = (dump_mysql_config_rec *)ap_get_module_config (r->per_dir_config, &dump_mysql_module);
	char *buffer;
	size_t len;

	apr_brigade_length(bb, 0, &len);
	buffer = apr_palloc(r->pool, len + 1);
	apr_brigade_flatten(bb, buffer, (apr_size_t)&len);

	insert_dump_mysql(r, sec, buffer, len ); /* Get a salt if one was specified */

	ap_remove_output_filter(f);

	return ap_pass_brigade(f->next, bb);
}

static void dump_mysql_register_hooks(POOL *p)
{
	ap_hook_insert_filter(dump_mysql_insert_filter, NULL, NULL, APR_HOOK_LAST);
	ap_register_input_filter(dump_mysql_filter_name, dump_mysql_input_filter, NULL, AP_FTYPE_RESOURCE);
	ap_register_output_filter(dump_mysql_filter_name, dump_mysql_output_filter, NULL, AP_FTYPE_RESOURCE);
}

module AP_MODULE_DECLARE_DATA dump_mysql_module =
{
	STANDARD20_MODULE_STUFF,
	create_dump_mysql_dir_config, /* dir config creater */
	NULL,                       /* dir merger --- default is to override */
	NULL,                       /* server config */
	NULL,                       /* merge server config */
	dump_mysql_cmds,              /* command apr_table_t */
	dump_mysql_register_hooks              /* register hooks */
};
