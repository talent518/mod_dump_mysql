#define STRING(x) STR(x) /* Used to build strings from compile options */
#define STR(x) #x

#include "ap_mmn.h" /* For MODULE_MAGIC_NUMBER */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"

#include "http_request.h" /* for ap_hook_(check_user_id | auth_checker)*/
#include "ap_compat.h"
#include "apr_strings.h"
#include "apr_sha1.h"
#include "apr_base64.h"
#include "apr_lib.h"
#include "apr_general.h"

#include <mysql.h>

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define APR_ARRAY_FOREACH_INIT() apr_table_entry_t *apr_foreach_elts;int apr_foreach_i;char *key,*val

#define APR_ARRAY_FOREACH_OPEN(arr, key, val)        \
{                   \
 apr_foreach_elts = (apr_table_entry_t *) arr->elts;      \
 for (apr_foreach_i = 0; apr_foreach_i < arr->nelts; apr_foreach_i++) { \
  key = apr_foreach_elts[apr_foreach_i].key;       \
  val = apr_foreach_elts[apr_foreach_i].val;

#define APR_ARRAY_FOREACH_CLOSE() }}

/*
 * Global information for the database connection. Contains
 * the host name, userid and database name used to open the
 * connection. If handle is not null, assume it is
 * still valid.  Mysql in recent incarnations will re-connect
 * automaticaly if the connection is closed, so we don't have
 * to worry about that here.
 */
typedef struct
{
	MYSQL * handle;
	char host [255];
	char user [255];
	char db [255];
} mysql_connection;

/*
 * structure to hold the configuration details for the request
 */
typedef struct
{
	char *mysqlhost;			/* host name of db server */
	int  mysqlport;				/* port number of db server */
	char *mysqlsocket;			/* socket path of db server */
	char *mysqluser;			/* user ID to connect to db server */
	char *mysqlpasswd;			/* password to connect to db server */
	char *mysqlDB;				/* DB name */
	char *mysqltable;			/* user group table */
	int  mysqlEnable;			/* do we bother trying to auth at all? */
	char *postText;				/* post submit data */
	int postTextLength;			/* post submit data length */
	char *mysqlCharacterSet;	/* Mysql character set to use */
	apr_array_header_t *rules;	/* dump rule array */
	mysql_connection mysql;
} dump_mysql_config_rec;

/*
 * structure to dump rule
 */
typedef struct
{
	char *pattern;
	ap_regex_t *regexp;
} rule_entry;

static const char dump_mysql_filter_name[] = "dump_mysql";

/*
 * Global handle to db.  If not null, assume it is still valid.
 * Mysql in recent incarnations will re-connect automatically if the
 * connection is closed, so we don't worry about that here.
 */
/* static MYSQL *mysql_handle = NULL; */

static apr_status_t mod_auth_mysql_cleanup (void *data)
{
	dump_mysql_config_rec *m = data;
	if (m->mysql.handle)
		mysql_close(m->mysql.handle);
	m->mysql.handle = NULL;  /* make sure we don't try to use it later */
	return 0;
}

/*
 * open connection to DB server if necessary.  Return TRUE if connection
 * is good, FALSE if not able to connect.  If false returned, reason
 * for failure has been logged to error_log file already.
 */
static int open_db_handle(request_rec *r, dump_mysql_config_rec *m)
{
	static MYSQL mysql_conn;
	char query[MAX_STRING_LEN];
	short host_match = FALSE;
	short user_match = FALSE;

	if (m->mysql.handle)
	{

		if (mysql_ping(m->mysql.handle))
		{
			ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "Mysql ERROR: %s", mysql_error(m->mysql.handle));
		}
	}

	m->mysql.handle = mysql_init(&mysql_conn);
	if (! m->mysql.handle)
	{
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "Mysql ERROR: %s", mysql_error(&mysql_conn));
	}

	if (!m->mysqlhost || strcmp(m->mysqlhost,"localhost") == 0)
	{
		m->mysql.host[0] = '\0';
	}
	else
	{
		strcpy(m->mysql.host, m->mysqlhost);
	}

	m->mysql.handle=mysql_real_connect(&mysql_conn,m->mysql.host,m->mysqluser, m->mysqlpasswd, NULL, m->mysqlport, m->mysqlsocket, 0);
	if (!m->mysql.handle)
	{
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "Mysql ERROR: %s", mysql_error(&mysql_conn));
		return FALSE;
	}

	apr_pool_cleanup_register(r->pool, (void *)m, mod_auth_mysql_cleanup, apr_pool_cleanup_null);

	if (m->mysqluser)
		strcpy(m->mysql.user, m->mysqluser);
	else
		m->mysql.user[0] = '\0';

	if (mysql_select_db(m->mysql.handle,m->mysqlDB) != 0)
	{
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "Mysql ERROR: %s", mysql_error(m->mysql.handle));
		return FALSE;
	}
	else
	{
		strcpy (m->mysql.db, m->mysqlDB);
	}
	if (m->mysqlCharacterSet)   /* If a character set was specified */
	{
		apr_snprintf(query, sizeof(query)-1, "SET NAMES %s", m->mysqlCharacterSet);
		if (mysql_query(m->mysql.handle, query) != 0)
		{
			ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "Mysql ERROR: %s: %s", mysql_error(m->mysql.handle), r->unparsed_uri);
			return FALSE;
		}
	}

	return TRUE;
}

static void *create_dump_mysql_dir_config (apr_pool_t *p, char *d)
{
	dump_mysql_config_rec *m = apr_pcalloc(p, sizeof(dump_mysql_config_rec));
	if (!m) return NULL;  /* failure to get memory is a bad thing */

	/* default values */
	m->mysqlhost = "localhost";
	m->mysqlport = 3306;
	m->mysqlsocket = NULL;
	m->mysqluser = "";
	m->mysqlpasswd = "";
	m->mysqlDB = "test";
	m->mysqltable = "apache_dump";
	m->mysqlEnable = FALSE;     /* authorization on by default */
	m->mysqlCharacterSet = "utf8";   /* default characterset to use */
	m->postText = NULL;
	m->postTextLength = 0;
	m->rules = apr_array_make(p, 20, sizeof(rule_entry));

	return (void *)m;
}

static const char *dump_mysql_rule(cmd_parms *cmd, void *m_, int argc, char *const argv[])
{
	dump_mysql_config_rec *m = m_;
	rule_entry *rule;
	int i;

	for (i=0;i<argc;i++)
	{
		rule = apr_array_push(m->rules);
		rule->regexp = ap_pregcomp(cmd->pool, argv[i], AP_REG_EXTENDED);
		if (rule->regexp == NULL)
			return "Regular expression could not be compiled.";
		rule->pattern = argv[i];
	}

	return NULL;
}

static command_rec dump_mysql_cmds[] =
{
	AP_INIT_TAKE1("DumpMysqlHost", ap_set_string_slot, (void *) APR_OFFSETOF(dump_mysql_config_rec, mysqlhost), OR_FILEINFO, "mysql server host name"),

	AP_INIT_TAKE1("DumpMysqlPort", ap_set_int_slot, (void *) APR_OFFSETOF(dump_mysql_config_rec, mysqlport), OR_FILEINFO, "mysql server port number"),

	AP_INIT_TAKE1("DumpMysqlSocket", ap_set_string_slot, (void *) APR_OFFSETOF(dump_mysql_config_rec, mysqlsocket), OR_FILEINFO, "mysql server socket path"),

	AP_INIT_TAKE1("DumpMysqlUser", ap_set_string_slot, (void *) APR_OFFSETOF(dump_mysql_config_rec, mysqluser), OR_FILEINFO, "mysql server user name"),

	AP_INIT_TAKE1("DumpMysqlPassword", ap_set_string_slot, (void *) APR_OFFSETOF(dump_mysql_config_rec, mysqlpasswd), OR_FILEINFO, "mysql server user password"),

	AP_INIT_TAKE1("DumpMysqlDB", ap_set_string_slot, (void *) APR_OFFSETOF(dump_mysql_config_rec, mysqlDB), OR_FILEINFO, "mysql database name"),

	AP_INIT_TAKE1("DumpMysqlTable", ap_set_string_slot, (void *) APR_OFFSETOF(dump_mysql_config_rec, mysqltable), OR_FILEINFO, "mysql user table name"),

	AP_INIT_FLAG("DumpMysqlEnable", ap_set_flag_slot, (void *) APR_OFFSETOF(dump_mysql_config_rec, mysqlEnable), OR_FILEINFO, "enable mysql authorization"),

	AP_INIT_TAKE1("DumpMysqlCharacterSet", ap_set_string_slot, (void *) APR_OFFSETOF(dump_mysql_config_rec, mysqlCharacterSet), OR_FILEINFO, "mysql character set to be used"),

	AP_INIT_TAKE_ARGV("DumpMysqlRule", dump_mysql_rule, NULL, OR_FILEINFO, "Controls what individual directives can be configured by per-directory config files"),

	{ NULL }
};

module AP_MODULE_DECLARE_DATA dump_mysql_module;

/*
 * Fetch and return password string from database for named user.
 * If we are in NoPasswd mode, returns user name instead.
 * If user or password not found, returns NULL
 */
static void insert_dump_mysql(request_rec *r, dump_mysql_config_rec *m, char *responseText, unsigned long responseTextLength)
{
	MYSQL_STMT   *stmt;
	MYSQL_BIND   binds[8];
	char query[MAX_STRING_LEN];
	const apr_array_header_t *arr;
	char *requestHeader, *responseHeader, *ptr, *client_ip;
	unsigned long requestHeaderLength=0, responseHeaderLength=0;
	unsigned long requestDateline;
	unsigned long uri_len, file_len;
	unsigned long method_len;
	unsigned long client_ip_len;
	APR_ARRAY_FOREACH_INIT();

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
	if (client_ip)
	{
		if (ptr = strchr(client_ip, ','))
		{
			client_ip_len = ptr-client_ip;
		}
		else
		{
			client_ip_len = strlen(client_ip);
		}
	}
	else
	{
		client_ip = r->useragent_ip?r->useragent_ip:"127.0.0.1";
		client_ip_len = strlen(client_ip);
	}

	if (!open_db_handle(r,m))
	{
		return;  /* failure reason already logged */
	}

	stmt = mysql_stmt_init(m->mysql.handle);
	if (!stmt)
	{
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "mysql_stmt_init(), out of memory: %s", r->uri);
		return;
	}

	apr_snprintf(query,sizeof(query)-1,"INSERT INTO %s SET scheme='%s', port=%d, protocol='%s', url=?, method=?, requestDateline=%d, requestTime=FROM_UNIXTIME(%d), responseCode=%d, requestHeader=?, requestHeaderLength=%d, responseHeader=?, responseHeaderLength=%d, responseText=?, responseTextLength=%d, postText=?, postTextLength=%d, ip=?, file=?, runTime=%d/1000, dateline=UNIX_TIMESTAMP(), createTime=NOW()", m->mysqltable, ap_http_scheme(r), r->server->addrs->host_port, r->protocol, requestDateline, requestDateline, r->status, requestHeaderLength, responseHeaderLength, responseTextLength, m->postTextLength, (apr_time_now() - r->request_time));

	if (mysql_stmt_prepare(stmt, query, strlen(query)))
	{
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "mysql_stmt_prepare(stmt, query, strlen(query)): %s: %s: %s", mysql_stmt_error(stmt), query, r->uri);
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

	file_len= strlen(r->uri);
	binds[7].buffer_type= MYSQL_TYPE_STRING;
	binds[7].buffer= r->uri;
	binds[7].buffer_length= file_len;
	binds[7].is_null= 0;
	binds[7].length= &file_len;

	if (mysql_stmt_bind_param(stmt, binds))
	{
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "mysql_stmt_bind_param(stmt, binds): %s: %s: %s", mysql_stmt_error(stmt), query, r->uri);
		return;
	}

	if (mysql_stmt_execute(stmt))
	{
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "mysql_stmt_execute(stmt): %s: %s: %s", mysql_stmt_error(stmt), query, r->uri);
		return;
	}

	if (mysql_stmt_close(stmt))
	{
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "mysql_stmt_close(stmt): %s: %s: %s", mysql_stmt_error(stmt), query, r->uri);
		return;
	}
}

/*
 * callback from Apache to do the authentication of the user to his
 * password.
 */
static void dump_mysql_insert_filter (request_rec *r)
{
	dump_mysql_config_rec *sec = (dump_mysql_config_rec *)ap_get_module_config (r->per_dir_config, &dump_mysql_module);

	if (!sec->mysqlEnable) /* no mysql authorization */
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

	if (mode != AP_MODE_READBYTES) {
		return ap_get_brigade(f->next, bb, mode, block, readbytes);
	}

	if (r->method_number == M_POST && r->method[0] == 'P' && sec->postText == NULL)
	{
		if (ap_get_brigade(f->next, bb, mode, block, readbytes)==APR_SUCCESS && apr_brigade_length(bb, 0, &sec->postTextLength ) == APR_SUCCESS)
		{
			sec->postText = apr_palloc(r->pool, sec->postTextLength + 1);
			apr_brigade_flatten(bb, sec->postText, (apr_size_t)&sec->postTextLength );
		}
	}

	ap_remove_input_filter(f);

	return APR_SUCCESS;
}

/*
 * callback from Apache to do the authentication of the user to his
 * password.
 */
static int dump_mysql_output_filter (ap_filter_t *f,apr_bucket_brigade *bb)
{
	request_rec *r = f->r;
	dump_mysql_config_rec *sec = (dump_mysql_config_rec *)ap_get_module_config (r->per_dir_config, &dump_mysql_module);
	char *buffer=NULL;
	size_t len=0;

	rule_entry *rule, *rules = (rule_entry *) sec->rules->elts;
	int flag = 0, i;
	ap_regmatch_t regm[AP_MAX_REG_MATCH];

	for (i = 0; i < sec->rules->nelts; ++i)
	{
		rule = &rules[i];

		if (!ap_regexec(rule->regexp, r->uri, AP_MAX_REG_MATCH, regm, 0))
		{
			flag = 1;
			break;
		}
	}

	if (i==0 || flag )
	{
		if (apr_brigade_length(bb, 0, &len) == APR_SUCCESS)
		{
			buffer = apr_palloc(r->pool, len + 1);
			apr_brigade_flatten(bb, buffer, (apr_size_t)&len);
		}

		insert_dump_mysql(r, sec, buffer, len ); /* Get a salt if one was specified */
	}

	ap_remove_output_filter(f);

	return ap_pass_brigade(f->next, bb);
}

static void dump_mysql_register_hooks(apr_pool_t *p)
{
	ap_hook_insert_filter(dump_mysql_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);
	ap_register_input_filter(dump_mysql_filter_name, dump_mysql_input_filter, NULL, AP_FTYPE_RESOURCE);
	ap_register_output_filter(dump_mysql_filter_name, dump_mysql_output_filter, NULL, AP_FTYPE_RESOURCE);
}

module AP_MODULE_DECLARE_DATA dump_mysql_module =
{
	STANDARD20_MODULE_STUFF,
	create_dump_mysql_dir_config, /* dir config creater */
	NULL,       /* dir merger --- default is to override */
	NULL,       /* server config */
	NULL,       /* merge server config */
	dump_mysql_cmds,    /* command apr_table_t */
	dump_mysql_register_hooks  /* register hooks */
};
