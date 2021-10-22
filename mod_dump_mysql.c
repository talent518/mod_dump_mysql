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

#ifndef BOOL
#define BOOL int
#endif

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
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
	int maxAllowedPacket;		/* Mysql client data packet max size from mysql server read */
	int insertId;				/* insert after dumpId for value */
	BOOL isFirstPostBucketRead; /* is first post bucket read */
	int post_readed_length;
	int response_readed_length;
	apr_time_t mysql_current_time;
	apr_time_t mysql_execute_time;
	BOOL isFirstResponseBucketRead; /* is first response bucket read */
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

typedef struct
{
	apr_bucket_brigade *bb;
} input_context;

static const char dump_mysql_filter_name[] = "dump_mysql";

static apr_status_t dump_mysql_db_cleanup (void *data)
{
	dump_mysql_config_rec *m = data;
	if (m->mysql.handle)
		mysql_close(m->mysql.handle);
	m->mysql.handle = NULL;  /* make sure we don't try to use it later */
	return 0;
}

static BOOL open_db_handle(request_rec *r, dump_mysql_config_rec *m)
{
	static MYSQL mysql_conn;
	char query[MAX_STRING_LEN];
	MYSQL_RES *result;
	MYSQL_ROW *row;
	MYSQL_FIELD *field;

	if (m->mysql.handle)
	{

		if (mysql_ping(m->mysql.handle))
		{
			ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "Mysql ERROR: %s", mysql_error(m->mysql.handle));

			return FALSE;
		}

		return TRUE;
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

	apr_pool_cleanup_register(r->pool, (void *)m, dump_mysql_db_cleanup, apr_pool_cleanup_null);

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
		if (mysql_query(m->mysql.handle, query))
		{
			ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "Mysql ERROR: %s: %s", mysql_error(m->mysql.handle), r->unparsed_uri);
			return FALSE;
		}
	}

	if(mysql_query(m->mysql.handle, "SHOW GLOBAL VARIABLES LIKE 'max_allowed_packet'"))
	{
		ap_log_rerror (APLOG_MARK, APLOG_WARNING, 0, r, "Mysql ERROR: %s: %s", mysql_error(m->mysql.handle), r->unparsed_uri);

		m->maxAllowedPacket = 1*1024*1024;

		return TRUE;
	}

	result = mysql_use_result(m->mysql.handle);

	row=mysql_fetch_row(result);
	field = mysql_fetch_field_direct(result, 1);

	if(row && field && strcmp(field->name,"Value")==0)
	{
		m->maxAllowedPacket = atoi(row[1]);
	}
	else
	{
		m->maxAllowedPacket = 1*1024*1024;
	}

	m->maxAllowedPacket -= 1024;

	mysql_free_result(result);

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
	m->mysqlEnable = FALSE;     /* not enable on by default */
	m->mysqlCharacterSet = "utf8";   /* default characterset to use */
	m->postText = NULL;
	m->postTextLength = 0;
	m->insertId = 0;
	m->rules = apr_array_make(p, 20, sizeof(rule_entry));
	m->maxAllowedPacket = 0;
	m->isFirstPostBucketRead = TRUE;
	m->isFirstResponseBucketRead = TRUE;
	m->post_readed_length = 0;
	m->response_readed_length = 0;
	m->mysql_current_time=0;
	m->mysql_execute_time=0;

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

	AP_INIT_FLAG("DumpMysqlEnable", ap_set_flag_slot, (void *) APR_OFFSETOF(dump_mysql_config_rec, mysqlEnable), OR_FILEINFO, "enable mysql dump filter"),

	AP_INIT_TAKE1("DumpMysqlCharacterSet", ap_set_string_slot, (void *) APR_OFFSETOF(dump_mysql_config_rec, mysqlCharacterSet), OR_FILEINFO, "mysql character set to be used"),

	AP_INIT_TAKE_ARGV("DumpMysqlRule", dump_mysql_rule, NULL, OR_FILEINFO, "Controls what individual directives can be configured by per-directory config files"),

	{ NULL }
};

module AP_MODULE_DECLARE_DATA dump_mysql_module;

static void dump_mysql_record_full_and_response(request_rec *r, dump_mysql_config_rec *m, char *responseText, unsigned long responseTextLength)
{
	MYSQL_STMT   *stmt;
	MYSQL_BIND   binds[7];
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

	stmt = mysql_stmt_init(m->mysql.handle);
	if (!stmt)
	{
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "mysql_stmt_init(), out of memory: %s", r->uri);
		return;
	}

	if(m->insertId == 0)
		apr_snprintf(query,sizeof(query)-1,"INSERT INTO %s SET scheme='%s', port=%d, protocol='%s', url=?, method=?, requestDateline=%d, requestTime=FROM_UNIXTIME(%d), responseCode=%d, requestHeader=?, requestHeaderLength=%d, responseHeader=?, responseHeaderLength=%d, responseText=?, responseTextLength=%d, ip=?, file=?, runTime=%d/1000,       dateline=UNIX_TIMESTAMP(), createTime=NOW()                ", m->mysqltable, ap_http_scheme(r), r->server->addrs->host_port, r->protocol, requestDateline, requestDateline, r->status, requestHeaderLength, responseHeaderLength, responseTextLength, (m->mysql_current_time - m->mysql_execute_time - r->request_time));
	else
		apr_snprintf(query,sizeof(query)-1,"     UPDATE %s SET scheme='%s', port=%d, protocol='%s', url=?, method=?, requestDateline=%d, requestTime=FROM_UNIXTIME(%d), responseCode=%d, requestHeader=?, requestHeaderLength=%d, responseHeader=?, responseHeaderLength=%d, responseText=?, responseTextLength=%d, ip=?, file=?, runTime=%d/1000, updateDateline=UNIX_TIMESTAMP(), updateTime=NOW() WHERE dumpId=%d", m->mysqltable, ap_http_scheme(r), r->server->addrs->host_port, r->protocol, requestDateline, requestDateline, r->status, requestHeaderLength, responseHeaderLength, responseTextLength, (m->mysql_current_time - m->mysql_execute_time - r->request_time), m->insertId);

	ap_log_rerror (APLOG_MARK, APLOG_WARNING, 0, r, "dump_mysql_record_full_and_response(%d): [%c] %s", responseTextLength, responseText, query);

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
	binds[5].buffer= client_ip;
	binds[5].buffer_length= client_ip_len;
	binds[5].is_null= 0;
	binds[5].length= &client_ip_len;

	file_len= strlen(r->uri);
	binds[6].buffer_type= MYSQL_TYPE_STRING;
	binds[6].buffer= r->uri;
	binds[6].buffer_length= file_len;
	binds[6].is_null= 0;
	binds[6].length= &file_len;

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

	if(m->insertId == 0)
		m->insertId = mysql_stmt_insert_id(stmt);

	if (mysql_stmt_close(stmt))
	{
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "mysql_stmt_close(stmt): %s: %s: %s", mysql_stmt_error(stmt), query, r->uri);
		return;
	}
}

static void dump_mysql_record_post_or_response(request_rec *r, dump_mysql_config_rec *m, BOOL is_post, char *buffer, unsigned long buffer_length)
{
	MYSQL_STMT   *stmt;
	MYSQL_BIND   binds[1];
	char query[MAX_STRING_LEN];

	if(buffer_length<=0)
	{
		return;
	}

	stmt = mysql_stmt_init(m->mysql.handle);
	if (!stmt)
	{
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "mysql_stmt_init(), out of memory: %s", r->uri);
		return;
	}

	if(is_post)
	{
		if(m->insertId == 0)
			apr_snprintf(query,sizeof(query)-1,"INSERT INTO %s SET postText=?, postTextLength=%d, runTime=%d/1000, dateline=UNIX_TIMESTAMP(), createTime=NOW()", m->mysqltable, buffer_length, (m->mysql_current_time - m->mysql_execute_time - r->request_time));
		else
			apr_snprintf(query,sizeof(query)-1,"UPDATE %s SET postText=CONCAT(postText,?), postTextLength=postTextLength+%d, runTime=%d/1000, updateDateline=UNIX_TIMESTAMP(), updateTime=NOW() WHERE dumpId=%d", m->mysqltable, buffer_length, (m->mysql_current_time - m->mysql_execute_time - r->request_time), m->insertId);
	}
	else
	{
		apr_snprintf(query,sizeof(query)-1,"UPDATE %s SET responseText=CONCAT(responseText,?), responseTextLength=responseTextLength+%d, runTime=%d/1000, updateDateline=UNIX_TIMESTAMP(), updateTime=NOW() WHERE dumpId=%d", m->mysqltable, buffer_length, (m->mysql_current_time - m->mysql_execute_time - r->request_time), m->insertId);
	}

	ap_log_rerror (APLOG_MARK, APLOG_WARNING, 0, r, "dump_mysql_record_post_or_response(%d): [%c] %s", buffer_length, buffer, query);

	if (mysql_stmt_prepare(stmt, query, strlen(query)))
	{
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "mysql_stmt_prepare(stmt, query, strlen(query)): %s: %s: %s", mysql_stmt_error(stmt), query, r->uri);
		return;
	}

	memset(binds, 0, sizeof(binds));

	binds[0].buffer_type= MYSQL_TYPE_STRING;
	binds[0].buffer= buffer;
	binds[0].buffer_length= buffer_length;
	binds[0].is_null= 0;
	binds[0].length= &buffer_length;

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

	if(is_post && m->insertId == 0)
		m->insertId = mysql_stmt_insert_id(stmt);

	if (mysql_stmt_close(stmt))
	{
		ap_log_rerror (APLOG_MARK, APLOG_ERR, 0, r, "mysql_stmt_close(stmt): %s: %s: %s", mysql_stmt_error(stmt), query, r->uri);
		return;
	}
}

static int dump_mysql_record(request_rec *r, dump_mysql_config_rec *sec, BOOL is_post, BOOL *ref_is_first, int *ref_length, char *buffer, apr_size_t len)
{
	BOOL is_first=*ref_is_first;
	int length=*ref_length;
	int buffer_length;

	sec->mysql_current_time=apr_time_now();
	if (open_db_handle(r,sec))
	{
		buffer_length=MIN(len,sec->maxAllowedPacket);
		if(is_first)
		{
			if(is_post)
				dump_mysql_record_post_or_response(r, sec, TRUE, buffer, buffer_length);
			else
				dump_mysql_record_full_and_response(r, sec, buffer, buffer_length);
			length = len;

			// set is first bucket read
			is_first=FALSE;
			if(is_post)
			{
				sec->isFirstPostBucketRead=FALSE;
			}
			else
			{
				sec->isFirstResponseBucketRead=FALSE;
			}
		}
		else
		{
			if(sec->insertId && sec->maxAllowedPacket>length+len)
			{
				dump_mysql_record_post_or_response(r, sec, is_post, buffer, buffer_length);
				length+=len;
			}
		}

		// set bucket readed length
		if(is_post)
		{
			sec->post_readed_length=length;
		}
		else
		{
			sec->response_readed_length=length;
		}
	}
	sec->mysql_execute_time+=(apr_time_now()-sec->mysql_current_time);
	*ref_is_first=is_first;
	*ref_length=length;
}

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
	conn_rec *c = r->connection;
	dump_mysql_config_rec *sec = (dump_mysql_config_rec *)ap_get_module_config (r->per_dir_config, &dump_mysql_module);

	apr_bucket *b,*bh;
	apr_size_t len=0;

	input_context *ctx;

	int ret;
	char *buffer=NULL,*buf;
	int length,buffer_length;
	BOOL is_first;

	is_first=sec->isFirstPostBucketRead;
	length=sec->post_readed_length;

	if(!(ctx=f->ctx))
	{
		f->ctx = ctx = apr_palloc(r->pool, sizeof(input_context));
		ctx->bb = apr_brigade_create(r->pool, c->bucket_alloc);
	}

	if (APR_BRIGADE_EMPTY(ctx->bb)) {
		ret = ap_get_brigade(f->next, ctx->bb, mode, block, readbytes);

		if (mode == AP_MODE_EATCRLF || ret != APR_SUCCESS)
			return ret;
	}

	while(!APR_BRIGADE_EMPTY(ctx->bb)) {
		b = APR_BRIGADE_FIRST(ctx->bb);

		if(APR_BUCKET_IS_EOS(b)) {
			APR_BUCKET_REMOVE(b);
			APR_BRIGADE_INSERT_TAIL(bb, b);
			break;
		}

		ret=apr_bucket_read(b, &buffer, &len, block);
		if(ret != APR_SUCCESS)
			return ret;

		dump_mysql_record(r, sec, TRUE, &is_first, &length, buffer, len);

		buf = apr_bucket_alloc(len, c->bucket_alloc);
		memcpy(buf,buffer,len);

		bh = apr_bucket_heap_create(buf, len, apr_bucket_free, c->bucket_alloc);
		APR_BRIGADE_INSERT_TAIL(bb, bh);
		apr_bucket_delete(b);
	}

	return APR_SUCCESS;
}

/*
 * callback from Apache to do the authentication of the user to his
 * password.
 */
static int dump_mysql_output_filter (ap_filter_t *f, apr_bucket_brigade *bb)
{
	request_rec *r = f->r;
	conn_rec *c = r->connection;
	dump_mysql_config_rec *sec = (dump_mysql_config_rec *)ap_get_module_config (r->per_dir_config, &dump_mysql_module);

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
		apr_bucket *b,*be,*bh;
		apr_bucket_brigade *ob;
		apr_size_t len=0;

		int ret;
		char *buffer=NULL,*buf;
		int length,buffer_length;
		BOOL is_first;

		is_first=sec->isFirstResponseBucketRead;
		length=sec->response_readed_length;

		ob=apr_brigade_create(r->pool, c->bucket_alloc);

		for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
			if(APR_BUCKET_IS_EOS(b))
			{
				apr_bucket *be=apr_bucket_eos_create(c->bucket_alloc);
				APR_BRIGADE_INSERT_TAIL(ob,be);
				continue;
			}
			ret = apr_bucket_read(b, &buffer, &len, APR_BLOCK_READ);
			if(ret != APR_SUCCESS)
				return ret;

			dump_mysql_record(r, sec, FALSE, &is_first, &length, buffer, len);

			buf = apr_bucket_alloc(len, c->bucket_alloc);
			memcpy(buf,buffer,len);

			bh = apr_bucket_heap_create(buf, len, apr_bucket_free, c->bucket_alloc);
			APR_BRIGADE_INSERT_TAIL(ob,bh);
		}
		apr_brigade_cleanup(bb);

		return ap_pass_brigade(f->next,ob);
	}

	ap_remove_output_filter(f);

	return ap_pass_brigade(f->next,bb);
}

static void dump_mysql_register_hooks(apr_pool_t *p)
{
	ap_hook_insert_filter(dump_mysql_insert_filter, NULL, NULL, APR_HOOK_LAST);
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
