#!/usr/bin/sh

lampp stopapache

rm -rf .libs *.o *.slo *.lo *.la

apxs -cia -L/opt/lampp/lib -I/opt/lampp/include -lmysqlclient mod_dump_mysql.c

chown daemon.daemon /opt/lampp/modules/mod_dump_mysql.so

lampp startapache
