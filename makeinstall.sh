#!/usr/bin/sh

lampp stopapache

rm -rf .libs *.o *.slo *.lo *.la

apxs -c -L/opt/lampp/lib -I/opt/lampp/include -lmysqlclient -lm -lz mod_dump_mysql.c && \
apxs -i mod_dump_mysql.la

chown daemon.daemon /opt/lampp/modules/mod_dump_mysql.so

lampp startapache