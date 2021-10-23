#!/usr/bin/sh

rm -rf .libs *.o *.slo *.lo *.la

apxs -cia -L/opt/lampp/lib -I/opt/lampp/include -lmysqlclient mod_dump_mysql.c

