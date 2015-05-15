@echo off

del /f *.so *.lo *.lib *.exp

apxs -cia -L./lib -I./include /NODEFAULTLIB:LIBCMT.lib libapr-1.lib libaprutil-1.lib libmysql.lib libhttpd.lib mod_dump_mysql.c
copy /y D:\apxs\Apache24\modules\mod_dump_mysql.so
