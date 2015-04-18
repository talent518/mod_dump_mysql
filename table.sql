CREATE TABLE `apache_dump` (
  `dumpId` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `url` varchar(2048) NOT NULL,
  `method` varchar(10) NOT NULL,
  `ip` varchar(15) NOT NULL,
  `file` varchar(1024) DEFAULT NULL,
  `requestDateline` int(10) NOT NULL,
  `requestTime` timestamp NULL DEFAULT NULL,
  `requestHeader` text,
  `requestHeaderLength` int(11) unsigned NOT NULL,
  `postText` mediumtext,
  `postTextLength` int(11) unsigned NOT NULL,
  `responseCode` int(11) NOT NULL,
  `responseHeader` text,
  `responseHeaderLength` int(11) unsigned NOT NULL,
  `responseText` mediumblob,
  `responseTextLength` int(11) unsigned NOT NULL,
  `runTime` double NOT NULL,
  `dateline` int(10) DEFAULT NULL,
  `createTime` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`dumpId`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8