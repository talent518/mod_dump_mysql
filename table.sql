CREATE TABLE `apache_dump` (
  `dumpId` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `url` varchar(2048) NOT NULL,
  `method` varchar(10) NOT NULL,
  `ip` varchar(15) NOT NULL,
  `requestDateline` int(10) NOT NULL,
  `requestTime` timestamp NULL DEFAULT NULL,
  `requestHeader` text,
  `postText` text,
  `responseCode` int(11) NOT NULL,
  `responseHeader` text,
  `responseText` mediumblob,
  `runTime` double NOT NULL,
  `dateline` int(10) DEFAULT NULL,
  `createTime` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`dumpId`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8