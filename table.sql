DROP TABLE IF EXISTS `apache_dump`;

CREATE TABLE `apache_dump` (
  `dumpId` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `scheme` varchar(20) DEFAULT NULL,
  `port` smallint(5) DEFAULT NULL,
  `protocol` varchar(10) DEFAULT NULL,
  `url` varchar(2048) DEFAULT NULL,
  `method` varchar(10) DEFAULT NULL,
  `ip` varchar(15) DEFAULT NULL,
  `file` varchar(1024) DEFAULT NULL,
  `requestDateline` int(10) DEFAULT NULL,
  `requestTime` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `requestHeader` text DEFAULT NULL,
  `requestHeaderLength` int(11) unsigned DEFAULT NULL,
  `postText` longblob DEFAULT NULL,
  `postTextLength` int(11) unsigned DEFAULT 0,
  `responseCode` int(11) DEFAULT NULL,
  `responseHeader` text DEFAULT NULL,
  `responseHeaderLength` int(11) unsigned DEFAULT 0,
  `responseText` longblob DEFAULT NULL,
  `responseTextLength` int(11) unsigned DEFAULT NULL,
  `runTime` double DEFAULT NULL,
  `dateline` int(10) DEFAULT NULL,
  `createTime` timestamp NULL DEFAULT NULL,
  `updateDateline` int(10) DEFAULT NULL,
  `updateTime` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`dumpId`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

