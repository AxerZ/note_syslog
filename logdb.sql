--
-- 資料庫: `logdb`
--

-- --------------------------------------------------------

--
-- 資料表格式： `manager`
--

CREATE TABLE IF NOT EXISTS `manager` (
  `mID` mediumint(9) NOT NULL AUTO_INCREMENT,
  `host` varchar(32) COLLATE utf8_bin NOT NULL,
  `mname` varchar(12) COLLATE utf8_bin NOT NULL,
  `email` varchar(48) COLLATE utf8_bin NOT NULL,
  `createdDT` datetime NOT NULL,
  PRIMARY KEY (`mID`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=4 ;

-- --------------------------------------------------------

--
-- 資料表格式： `perllogs`
--

CREATE TABLE IF NOT EXISTS `perllogs` (
  `seq` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `host` varchar(32) COLLATE utf8_bin DEFAULT NULL,
  `facility` varchar(10) COLLATE utf8_bin DEFAULT NULL,
  `priority` varchar(10) COLLATE utf8_bin DEFAULT NULL,
  `level` varchar(10) COLLATE utf8_bin DEFAULT NULL,
  `tag` varchar(4) COLLATE utf8_bin DEFAULT NULL,
  `date` date DEFAULT NULL,
  `time` time DEFAULT NULL,
  `program` varchar(24) COLLATE utf8_bin DEFAULT NULL,
  `msg` text COLLATE utf8_bin,
  `createdDT` datetime NOT NULL,
  PRIMARY KEY (`seq`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1 ;

