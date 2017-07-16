# note_syslog
A simple syslog server in PERL

Collect syslogs to your database;

# 簡易版SYSLOG伺服器

把大部分的SYSLOG都收錄到資料庫中
- logsrvmain.pl 收錄到資料庫主程式
- syslog2mrtg.pl 收錄筆數繪製MRTG
- logdb.sql 資料庫架構

需要PERL的套件
- use IO::Socket;
- use threads;
- use threads::shared;
- use DBI;
- use Text::Iconv;
- use Time::Local;
- use Time::Elapse;
- use Mail::Sendmail;

# 資料庫欄位
> --
> -- 資料庫: `logdb`
> --
> 
> -- --------------------------------------------------------
> 
> --
> -- 資料表格式： `manager`
> --
> 
> CREATE TABLE IF NOT EXISTS `manager` (
>   `mID` mediumint(9) NOT NULL AUTO_INCREMENT,
>  `host` varchar(32) COLLATE utf8_bin NOT NULL,
>  `mname` varchar(12) COLLATE utf8_bin NOT NULL,
>  `email` varchar(48) COLLATE utf8_bin NOT NULL,
>  `createdDT` datetime NOT NULL,
>  PRIMARY KEY (`mID`)
> ) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=4 ;
>
> -- --------------------------------------------------------
> 
> --
> -- 資料表格式： `perllogs`
> --
>
> CREATE TABLE IF NOT EXISTS `perllogs` (
>   `seq` int(10) unsigned NOT NULL AUTO_INCREMENT,
>   `host` varchar(32) COLLATE utf8_bin DEFAULT NULL,
>   `facility` varchar(10) COLLATE utf8_bin DEFAULT NULL,
>   `priority` varchar(10) COLLATE utf8_bin DEFAULT NULL,
>   `level` varchar(10) COLLATE utf8_bin DEFAULT NULL,
>   `tag` varchar(4) COLLATE utf8_bin DEFAULT NULL,
>   `date` date DEFAULT NULL,
>   `time` time DEFAULT NULL,
>   `program` varchar(24) COLLATE utf8_bin DEFAULT NULL,
>   `msg` text COLLATE utf8_bin,
>   `createdDT` datetime NOT NULL,
>   PRIMARY KEY (`seq`)
> ) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1 ;

