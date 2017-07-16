#!/usr/bin/perl -w

my $mrtg_workdir = '/usr/local/www/apache22/data/diagrams/';  # Directory for MRTG to put its log files, keep the '/' in the end of path


# Do not modify folling lines unless you know what they are
#
# Line 1
#    current state of the first variable, normally 'incoming bytes count'
# Line 2
#    current state of the second variable, normally 'outgoing bytes count'
# Line 3
#    string (in any human readable format), telling the uptime of the target.
# Line 4
#    string, telling the name of the target.

if(  !$ARGV[0] )  {die  "沒有傳入伺服器名，範例 ./syslog2mrtg.pl 163.17.38.250\r\n";} 

$sch_filename = $mrtg_workdir. $ARGV[0].".1min.log";

open( FILE, "< $sch_filename") || die "read file wrong\n";
my ($ontime, $logcnt, $filcnt)= (1,0,0);

do{
	$line= <FILE>;
	$line=~ /(\d+)\s(\d+)\s(\d+)/;
	($rectime, $c, $fc)= ($1, $2, $3);
	# 5min
	if(time-$rectime > 60*5){$ontime=0;}
	else{
		$logcnt += $c;
		$filcnt += $fc;
	}
}while( $ontime );


print "$logcnt\n$filcnt\n5 mins\n$ARGV[0]\n";

