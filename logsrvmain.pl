#!/usr/bin/perl -w
# UDP SysLog-Server <<< Gather syslogs from servers and Insert to database
# 因為採用 syslog=ng + mysql，不知怎麼搞用一半就會停掉，不如自己來寫
# 程式設計 張本和 axer@ms1.boe.tcc.edu.tw 97.05.10
# Features:
#   1. Easy configuration of filters
#	2. Support IPv6
#   3. Filtered syslogs will be wrote to text file.

use IO::Socket;
use threads;
use threads::shared;
use DBI;
use Text::Iconv;
use Time::Local;
use Time::Elapse;
use Mail::Sendmail;

my @udp_listen_port = (514, 5140, 5144, 51444);
my $DB_IP="127.0.0.1";
my $DB_name="logdb";
my $DB_account="offline";
my $DB_passwd="2350";
my $log_interval=300; #log count in every 60 seconds
my $outputfile = "~/log.tmp";	# An unrecognized syslogs drops into this text file.
my $enable_mrtg = 1;	# set to 0 if disable mrtg
my $mrtg_path = '/usr/local/bin/mrtg';
my $mrtg_workdir = '/usr/local/www/apache22/data/diagrams/';  # Directory for MRTG to put its log files, keep the '/' in the end of path
my @filter;  #Don't modify this line.
my @notification;  #Don't modify this line.

# Filter the syslog.
# 
# Filter string: A filter string composed of three columns: host, key and restrict, which seperated by a ';'.
# Syntax   "HOST; KEY; RESTRICT"
# You can use a ',' to set multiple filter strings. For example: "host1, key1, res1", "host2, key2, res2", ...
# inside the parentheses of @filter.
# 
# If any filter string matches the 'DROP'(or DENIED) condition, the syslog will be DROPPED no matter other filter  
# string 'accept' this syslog.
#
# HOST is the hostname recorded in the syslog string, or acquired by the gethostbyaddr() if no hostname in the 
#      syslog string.
# KEY  is the key of filter, it can be one of (facility, priority, level, program, message).
# RESTRICT denotes KEY will be or will not be by add a '!' character.
#   If there're many RESTRICT parameters, you can use a ',' to seperate them. Filters will run through all of the
#   RESTRICT parameters from the start of parameter list, it will drop the log if there's no any parameter matched.
#   For example, if your filter string is "www; program; !sshd, sshd", the syslog with program "sshd" will NEVER be
#   dropped; Another exmaple, if you filter string is "www; program; !cron, sshd", the second parameter 'sshd' is
#   redundant and only the syslog with program 'cron' will be dropped.
#    
# ex..
# 1. Filter the level and priority.. (level and priority are the same value). The RESTRICT can be one of 
# (emerg, alert, crit, err, warning, notice, info, debug) or a range likes err..info and so on.
#
# "ldap; level; info..emerg" => Save syslogs of host ldap with level from info to emerg, and drop those syslogs 
#                               outside the level info to emerg.
# "ldap; level; !info..warning" => Ignore the syslogs of host ldap with level from info to warning.
# "www; level ; !info, err, emerg" => This is an ambiguous restrict, the filter string will not accept syslogs 
#                               only with level info.
# 
# 2. Filter the program and facility.. facility can be one of (kern, userlevel, mail, daemon, auth, syslogd, lineptr,
# netnews,uupc,cron,authpriv,ftp,ntp,logaudit,logalert,clock,local0,local1,local2,local3,local4,local5,local6,local7)
# "ldap; program; sshd" => Only save syslogs of host ldap with program sshd.
# If you don't want to save program ldapd and sendmail, the following string is wrong:
# "ldap; program; !ldapd, !sendmail"
# Because program ldapd don't be allowed with restrict !ldapd, however it is allowed by the second restrict !sendmail.
# So, the correct usage is to write two filter strings as follows:
# "ldap; program; !ldapd", "ldap; program; !webmail"
# System will drop the syslog immediately as long as it match the program '!ldapd'
# "www; facility; mail, auth, authpriv" => Only the three facilities (mail, auth, authpriv) are saved.
#
# 3. Filter the message 
# It is the most fascinated function, the system allows you to filter the message string. Unfortunately, it supports only
# "words"(A-Za-z0-9_), but the space or other characters.
# Let's see the following example..
# "dns; message; !FORMERR" => Log the syslog only whenever message has no the string 'FORMERR'
# "dns; message; inbound" => Save the syslog only when its message contains a string 'inbound'
#
# 4. Multiple Conditions
# Someone can use a word "and", "AND" or "&&" to combine several conditions, for example, you want to log program named 
# with level info..warning only, if you write down this, the result is not what you want.
# "dns; level, info..warning", "dns, program, named" => Log when level is info..warning "or" program is named.
# Therefore, you have to combine conditions:
# "dns; (level; info..warning) and (program; named)"
# Notice that each condition must be enclosed in parentheses: "host, (key1, res1) and (key2, res2) and ...."
#
# If you DO NOT want to log a program named when its level in info..warning, the filter string is logically confusing:
# "dns; (level; !info..warning) and (program; !named)" <== CORRECT
# "dns; (level; info..warning) and (program; !named)" <== WRONG1
# "dns; (level; !info..warning) and (program; named)" <== WRONG2
#
# Let's think about it slowly. Condition 1:(level; !info..warning) means "only deny log level info..warning" and Condition 2:
# (program; !named) represent "only deny program named". Now a syslog with level info and program named comes, it will 
# be denied by both Condition 1 and Condition 2. In other words, (DENIED) and (DENIED) = DENIED.
# On the contrary, the WRONG1 string means "we log all syslogs with level info..warning and its program is not named", we 
# simplify the wrong filter string as (ACCEPTED) and (DENIED) = ACCEPTED. 
# And WRONG2 string is (DENIED) and (ACCEPTED)= ACCEPTED.
# 
# 
# add more filters by scripting: push @filter, "filter1","filter2", ... ,"filterN";
push @filter,"ldap; program; !slapd","ldap; level; info..emerg","ftp.tcc.edu.tw; priority; info..emerg";
push @filter,"syslogd; facility; syslogd";
push @filter, "dns; (level; !info..notice) and (program; !named)", "dns; (level; !warning) and (message; !RFC)", "netflow.tcc.edu.tw; program; !sendmail" ;
push @filter, "PIX; message; !Deny%20inbound%20icmp";	#%20 means a space ' '

# Email abnormal syslogs to administrator
# 
# You can use 
# Syntax: "HOST; KEY; RESTRICT"
# 
# HOST: Specify a host or '*' to represent all the hosts.
# KEY: is same with the KEY of filter syntax.
# RESTRICT: is same with the RESTRICT of filter syntax.
#
my $enable_email ="YES";	# Set to YES if you want the administrator to catch abnormal email notification.
my $email_interval=1200; # interval to send notification email in second.
my $use_database = "YES"; # Set to YES if you want to use database as datasource of administators, by default program will query table
						  # "manager" to find out the administrator of this host.
 # Set a global administrator email. Don't remove the slash '\' in front of '@'.
my $adm_email = "axer\@ms1.boe.tcc.edu.tw";

push @notification, "*; level; emerg..err", "*; (facility; auth, authpriv) and (level; notice..emerg)";
push @notification, "ftp.tcc.edu.tw; level; emerg..err", "ftp.tcc.edu.tw; (facility; auth, authpriv) and (level; notice..emerg)";
push @notification, "www.tcc.edu.tw; level; emerg..err", "www.tcc.edu.tw; (facility; auth, authpriv) and (level; notice..emerg)";
push @notification, "netflow.tcc.edu.tw; level; emerg..err", "netflow.tcc.edu.tw; (facility; auth, authpriv) and (level; notice..emerg)";
push @notification, "db3; level; emerg..err", "db3; (facility; auth, authpriv) and (level; notice..emerg)";
push @notification, "ldap; level; emerg..err", "ldap; (facility; auth, authpriv) and (level; notice..emerg)";
push @notification, "163.17.40.53; level; emerg..err", "163.17.40.53; (facility; auth, authpriv) and (level; notice..emerg)";
#push @notification, "www.tcc.edu.tw; level; emerg..err", "www.tcc.edu.tw; facility; auth, authpriv";
#push @notification, "dns3; facility; auth, authpriv",  "diamond.tcc.edu.tw; (facility; auth, authpriv) and (level; notice..emerg)";

#========================================== WARNING ====================================================
#======= Following lines are program kernel, do not modify them if you don't know what they are ========
my $now;
my %lvcnt :shared;
my $total :shared;
my $totalfiltered :shared;
my %filterlv :shared;
my %filterule :shared;
my %notifcnt  :shared;
my %notifmsg :shared;
my @oldnotif = @notification;
$total=0;$totalfiltered=0;
# Start the timer
#Time::Elapse->lapse($now);
my @facility= ( "kern", "userlevel", "mail", "daemon", "auth", "syslogd", "lineptr","netnews", "uupc","cron", "authpriv", "ftp", "ntp", "logaudit", "logalert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7");
my @level = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug");
my @mon = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep" , "Oct", "Nov", "Dec" );
my $ii = 0;
my %mon = map { $_ => ++$ii } @mon;
$log_interval=10 if  $log_interval<10;
$email_interval=10 if $email_interval<10;

print "Syslog UDP server by axer\@ms1.boe.tcc.edu.tw\nProgram is listening...\n";

foreach (@udp_listen_port){
    #送入執行緒
    $thr[$_] = threads->create('zaket_listen_thread', $_ );
}
# 結束thread
foreach (@udp_listen_port){
    $thr[$_]->join();
}

sub zaket_listen_thread {
	my $DB = DBI->connect("DBI:mysql:dbname=$DB_name;host=".$DB_IP, $DB_account , $DB_passwd) or die "Cannot connect to $DB_IP: $!\n";
	my @args = @_;
	my $port=$args[0];
	my ($lv, $fac, $sql, $date, $time, $host, $chk);
	my $tid= threads->tid();
    print "Thread[$tid] listen udp port on $port\n";
	my $server = IO::Socket::INET->new(LocalPort =>  $port, Proto => "udp") or print "Couldn't be a udp server on port $port : $@\n";
	my %host1m=();
	my %host1mcnt=();
    my %filterhost=();

my @tmp;
foreach( @filter ){
    $_ =~ s/ //g;
	$_ =~ s/%20/ /g;
    if(  $_ =~ /^([.\w]+);(\(.+\))/){
        ($filhost, $ky)= ($1, $2);
        @mcond= split( /and|AND|&&|And/, $ky);
        @mcond =map { &trim($_) }@mcond;
        if($#mcond ==0) { die "Filter string error at: @mcond"; }
        $ii=0;
        foreach(@mcond){
            $_ =~ /\(([\w]+);([!.\/\w]+)/;
#            print "$_ <==\n";
            $ky = &trim($1);
            $ky = '{' . $ky if $ii == 0;
            $ky = $ky. '}' if $ii == $#mcond;
            push ( @tmp, "$filhost;$ky;".&trim($2));
            $ii++;
        }
    }
	else{ push @tmp, $_  } 
}
@filter = @tmp;
@tmp=();

foreach( @notification ){
    $_ =~ s/ //g;
    $_ =~ s/%20/ /g;
    if(  $_ =~ /^([\w.*]+);(\(.+\))/){
        ($filhost, $ky)= ($1, $2);
        @mcond= split( /and|AND|&&|And/, $ky);
        @mcond =map { &trim($_) }@mcond;
        if($#mcond ==0) { die "Filter string error at: @mcond"; }
        $ii=0;
        foreach(@mcond){
            $_ =~ /\(([\w]+);([!.\/\w]+)/;
#            print "$_ <==\n";
            $ky = &trim($1);
            $ky = '{' . $ky if $ii == 0;
            $ky = $ky. '}' if $ii == $#mcond;
            push ( @tmp, "$filhost;$ky;".&trim($2));
            $ii++;
        }
    }
    else{ push @tmp, $_  }
}
@notification = @tmp;
undef @tmp;
my $old_log=time;
my $old_time=time;

while ($server->recv($datagram, 1024, 0)) {
print $datagram;
my @logs;
# <43>Dec 23 22:58:26 dns2 syslog-ng[9961]: I/O error occurred while writing; fd='6', error='Connection refused (111)'
if( $datagram =~ /^<(\d+)>(\d+:\s)?([A-Za-z]+\s+\d+(\s\d+)?\s)?(\d+:\d+:\d+:?\s)?([\w\-\.]+\s|[\d:]+\s)?(.*)$/ ){
   	$lv=  $1 % 8; #"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"
    $fac = ($1-$lv)/8;
	my ($tag, $rest)= ( $1, $7);
	if(defined $3){	$date= &get_logdate($3);}
	else{ @arr=&get_datetime(); $date = shift @arr; }
    if(defined $5){ $time = &rtrim($5);}
    else{  @arr=&get_datetime(); $time = pop @arr; }
	if( defined($6)){$host= &rtrim($6);}
	else{ 
        my $ipaddr = $server->peeraddr();
        $host = gethostbyaddr($ipaddr, AF_INET);
		if( defined( $host)){ } # "host name: $host\n";}
		else{$host=inet_ntoa($ipaddr); print "host name unknownip". inet_ntoa($ipaddr)."\n";}
	}
	$host1m{"$host:$lv"}++;
	$host1mcnt{"$host"}++;
#	print "CountLevel{ $host:$level[$lv] } ". $host1m{"$host:$lv"} ." Count1min=".$host1mcnt{"$host"}."\n";
	$rest =~ /^([^:\[]+)(\[\d+\])?:\s?(.*)/;
    my ($program, $pid, $msg) = ($1, $2, $3);
	@logs = ($tag, $host, $lv, $fac, $date, $time, $program, $pid, $msg);

#print "\@logs = @logs \n";
	my $rr=1;
	foreach( @filter ){
      if( $_ =~ /([.\w]+);([{}\w]+);([,!. \/\w]+)$/){
          ($filhost, $ky, $restrict)= ($1, $2 ,$3);
	  }else{next;}
	  $and =0;
      $chk =1;	#chk=0 will be dropped
	  if( $filhost eq $host ){
        $chk= 0;
        @cond = split( /,/,$restrict );
		if( $ky =~ /^{(\w+)/ ){ $ky=$1;	$and =1; $mchk=0; }
		elsif( $ky =~ /(\w+)}$/ ){ $ky=$1; $and=2; }
        if( $ky eq 'facility'){
            foreach(@cond){
                if( $_ =~ /^(!)?(\w+)/ ){
                    if( ( !defined($1) && $2 eq $facility[$fac]) || (defined($1) && $2 ne $facility[$fac] )){ $chk=1; last; }
        }}}
        elsif( $ky eq 'priority' ||  $ky eq 'level' ){
            foreach(@cond){
                if( $_ =~ /^(!)?(\w+)$/ ){
                    if( ($1 ne '!' && $2 eq $level[$lv]) || (defined($1) && $2 ne $level[$lv] )){ $chk=1; last; }
                }elsif( $_ =~ /^(!)?(\w+)\.{2}(\w+)/ ){
                    ($not, $head, $tail) = ($1, $2, $3);
                    $t = join(',', @level);
                    if( $t =~ /${head}.+${tail}/i or $t =~ /${tail}.+${head}/i   ){
                        $levelrange= $&;
                        my $currlv=$level[$lv];
						if( not defined($not)){ if($levelrange =~ /${currlv}/){$chk=1; last;} }
						else{ if($levelrange !~ /${currlv}/){$chk=1; last;} }
		}}}}
        elsif( $ky eq 'program'){
            foreach(@cond){
                if( $_ =~ /^(!)?([\w\/]+)/ ){
                    if( ( !defined($1) && $2 eq $program) || (defined($1) && $2 ne $program )){ $chk=1; last; }
        }}}
        elsif( $ky eq 'message'){
            foreach(@cond){
                if( $_ =~ /^(!)?(\w+)/ ){
                    if(( !defined($1) && $msg =~ /${2}/) || (defined($1) &&  $msg !~ /${2}/) ){ $chk=1; last; }
        }}}
      }   #end if
      if( $and >=1){
		$rr--;
#		print "this chk $chk /or check: $mchk\n";
		$mchk |= $chk;
	    if( $and ==2){ $chk= $mchk; $and=0; }
	  }
      if( $and ==0 && $chk == 0){ last;}
      $rr++;
	}   #end foreach filter

	++$lvcnt{$level[$lv]};	#shared
	++$total;	#shared

	if($chk == 0){
    	$filterule{$rr}++;	 #shared
		$filterlv{$lv}++;	 #shared
		$totalfiltered++;	#shared
		$filterhost{$filhost}++;
		# Because of different thread, so the count values are counted in their own thread. 
		print "  !! Log filtered !! by Rule $rr ($filhost, $ky, $restrict) Count=". $filterule{$rr} ."; Level $level[$lv] count=". $filterlv{$lv} ."\n";
	}
	else{
#       system (`echo "$datagram" >> $outputfile`);
	    $sqltxt = "INSERT INTO `$DB_name`.`perllogs` (`host` ,`facility` ,`priority` ,`level` ,`tag` ,`date` ,`time` ,`program` ,`msg`, `createdDT` )";
	    $sqltxt .= " VALUES ( '$host', '$facility[$fac]', '$level[$lv]', '$level[$lv]', '$tag', '$date' , '$time' , '$program', ?, NOW());";
	    $DB->do( $sqltxt, undef, "$msg" );
	}
	# email start

    &chk_is_notif( @logs);

} # end line 235 if
else{
	print ("無法辨視的格式\n");
    system (`echo "$datagram" >> $outputfile`);
}

    select(undef,undef,undef,0.1);
	$time = time;
    if( $time - $old_time >= $email_interval ){
		my $msg ="";
		my $ii=0;
		my $sql;
print "\n---Send notification emails to administrator-----\n";
		if($enable_email eq "YES" && $old_time>0){
          my %email_ct=();
          my %email_man =();
		  while (($k, $v) = each(%notifcnt)){
			$msg ="";
			if( $v == 0){next;}
			$msg .=  "<b>syslog通報條件$k. $oldnotif[$k] 筆數 $v</b>\n".$notifmsg{"$k"}."\n";
			#"dns3;facility;auth,authpriv",
			if( $notification[$k] =~ /([^;]+);[^;]+;.+/ ){
		        $sql= $DB->prepare( "SELECT `mname`,`email` from `$DB_name`.`manager` where `host`=?");
print $1."\n";
		        $sql->bind_param( 1, $1);
			    $sql->execute;
			    $sql->bind_columns( undef, \$mname, \$to);
		        while($sql->fetch()){
					$email_ct{"$to"} .= $msg;	
					$email_man{"$to"} = $mname;
				}
			}
		  }
          while (($k, $v) = each(%email_man)){
			&email_to( $email_ct{"$k"}, $k, $v );
          }
		}
		$old_time= $time;
		%notifmsg=();
		%notifcnt=();
	}
	
    if( $time - $old_log >= $log_interval ){
			$old_log= $time;
			my $ky="total";
			if( $total >0){
			{ #lock
			lock($total);
			lock($totalfiltered);
            $rnd= time. " ".  $totalfiltered. " ". $total;
            print "寫入sysleg流量記錄..全部\n";
            my $ct="";
            $fname="$mrtg_workdir$ky.1min.log";
            if( open(FILE, "< $fname")){
	            $ct .= $_ while sysread(FILE, $_, 2 ** 10);
                $ct = $rnd."\n". $ct;
                close(FILE);
                if(open(FILE, "> $fname")){
    	            print FILE $ct;
                    close(FILE);
                }else { print "write log failed: $!";}
            }
            else{`echo $rnd >> $fname`;}
			$total=0;
			$totalfiltered=0;
			} #unlock
			}
#			while (($ky, $v) = each(%host1mcnt)){
            foreach(keys %filterlv){
				lock( %lvcnt );
				lock( %filterlv );
                $ky=$_;
                $lvname= $level[$ky];
				$totallv= $lvcnt{$lvname};
				if($totallv>0){
                $rnd= time. " ". $filterlv{$ky}. " ". $totallv;
                print "寫入syslog lv流量記錄..$lvname\n";
                $ct="";
                $fname="$mrtg_workdir$lvname.1min.log";
                if( open(FILE, "< $fname")){
                    $ct .= $_ while sysread(FILE, $_, 2 ** 10);
                    $ct = $rnd."\n". $ct;
                    close(FILE);
                    if(open(FILE, "> $fname")){
                        print FILE $ct;
                        close(FILE);
                    }else { print "write log failed: $!";}
                }
                else{`echo $rnd >> $fname`;}
                $lvcnt{$lvname}=0;
                $filterlv{$ky}=0;
				}
            }
			foreach(keys %host1mcnt){
				$ky=$_;
				$filhost= (defined  $filterhost{$ky})?$filterhost{$ky}:0;
			    $rnd= time. " ". $filhost. " ". $host1mcnt{$ky};
				if($host1mcnt{$ky}>0){
				print "寫入syslog流量記錄..$ky\n";
				$ct="";
				$fname="$mrtg_workdir$ky.1min.log";
				if( open(FILE, "< $fname")){
	                $ct .= $_ while sysread(FILE, $_, 2 ** 10);
    	            $ct = $rnd."\n". $ct;
        	        close(FILE);
            	    if(open(FILE, "> $fname")){
	                	print FILE $ct;
    	                close(FILE);
					}else { print "write log failed: $!";}
				}
				else{`echo $rnd >> $fname`;}
				$host1mcnt{$ky}=0;
				$filterhost{$ky}=0;
    		    $|=2;
				}
			sleep(1);	#write 1 time in this second
		}
		} # end write flow rec

    } #end while
}


sub chk_is_notif {
  local ($tag, $host, $lv, $fac, $date, $time,  $program, $pid, $msg) = @_;
  $pid = undef; $tag = undef;
  my $rrr=-1;
  my ($and, $mchk, $chk); 
  $and=0;
  foreach( @notification ){
	$rrr++;
	my ($notifhost, $ky, $restrict);
	if( $_ =~ /([.*\w]+);([{}\w]+);([,!. \/\w]+)$/){
          ($notifhost, $ky, $restrict)= ($1, $2 ,$3);
    }else{next;}
    $chk=0; #will be ignored
    if( ($notifhost eq $host) || ($notifhost eq '*') ){
        my @cond = split( /,/,$restrict );
        if( $ky =~ /^{(\w+)/ ){ $ky=$1; $and =1; $mchk=1; }
        elsif( $ky =~ /(\w+)}$/ ){ $ky=$1; $and=2; }
        if( $ky eq 'facility'){
            foreach(@cond){
                if( $_ =~ /^(!)?(\w+)/ ){
                    if( ( !defined($1) && $2 eq $facility[$fac]) || (defined($1) && $2 ne $facility[$fac] ))
                        {$chk=1;}
        }}}
        elsif( $ky eq 'priority' ||  $ky eq 'level' ){
            foreach(@cond){
                if( $_ =~ /^(!)?(\w+)$/ ){
                    if( ( !defined($1) && $2 eq $level[$lv]) || (defined($1) && $2 ne $level[$lv] )){ $chk=1; print"MATCH level\n"; }
                }elsif( $_ =~ /^(!)?(\w+)\.{2}(\w+)/ ){
                    ($not, $head, $tail) = ($1, $2, $3);
                    $t = join(',', @level);
                    if( $t =~ /${head}.+${tail}/i or $t =~ /${tail}.+${head}/i   ){
                        $levelrange= $&;
                        my $currlv=$level[$lv];
#print"currlv=$currlv, levelrange=$levelrange\n";
                        if( not defined($not)){ if($levelrange =~ /${currlv}/){$chk=1;} }
                        else{ if($levelrange !~ /${currlv}/){$chk=1;} }
        }}}}
        elsif( $ky eq 'program'){
            foreach(@cond){
                if( $_ =~ /^(!)?([\w\/]+)/ ){
                    if( ( !defined($1) && $2 eq $program) || (defined($1) && $2 ne $program )){ $chk=1; print"MATCH program\n"; }
        }}}
        elsif( $ky eq 'message'){
            foreach(@cond){
                if( $_ =~ /^(!)?(\w+)/ ){
                    if(( !defined($1) && $msg =~ /${2}/) || (defined($1) &&  $msg !~ /${2}/) ){ $chk=1; print"MATCH message\n";}
        }}}
    }  #end if
    if( $and >=1){
        $rrr--;
        $mchk &= $chk;
#       print "rrr=$rrr, chk=$chk, and=$and, mchk=$mchk\n";
        if( $and ==2){ $chk= $mchk; $and=0; $rrr++; }
    }
    if( $and ==0 && $chk == 1){
	#	print "chk=$chk, and=$and\n";
    	$notifcnt{"$rrr"} ++;
        $nn ="主機 [$host] 記錄時間 $date $time 機構 $facility[$fac] 等級 $level[$lv] 程式 $program<br>訊息內容 $msg<br>";
        $notifmsg{"$rrr"} .= $nn;
        print $nn."\n";
    }
  }  #end foreach
}

sub email_to {
	$msg= shift;
	$to = shift;
	$mname =shift;
    ($now_date, $now_time) = &get_datetime();
	my $converter = Text::Iconv->new("UTF-8", "Big5");
    my $subject_big5 = $converter->convert("$now_date $now_time syslog通報");
    my $from_txt= $converter->convert("台中縣教網中心 網路組")."<adminnet\@ms1.boe.tcc.edu.tw>";
    my $msg_big5=<<ENDMSG;
$mname 老師您好：以下為系統記錄狀況通報 <<此為系統自動發信，請勿直接回覆此信>><BR>
<pre><big>
統計時間：$now_date $now_time
$msg

說明：
<B>記錄通報</b> 目前系統會針對以下狀況每隔 $email_interval 秒送出通知信
1. 等級 notice(含) 以上
2. 系統有登入登出的情況

如不願收到此信，請Email 通知網路組 張本和 axer\@ms1.boe.tcc.edu.tw
其他資訊 [<a href=http://syslog.tcc.edu.tw/>系統 Syslog 狀況MRTG圖</a>]

                                                         台中縣教網中心 網路組
</big></pre>
ENDMSG
    my $mailunit;
	print "mailsent $to\n";
    $msg_big5=$converter->convert("$msg_big5");
    my %mail = ( 'To' => "$to",
        'From'    => "$from_txt",
        'Subject' => "$subject_big5",
        'Message' => "$msg_big5",
        'content-type' => 'text/html; charset="big5"',
    );
    sendmail(%mail) or die $Mail::Sendmail::error;
}

sub get_datetime {
        ($sec,$min,$hour,$day,$mon,$year)=localtime(time);
        my $now_date=join("-",($year+1900,$mon+1,$day));
        my $now_time=join(":",($hour,$min,$sec));
		return ( $now_date, $now_time);
}

sub get_logdate {
        ($sec,$min,$hour,$day,$mon,$year)=localtime(time);
        $year +=1900;
        my $mday=shift;
        $mday =~ /^(\S+)\s+(\d+)/; #Nov 11
        return "$year-$mon{$1}-$2";
}
sub rtrim {
	my $str=shift;
	$str =~ s/\s+$//g;
	return $str;
}

sub ltrim {
    my $str=shift;
    $str =~ s/^\s+//g;
    return $str;
}

sub trim {
    my $str=shift;
    $str = &rtrim( $str);
    $str = &ltrim( $str);	
    return $str;
}

