## OpenCA::DBI
##
## Copyright (C) 2000-2001 Michael Bell (michael.bell@web.de)
## GNU public license
##
## Code parts from OpenCA::DB are under the following license
## (copyright statement from OpenCA::DB v0.8.7a
##
## Copyright (C) 1998-1999 Massimiliano Pala (madwolf@openca.org)
## All rights reserved.
##
## This library is free for commercial and non-commercial use as long as
## the following conditions are aheared to.  The following conditions
## apply to all code found in this distribution, be it the RC4, RSA,
## lhash, DES, etc., code; not just the SSL code.  The documentation
## included with this distribution is covered by the same copyright terms
## 
## Copyright remains Massimiliano Pala's, and as such any Copyright notices
## in the code are not to be removed.
## If this package is used in a product, Massimiliano Pala should be given
## attribution as the author of the parts of the library used.
## This can be in the form of a textual message at program startup or
## in documentation (online or textual) provided with the package.
## 
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions
## are met:
## 1. Redistributions of source code must retain the copyright
##    notice, this list of conditions and the following disclaimer.
## 2. Redistributions in binary form must reproduce the above copyright
##    notice, this list of conditions and the following disclaimer in the
##    documentation and/or other materials provided with the distribution.
## 3. All advertising materials mentioning features or use of this software
##    must display the following acknowledgement:
##    "This product includes OpenCA software written by Massimiliano Pala
##     (madwolf@openca.org) and the OpenCA Group (www.openca.org)"
## 4. If you include any Windows specific code (or a derivative thereof) from 
##    some directory (application code) you must include an acknowledgement:
##    "This product includes OpenCA software (www.openca.org)"
## 
## THIS SOFTWARE IS PROVIDED BY OPENCA DEVELOPERS ``AS IS'' AND
## ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
## ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
## FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
## DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
## OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
## HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
## LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
## OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
## SUCH DAMAGE.
## 
## The licence and distribution terms for any publically available version or
## derivative of this code cannot be changed.  i.e. this code cannot simply be
## copied and put under another distribution licence
## [including the GNU Public Licence.]
##
## end of license of OpenCA::DB v0.8.7a
##

use strict;
use DBD::DB2::Constants;

package OpenCA::DBI;

## We must store/retrieve CRLs,CERTs,REQs objects:
## proper instances of object management classes are
## needed.
## see http://www.informatik.hu-berlin.de/~mbell/OpenCA/OpenCA_DBI/OpenCA_DBI.html
## for more information about the datastructure

use OpenCA::REQ;
use OpenCA::X509;
use OpenCA::CRL;
use OpenCA::CRR;
use OpenCA::OpenSSL;
use OpenCA::Tools;
use DBI;
use OpenCA::DBIS;

## the other use directions depends from the used databases

## $Revision: 1.12 $

$OpenCA::DBI::VERSION = 'DBI 0.4.3a';

##################
## DB Org-stuff ##
##################

############################################################################
##  PLEASE read carefully the following conventions before you            ##
##  edit something of the database code                                   ##
############################################################################
##  1.  don't use plural at sometime because you can come into trouble    ##
##      with types                                                        ##
##  2.  please write all types and all names small - this is not good     ##
##      sql-style but sybase ase and ibm db2 for example has no problems  ##
##      with this (they made it big ;-) ). PostgreSQL has with it's       ##
##      standard configuration (tested on debian 2.2 i386) really big     ##
##      trouble with names of tables and variables in big letters because ##
##      it tries to convert it to small letters but it don't works        ##
##      correctly (I think because it reports errors of mdopen that the   ##
##      lowercase forget the filename).                                   ##
############################################################################

$OpenCA::DBI::SQL = {
                     TABLE => { 
                               REQUEST        => "request",
                               CERTIFICATE    => "certificate",
                               CA_CERTIFICATE => "ca_certificate",
                               CRR            => "crr",
                               CRL            => "crl",
                               LOG            => "log",
                               SIGNATURE      => "signature",
                               SEQUENCE       => "openca_log_sequence"
                              },
                     ## I use here several duplicate array
                     ## somewhere I have to stop the complexity ...
                     VARIABLE => {
                                  DATE                  => ["date",          "TEXT"],
                                  SUBMIT_DATE           => ["date",          "TEXT"],
                                  FORMAT                => ["format",        "TEXT"],
                                  DATA                  => ["data",          "TEXT"],
                                  INFO                  => ["info",          "TEXT"],

                                  SERIAL                => ["serial",        "BIGINT"],
                                  KEY                   => ["mykey",         "TEXT_KEY"],

                                  CERTIFICATE_SERIAL    => ["cert_key",      "TEXT_KEY"],
                                  CA_CERTIFICATE_SERIAL => ["ca_cert_key",   "TEXT_KEY"],
                                  REQUEST_SERIAL        => ["req_key",       "TEXT_KEY"],
                                  CRR_SERIAL            => ["crr_key",       "TEXT_KEY"],
                                  CRL_SERIAL            => ["crl_key",       "TEXT_KEY"],

                                  LOG_SERIAL            => ["action_number", "BIGINT"],
                                  SIGNATURE_SERIAL      => ["action_number", "BIGINT"],
                                  # end of redefined variables
                                  
                                  # for searching
                                  DN                    => ["dn",            "TEXT"],
                                  CN                    => ["cn",            "TEXT"],
                                  EMAIL                 => ["email",         "TEXT"],
                                  RA                    => ["ra",            "TEXT"],
                                  RAO                   => ["rao",           "TEXT"],
                                  Operator              => ["rao",           "TEXT"],
                                  OPERATOR              => ["rao",           "TEXT"],
                                  LAST_UPDATE           => ["last_update",   "TEXT"],
                                  NEXT_UPDATE           => ["next_update",   "TEXT"],
                                  DATATYPE              => ["datatype",      "TEXT"],
                                  ROLE                  => ["role",          "TEXT"],
                                  
                                  # logging and integrity support
                                  STATUS                => ["status",        "TEXT"],
                                  REASON                => ["reason",        "TEXT"],
                                  ACTION_NUMBER         => ["action_number", "BIGINT"],
                                  MODULETYPE            => ["moduletype",    "TEXT"],
                                  MODULE                => ["module",        "TEXT"],
                                  LOG_SUBMIT_DATE       => ["submit_date",   "TEXT"],
                                  LOG_DO_DATE           => ["do_date",       "TEXT"],
                                  ROLE_SIGNATURE        => ["role_signature","TEXT"],
                                  HEADER_SIGNATURE      => ["header_signature","TEXT"],
                                 }
                    };

## second call to $OpenCA::DBI::SQL because I use content of this variable
$OpenCA::DBI::SQL->{TABLE_STRUCTURE} = 
  {
   REQUEST => [
               "REQUEST_SERIAL",
               "FORMAT",
               "DATA",
               "INFO",
               "DN",
               "CN",
               "EMAIL",
               "RA",
               "Operator",
               "STATUS",
               "ROLE",
               "HEADER_SIGNATURE"
              ],
   CERTIFICATE => [
                   "CERTIFICATE_SERIAL",
                   "FORMAT",
                   "DATA",
                   "INFO",
                   "DN",
                   "CN",
                   "EMAIL",
                   "STATUS",
                   "ROLE",
                   "ROLE_SIGNATURE",
                   "HEADER_SIGNATURE"
                  ],
   CA_CERTIFICATE => [
                      ## real serial senseless because at every time zero
                      "CA_CERTIFICATE_SERIAL",
                      "FORMAT",
                      "DATA",
                      "INFO",
                      "DN",
                      "CN",
                      "EMAIL",
                      "STATUS"
                     ],
   CRR => [
           "CRR_SERIAL",
           "CERTIFICATE_SERIAL",
           "SUBMIT_DATE",
           "FORMAT",
           "DATA",
           "INFO",
           "DN",
           "CN",
           "EMAIL",
           "RA",
           "Operator",
           "STATUS",
           "REASON",
           "HEADER_SIGNATURE"
          ],
   CRL => [
           "CRL_SERIAL",
           "STATUS",
           "FORMAT",
           "DATA",
           "LAST_UPDATE",
           "NEXT_UPDATE",
           "INFO"
          ],
   LOG => [
           ## warning this is the only exception of the clear 
           ## design !!!
           ## the first element of log must be followed by SEQUENCE of 
           ## the $OpenCA::DBI::DB->{$type}...!!!
           "ACTION_NUMBER",
           "MODULETYPE",
           "MODULE",
           "LOG_SUBMIT_DATE",
           "LOG_DO_DATE",
           "KEY",
           "SUBMIT_DATE",  ## for CRRs
           "FORMAT",
           "DATA",
           "INFO",
           "CERTIFICATE_SERIAL",
           "ROLE",
           "DN",
           "CN",
           "EMAIL",
           "RA",
           "Operator",
           "LAST_UPDATE",
           "NEXT_UPDATE",
           "STATUS",
           "REASON",
           "ROLE_SIGNATURE",
           "HEADER_SIGNATURE"
          ],
   SIGNATURE => [
                 "ACTION_NUMBER",
                 # signer's serial !!!
                 "CERTIFICATE_SERIAL",
                 "DATE",
                 "FORMAT",
                 "DATA",
                 "INFO"
                ],
   ## this is for the future OpenCA::SYNC-module
   ## SYNC => [
   ##         ],
  };

$OpenCA::DBI::STATUS = {
			EXIST       => 1,
			VALID       => 2,
			RENEWED     => 3,
			UPDATED     => 4,
			PENDING     => 5,
			APPROVED    => 6,
			SUSPENDED   => 7,
			REVOKED     => 8,
			DELETED     => 9,
			ARCHIVIED   => 10,
			EXPIRED     => 11,
                        NONEXISTENT => 12,
                        ANY         => 13,
		       };

#########################
## end of DB Org-stuff ##
#########################

#################
## error-codes ##
#################

$OpenCA::DBI::ERROR = {
  
  SUCCESS            => 0,
  UNEXPECTED_ERROR   => 88888,
  ATTACK             => 16666,
                       
  # unspecific errors
  WRONG_DATATYPE               => 10001,
  NO_OBJECT                    => 10002,
  GETBASETYPE_FAILED           => 10003,
  UPDATE_WITHOUT_KEY           => 10004,
  UPDATE_WITHOUT_KEY           => 10005,
  ENTRY_EXIST                  => 10006,
  ENTRY_NOT_EXIST              => 10007,
  UNSUPPORTED_SEARCH_ATTRIBUTE => 10008,
  DB_TYPE_UNKNOWN              => 10009,
  SIGNING_LOG_FAILED           => 10010,
  ITEM_NOT_UNIQUE              => 10011,
  FALSE_MODE                   => 10012,
  FALSE_FAILSAFE               => 10013,
  FALSE_SECOND_CHANCE          => 10014,
  MISSING_PRIMARY_DATABASE     => 10015,
  MISSING_BACKUP_DATABASE      => 10016,
  MISSING_BACKEND              => 10017,
  MISSING_TOOLS                => 10018,

  CERTIFICATE_TABLE_EXIST      => 10020,
  CA_CERTIFICATE_TABLE_EXIST   => 10021,
  CRR_TABLE_EXIST              => 10022,
  CRL_TABLE_EXIST              => 10023,
  LOG_TABLE_EXIST              => 10024,
  SIGNATURE_TABLE_EXIST        => 10025,
  SEQUENCE_TABLE_EXIST         => 10026,
  RBAC_TABLE_EXIST             => 10027,
  REQUEST_TABLE_EXIST          => 10028,
  
  CANNOT_REMOVE_CA_CERTIFICATE => 10030,
  CANNOT_REMOVE_CRR            => 10031,
  CANNOT_REMOVE_CRL            => 10032,
  CANNOT_REMOVE_LOG            => 10033,
  CANNOT_REMOVE_SIGNATURE      => 10034,
  CANNOT_REMOVE_SEQUENCE       => 10035,
  CANNOT_REMOVE_RBAC           => 10036,
  CANNOT_REMOVE_REQUEST        => 10037,
  CANNOT_REMOVE_CERTIFICATE    => 10038,
  
  CANNOT_CREATE_CA_CERTIFICATE => 10040,
  CANNOT_CREATE_CRR            => 10041,
  CANNOT_CREATE_CRL            => 10042,
  CANNOT_CREATE_LOG            => 10043,
  CANNOT_CREATE_SIGNATURE      => 10044,
  CANNOT_CREATE_SEQUENCE       => 10045,
  CANNOT_CREATE_RBAC           => 10046,
  CANNOT_CREATE_REQUEST        => 10047,
  CANNOT_CREATE_CERTIFICATE    => 10048,
 
  CANNOT_INIT_SEQUENCE         => 10050,

  CANNOT_CREATE_OBJECT         => 10060,
  MISSING_ARG_TABLE            => 10061,
  MISSING_ARG_SERIAL           => 10062,
  MISSING_ARG_DATATYPE         => 10063,
  UNSUPPORTED_OBJECT           => 10064,
  ILLEGAL_STATUS               => 10065,
  ILLEGAL_DATE                 => 10067,

  # DB-errors
  # using bitwise-or for DIAGNOSTICS so (ERROR+20000) 
  # & ERROR_MASK -> yes/no
  
  CONNECT_FAILED        => 20001,
  SECOND_CONNECT_FAILED => 20002,
  NO_BACKUP             => 20004,
 
  PREPARE_FAILED        => 20008,
  EXECUTE_FAILED        => 20016,
  
  SELECT_FAILED         => 20032,
  UPDATE_FAILED         => 20064,
  INSERT_FAILED         => 20128,
  DELETE_FAILED         => 20256,
  COMMIT_FAILED         => 20512,
  ROLLBACK_FAILED       => 21024,
  DISCONNECT_FAILED     => 22048,
  SEQUENCE_GENERATOR_FAILED => 24096,

                      };
  
$OpenCA::DBI::MESSAGE = {
  
  0     => "Success",
  88888 => "Unexpected Error",
  16666 => "Possible Attack",
                       
  # unspecific errors
  10001 => "WRONG_DATATYPE",
  10002 => "NO_OBJECT",
  10003 => "GETBASETYPE_FAILED",
  10004 => "UPDATE_WITHOUT_KEY",
  10006 => "ENTRY_EXIST",
  10007 => "ENTRY_NOT_EXIST",
  10008 => "UNSUPPORTED_SEARCH_ATTRIBUTE",
  10009 => "DB_TYPE_UNKNOWN",
  10010 => "SIGNING_LOG_FAILED",
  10011 => "ITEM_NOT_UNIQUE",
  10012 => "FALSE_MODE - normally this means, that you are not using ".
           "secure or standard as the accessmode.",
  10013 => "FALSE_FAILSAFE - failsafe \"on|off\".",
  10014 => "FALSE_SECOND_CHANCE - second_chance \"yes|no\"",
  10015 => "MISSING_PRIMARY_DATABASE",
  10016 => "MISSING_BACKUP_DATABASE",
  10017 => "MISSING_BACKEND",
  10018 => "MISSING_TOOLS",
  
  10020 => "The table certificate already exists.",
  10021 => "The table ca_certificate already exists.",
  10022 => "The table crr already exists.",
  10023 => "The table crl already exists.",
  10024 => "The table log already exists.",
  10025 => "The table signature already exists.",
  10026 => "The sequence generator already exists.",
  10027 => "The table rbac already exists.",
  10028 => "The table request already exists.",
  
  10030 => "Cannot drop the table ca_certificate.",
  10031 => "Cannot drop the table crr.",
  10032 => "Cannot drop the table crl.",
  10033 => "Cannot drop the table log.",
  10034 => "Cannot drop the table signature.",
  10035 => "Cannot drop the sequence generator.",
  10036 => "Cannot drop the table rbac.",
  10037 => "Cannot drop the table request.",
  10038 => "Cannot drop the table certificate.",
  
  10040 => "Cannot create the table ca_certificate.",
  10041 => "Cannot create the table crr.",
  10042 => "Cannot create the table crl.",
  10043 => "Cannot create the table log.",
  10044 => "Cannot create the table signature.",
  10045 => "Cannot create the sequence generator.",
  10046 => "Cannot create the table rbac.",
  10047 => "Cannot create the table request.",
  10048 => "Cannot create the table certificate.",

  10050 => "Cannot init sequence generator.",  

  10060 => "CANNOT_CREATE_OBJECT",
  10061 => "MISSING_ARG_TABLE",
  10062 => "MISSING_ARG_SERIAL",
  10063 => "MISSING_ARG_DATATYPE",
  10064 => "UNSUPPORTED_OBJECT",
  10065 => "ILLEGAL_STATUS",
  10067 => "ILLEGAL_DATE",

  # DB-errors
  # using bitwise-or for DIAGNOSTICS so (ERROR+20000) 
  # & ERROR_MASK -> yes/no
  
  20001 => "CONNECT_FAILED",
  20002 => "SECOND_CONNECT_FAILED",
  20004 => "NO_BACKUP",
 
  20008 => "PREPARE_FAILED",
  20016 => "EXECUTE_FAILED",
  
  20032 => "SELECT_FAILED",
  20064 => "UPDATE_FAILED",
  20128 => "INSERT_FAILED",
  20256 => "DELETE_FAILED",
  20512 => "COMMIT_FAILED",
  21024 => "ROLLBACK_FAILED",
  22048 => "DISCONNECT_FAILED",
  24096 => "SEQUENCE_GENERATOR_FAILED",

                      };
  
## these vars are used to handle crashes during new
$OpenCA::DBI::ERRNO  = $OpenCA::DBI::ERROR->{SUCCESS};

#######################
## end of errorcodes ##
#######################  

################
## modulecodes ##
################

$OpenCA::DBI::MODULETYPE = {
                           UNKNOWN    => 0,
                           CA         => 1,
                           PKIManager => 2,
                           RA         => 3,
                           WebGateway => 4,
                           RAServer   => 5,
                          };
	      
#######################
## end of modulecodes ##
#######################

############################################
## begin of vendordependent databasestuff ##
############################################

## how much spped costs this for 10 databases (compared with 2 databases)?
$OpenCA::DBI::DB = {
                    ## get sequence is coded in sub getSequence (\%db_hash_write)
                    Pg => {
                           TYPE => {
                                    ## numeric available but not documented
                                    TEXT       => "text",
                                    TEXT_KEY   => "text",
                                    BIGINT     => "int8",
                                    PRIMARYKEY => "PRIMARY KEY NOT NULL",
                                    SEQUENCE   => "int8 primary key not null"
                                   },
                           DBI_OPTION => {
                                          RaiseError => 0, 
                                          Taint => 0, 
                                          AutoCommit => 0},
                           SEQUENCE => {
                                        CREATE   => "create sequence ".
                                        $OpenCA::DBI::SQL->{TABLE}->{SEQUENCE}.
                                        " START 0 INCREMENT 1 MINVALUE 0",
                                        INIT     => "",
                                        GENERATE => "insert into ".
                                        $OpenCA::DBI::SQL->{TABLE}->{LOG}."(".
                                        $OpenCA::DBI::SQL->{VARIABLE}->{ACTION_NUMBER}[0].
                                        ") VALUES (NEXTVAL('".
                                        $OpenCA::DBI::SQL->{TABLE}->{SEQUENCE}."'))",
                                        GENERATE_BY_INSERT => 1,
                                        DROP     => "drop SEQUENCE ".
                                        $OpenCA::DBI::SQL->{TABLE}->{SEQUENCE}
                                       }
                          },
                    ## sorry for the people who like mysql and msql but both don't
                    ## support transactions so please don't use them for OpenCA in
                    ## reallifesystems - this is negligent
                    ## if you have only such systems please use the OpenCA::DB-module
                    ## which is prepared for work with a system which don't support 
                    ## transactions
                    ## OpenCA::DBI is build to work correct with systems which support 
                    ## transactions !!!
                    mysql => {
                              TYPE => {
                                       ## numeric available but not documented
                                       TEXT       => "TEXT",
                                       TEXT_KEY   => "TEXT",
                                       BIGINT     => "BIGINT",
                                       PRIMARYKEY => "NOT NULL PRIMARY KEY",
                                       SEQUENCE   => "BIGINT AUTO_INCREMENT NOT NULL PRIMARY KEY"
                                      },
                              DBI_OPTION => {},
                              SEQUENCE => {
                                           CREATE   => "",
                                           INIT     => "",
                                           GENERATE => "insert into ".
                                           $OpenCA::DBI::SQL->{TABLE}->{LOG}."(".
                                           $OpenCA::DBI::SQL->{VARIABLE}->{ACTION_NUMBER}[0].
                                           ") VALUES (NULL)",
                                           GENERATE_BY_INSERT => 1,
                                           DROP     => ""
                                          }
                             },
                    DB2 => {
                            TYPE => {
                                     TEXT       => "long varchar",
                                     ## 255 is the limit for a index key in db2
                                     TEXT_KEY   => "varchar (255)",
                                     BIGINT     => "decimal (31, 0)",
                                     PRIMARYKEY => "PRIMARY KEY NOT NULL",
                                     SEQUENCE   => "decimal (31, 0) primary key not null"
                                    },
                            DBI_OPTION => {
                                           RaiseError => 0, 
                                           Taint => 0, 
                                           AutoCommit => 0},
                            SEQUENCE => {
                              CREATE   => "create table ".
                                $OpenCA::DBI::SQL->{TABLE}->{SEQUENCE}." ".
                                "( my_identity DECIMAL (31, 0) ".
                                "    GENERATED ALWAYS AS IDENTITY ".
                                "    (START WITH 0), ".
                                "  my_help INTEGER".
                                ")",
                              INIT     => "",
                              GENERATE => "insert into ".
                                $OpenCA::DBI::SQL->{TABLE}->{SEQUENCE}.
                                " ( my_help ) VALUES ( 0 )",
                              ## attention this is not a generate by insert
                              ## because the insert is done on a different table
                              GENERATE_BY_INSERT => 0,
                              DROP     => "drop table ".
                                $OpenCA::DBI::SQL->{TABLE}->{SEQUENCE}
                                        }
                           },
                    Oracle => {
                            TYPE => {
                                     TEXT       => "LONG",
                                     ## 2000 is the limit for varchar in Oracle7
                                     TEXT_KEY   => "varchar2 (1999)",
                                     BIGINT     => "number (38)",
                                     PRIMARYKEY => "PRIMARY KEY NOT NULL",
                                     SEQUENCE   => "number (38) primary key not null"
                                    },
                            DBI_OPTION => {
                                           RaiseError => 0, 
                                           Taint => 0, 
                                           AutoCommit => 0},
                            SEQUENCE => {
                                         CREATE   => "create sequence ".
                                         $OpenCA::DBI::SQL->{TABLE}->{SEQUENCE},
                                         INIT     => "",
                                         GENERATE => "insert into ".
                                         $OpenCA::DBI::SQL->{TABLE}->{LOG}."(".
                                         $OpenCA::DBI::SQL->{VARIABLE}->{ACTION_NUMBER}[0].
                                         ") VALUES (".
                                         $OpenCA::DBI::SQL->{TABLE}->{SEQUENCE}.
                                         ".nextval)",
                                         GENERATE_BY_INSERT => 1,
                                         DROP     => "drop SEQUENCE ".
                                         $OpenCA::DBI::SQL->{TABLE}->{SEQUENCE}
                                        }
                           },
                   };

##########################################
## end of vendordependent databasestuff ##
##########################################

$OpenCA::DBI::beginHeader     = "-----BEGIN HEADER-----";
$OpenCA::DBI::endHeader       = "-----END HEADER-----";
$OpenCA::DBI::beginAttribute  = "-----BEGIN ATTRIBUTE-----";
$OpenCA::DBI::endAttribute    = "-----END ATTRIBUTE-----";

## here a special remark
## OpenCA::DBI uses only PEM and such things like SPKAC ...
## binary data like DER is not storable in textfields

my $params = {
              mode          => "secure",
	      failsafe      => "off",
              second_chance => "no",
	      ## every other logsecuritylevel than 0 limits the range of 
	      ## the signed logs !!!
	      logsecurity    => undef,
	      logperformance => undef,
              MESSAGEKEY     => undef,
              MESSAGELENGTH  => undef,
              CERT_FILE      => undef,
              KEY_FILE       => undef,
              PASSWD         => undef,
              SignLog        => "Off",
	      ## don't define localType here !!!
	      ## it's used to detect the existence of a localDB
	      localType   => undef,
	      localHost   => undef,
	      localPort   => undef,
	      localName   => undef,
	      localUser   => undef,
	      localPasswd => undef,
	      localDB     => undef,
	      remoteType   => undef,
	      remoteHost   => undef,
	      remotePort   => undef,
	      remoteName   => undef,
	      remoteUser   => undef,
	      remotePasswd => undef,
	      remoteDB     => undef,
              standardDB     => undef,
              standardUser   => undef,
              standardPasswd => undef,
              standardType   => undef,
              backupDB     => undef,
              backupUser   => undef,
              backupPasswd => undef,
              backupType   => undef,
	      backend => undef,
	      tools   => undef,
	      ## debugging is off !!!
              DEBUG  => 0,
              ERRNO  => 0,
              ERRVAL => "",
	     };

sub new {
  
  # no idea what this should do
  
  my $that = shift;
  my $class = ref($that) || $that;
  
  ## my $self  = $params;
  my $self;
  my $help;
  foreach $help (keys %{$params}) {
    $self->{$help} = $params->{$help};
  }                                                                                          
 
  bless $self, $class;

  ## because db uses variablenames etc. I can't define it in $params :-(

  # ok here I start ;-)

  my $keys = { @_ };

  print "Starting to init a new OpenCA::DBI\n" if ($self->{DEBUG});

  # non-DB-specific

  $self->{DEBUG}          = 1 if ($keys->{DEBUG});

  $self->{backend}        = $keys->{SHELL};
  $self->{mode}           = $keys->{mode} if ($keys->{mode});
  $self->{failsafe}       = $keys->{failsafe} if ($keys->{failsafe});
  $self->{second_chance}  = $keys->{second_chance} if ($keys->{second_chance});

  ## signing and logrelevant code
  $self->{logsecurity}    = int ($keys->{logsecurity})    if (int ($keys->{logsecurity})    >= 0);
  $self->{logperformance} = int ($keys->{logperformance}) if (int ($keys->{logperformance}) >= 8);
  $self->{CERT_FILE}     = $keys->{CERT_FILE};
  $self->{KEY_FILE}      = $keys->{KEY_FILE};
  $self->{PASSWD}        = $keys->{PASSWD};
  $self->{MESSAGEKEY}    = $keys->{MESSAGEKEY};
  $self->{MESSAGELENGTH} = $keys->{MESSAGELENGTH};
  $self->{SignLog}       = $keys->{SignLog} if ( (uc $keys->{SignLog} eq "ON") or
                                                 (uc $keys->{SignLog} eq "OFF") or
                                                 (uc $keys->{SignLog} eq "YES") or
                                                 (uc $keys->{SignLog} eq "NO"));

  $self->{mode}          = "secure";
  $self->{second_chance} = "no";
  $self->{failsafe}      = "off";

  print "  defining the class parameters\n" if ($self->{DEBUG});

  # The minimum I need is remote: 
  # type, host, port, name, user, passwd

  $self->{remoteType} = $keys->{remoteType};
  $self->{remoteHost} = $keys->{remoteHost};
  $self->{remotePort} = $keys->{remotePort};
  $self->{remoteName} = $keys->{remoteName};
  $self->{remoteUser} = $keys->{remoteUser};
  $self->{remotePasswd} = $keys->{remotePasswd};

  $self->{localType} = $keys->{localType};
  $self->{localHost} = $keys->{localHost};
  $self->{localPort} = $keys->{localPort};
  $self->{localName} = $keys->{localName};
  $self->{localUser} = $keys->{localUser};
  $self->{localPasswd} = $keys->{localPasswd};
  
  # Check for all neccessary variables to initialize OpenCA:DBI 
  print "    checking the configuration for enough data\n" if ($self->{DEBUG});

  # backend is not required actually
  # if ( not $self->{backend} ) {
  #   $self->errno ( $OpenCA::DBI::ERROR->{ MISSING_BACKEND } );
  #   return undef;
  # }
  if (
      (
       ($self->{mode}     =~ /^secure$/i ) or
       ($self->{failsafe} =~ /^on$/i )
      )
      and
      (
       (not $self->{remoteType}) or
       (not $self->{remoteName}) or
       (not $self->{remoteUser}) or
       (not $self->{remotePasswd})
      )
     ) {
    $self->errno ( $OpenCA::DBI::ERROR->{MISSING_PRIMARY_DATABASE} );
    return undef;
  }

  if (
      (
       ($self->{mode}     =~ /^standard$/i ) or
       ($self->{failsafe} =~ /^on$/i )
      )
      and
      (
       (not $self->{localType}) or
       (not $self->{localName}) or
       (not $self->{localUser}) or
       (not $self->{localPasswd})
      )
     ) {
    $self->errno ( $OpenCA::DBI::ERROR->{MISSING_BACKUP_DATABASE} );
    return undef;
  }

  print "    checking for the tools\n" if ($self->{DEBUG});

  if ( not $self->{tools} = new OpenCA::Tools()) {
    $self->errno ( $OpenCA::DBI::ERROR->{ MISSING_TOOLS } );
    return undef;
  }

  # The availability of the databases is checked during the operations
  # because I have different accessed databases and perhaps failsafe.
  # I could only stop here if there is no database online but to write
  # here a very big test only for this purpose makes no sense.

  ###########################
  ## vendor dependent part ##
  ###########################

  ## preparing now the database-strings
  ## this is very database dependent
  print "    preparing the remote and local databases (vendor dependent)\n" 
    if ($self->{DEBUG});

  ## WARNING I don't include any attributes into the DSN
  ## because I don't know how widely version 1.10 of DBI is used actually
  ## END of WARNING

  $self->{remoteDB} = "dbi:".$self->{remoteType}.":";
  if ($self->{remoteType} eq "Pg") {
    print "      Pg detected for remoteDB\n" if ($self->{DEBUG});
    $self->{remoteDB} .= "dbname=".$self->{remoteName};
    $self->{remoteDB} .= ";"."host=".$self->{remoteHost} if ($self->{remoteHost});
    $self->{remoteDB} .= ";"."port=".$self->{remotePort} if ($self->{remotePort});
  } elsif ($self->{remoteType} eq "mysql") {
    print "      mysql detected for remoteDB\n" if ($self->{DEBUG});
    $self->{remoteDB} .= "database=".$self->{remoteName};
    $self->{remoteDB} .= ";"."host=".$self->{remoteHost} if ($self->{remoteHost});
    $self->{remoteDB} .= ";"."port=".$self->{remotePort} if ($self->{remotePort});
  } elsif ($self->{remoteType} =~ /^DB2$/ ) {
    print "      DB2 detected for remoteDB\n" if ($self->{DEBUG});
    $self->{remoteDB} .= $self->{remoteName};
  } elsif ($self->{remoteType} =~ /^Oracle$/ ) {
    print "      Oracle detected for remoteDB\n" if ($self->{DEBUG});
    ## you can use tnsname or sidname
    $self->{remoteDB} .= $self->{remoteName};
  } else {
   $self->errno ( $OpenCA::DBI::ERROR->{DB_TYPE_UNKNOWN} );
   return undef;
  }
  print "      remoteDB: ".$self->{remoteDB}."\n" if ($self->{DEBUG});

  $self->{localDB} = "dbi:".$self->{localType}.":";
  if ($self->{localType} eq "Pg") {
    print "      ODBC-like type detected for localDB\n" if ($self->{DEBUG});
    $self->{localDB} .= "dbname=".$self->{localName};
    $self->{localDB} .= ";"."host=".$self->{localHost} if ($self->{localHost});
    $self->{localDB} .= ";"."port=".$self->{localPort} if ($self->{localPort});
  } elsif ($self->{localType} eq "mysql") {
    print "      mysql detected for localDB\n" if ($self->{DEBUG});
    $self->{localDB} .= "database=".$self->{localName};
    $self->{localDB} .= ";"."host=".$self->{localHost} if ($self->{localHost});
    $self->{localDB} .= ";"."port=".$self->{localPort} if ($self->{localPort});    
  } elsif ($self->{localType} =~ /^DB2$/ ) {
    print "      DB2 detected for localDB\n" if ($self->{DEBUG});
    $self->{localDB} .= $self->{localName};
  } elsif ($self->{remoteType} =~ /^Oracle$/ ) {
    print "      Oracle detected for localDB\n" if ($self->{DEBUG});
    ## you can use tnsname or sidname
    $self->{localDB} .= $self->{localName};
  } else {
    $self->{localDB} = "";
    ## attention sometimes local is not used !!!
    if ($self->{localType}) {
      $self->errno ($OpenCA::DBI::ERROR->{DB_TYPE_UNKNOWN});
      return undef;
    }
  }
  print "      localDB: ".$self->{localDB}."\n" if ($self->{DEBUG});

  ##################################
  ## end of vendor dependent part ##
  ##################################


  # the following part is only for future use
  # I plan to develop a synclayer to support offline
  # certificate revocation etc.

  # initialization of databaseaccess
  # this is done by a matrix

  # during this process I ever test with local as true result
  # this prevent us to store data in a local misconfigured 
  # database if there was a mistake during writing the
  # configurationfile, e.g. ulttra-secure never should cause 
  # any local action !!! 

  print "    try to get a consistent operationmode\n" if ($self->{DEBUG});
  # compensate evtl. documentation-problems
  my $access_mode = lc ($self->{mode});
  my $do_failsafe = lc ($self->{failsafe});
  my $do_second_chance = lc ($self->{second_chance});
  
  # check for correct modesetting
  if ( $access_mode !~ /^(secure|standard)$/ ) {
    $self->errno ( $OpenCA::DBI::ERROR->{FALSE_MODE} );
    return undef;
  }
  if (not
      (
       ($do_failsafe eq "on") or
       ($do_failsafe eq "off")
      )
     ) {
    $self->errno ( $OpenCA::DBI::ERROR->{ FALSE_FAILSAFE } );
    return undef;
  }
  if (not
      (
       ($do_second_chance eq "yes") or
       ($do_second_chance eq "no") or
       ($do_second_chance eq "")
      )
     ) {
    $self->errno ( $OpenCA::DBI::ERROR->{ FALSE_SECOND_CHANCE } );
    return undef;
  }

  # Standard access matrix
  #
  # mode                 write                read
  #                standard  backup     standard  backup
  # -----------------------------------------------------------
  # ultra-secure   remote               remote
  # secure         remote               remote    local
  # standard       remote               local
  # progressive    remote    local      local
  # agressive      local                local
  #
  # failsafe cause a local access if remote access fails
  # Does someone need a seconde chance (local fails so local retry)?
  # I'm ready for discussion (performance vs. security/availability)
  # 
  # actually I don't give a second chance but I think I should do it.
  # 2000-Dec-18
  # I give a second chance if there is no other comment.
  #
  # 2001-Mar-08
  # due to relational concepts the first matrix is ideotic
  # RDBMS must support ACID-feature
  #
  # A atomicity
  # C consistency
  # I isolation
  # D durability
  #
  # if I would use different databases for read and write-operation then
  # I have no isolation and this is very dangerous
  # so the new matrix is
  #
  # mode           standard
  # -----------------------
  # secure         remote
  # standard       local
  #
  # failsafe activates a second try to the other database
  # second_chance activates second try to the same database
  # failesafe overwrites second_chance this mean
  #  * failsafe is a second chance
  #  * failsafe define that the second chance is not a retry

  print "    set standard and backup databases\n" if ($self->{DEBUG});

  # standard database
  if ($access_mode eq "standard") {
    $self->{standardDB}     = $self->{localDB};
    $self->{standardUser}   = $self->{localUser};
    $self->{standardPasswd} = $self->{localPasswd};
    $self->{standardType}   = $self->{localType};
  } else {
    ## access_mode is secure
    $self->{standardDB}     = $self->{remoteDB};
    $self->{standardUser}   = $self->{remoteUser};
    $self->{standardPasswd} = $self->{remotePasswd};
    $self->{standardType}   = $self->{remoteType};
  }
  
  # backup database
  if (
      (
       ($do_failsafe eq "on") and
       ($access_mode eq "secure")
      ) or
      (
       ($do_failsafe ne "on") and
       ($do_second_chance eq "on") and
       ($access_mode eq "standard" )
      )
     ) {
    $self->{backupDB}     = $self->{localDB};
    $self->{backupUser}   = $self->{localUser};
    $self->{backupPasswd} = $self->{localPasswd};
    $self->{backupType}   = $self->{localType};
  } else {
    # security is better then performance
    if (
        (
         ($do_second_chance eq "on") and
         ($access_mode      eq "secure")
        ) or
        (
         ($do_failsafe eq "on") and
         ($access_mode eq "standard" )
        )
       ) {
      $self->{backupDB}     = $self->{remoteDB};
      $self->{backupUser}   = $self->{remoteUser};
      $self->{backupPasswd} = $self->{remotePasswd};
      $self->{backupType}   = $self->{remoteType};
    } else {
      $self->{backupDB}         = "";
      $self->{backupUser}       = "";
      $self->{backupPasswd}     = "";
      $self->{backupType}       = "";
    }
  }

  print "  OpenCA::DBI should now complete\n" if ($self->{DEBUG});
  
  return $self;
  
}


#############################
## database initialization ##
#############################

sub initDB {
  ## Generate a new db and initialize it allowing the
  ## DB to keep track of the DB status
  
  my $self = shift;
  my $keys = { @_ };
  
  my $mode   = $keys->{MODE};
  my $dbs_h  = $keys->{DB};
  my @dbs;
  if ($dbs_h) {
    @dbs     = @{$keys->{DB}};
  }

  if ($self->{DEBUG}) {
    print "Entering sub initDB\n";
    print "  MODE: ".$mode."\n";
    foreach my $help (@dbs) {
      print "  DB: ".$help."\n";
    }
  }

  # most secure mode is used (ultra-secure)
  if (not scalar(@dbs)) {
    $dbs [0] = "remote";
  }
  
  ## Accepted modes are
  ## NONE
  ## FORCE  to force table creation on localDB
  ## FORCE_LOCAL  to force table creation on localDB
  ## FORCE_REMOTE to force table creation on remoteDB
  ## FORCE_ALL to force table creation on all DBs

  print "  Entering Loop for different databases\n" if ($self->{DEBUG});
 
  my ($db, $force, $table, $dsn, $type); 
  foreach $db (@dbs) {
    $db = lc $db;
    print "  database: ".$db."\n" if ($self->{DEBUG});
    # force ?
    $force = 0;
    if ( ($db eq "local") and 
	 (($mode eq "FORCE") or 
	  ($mode eq "FORCE_LOCAL") or
          ($mode eq "FORCE_ALL")
	 )
       ) {
      $force = 1;
    }
    if ( ($db eq "remote") and
	 (($mode eq "FORCE_REMOTE") or ($mode eq "FORCE_ALL"))
       ) {
      $force = 1;
    }
    print "    force: ".$force."\n" if ($self->{DEBUG});
    if (($self->{DEBUG}) and $force) {
      print "    ###############################\n";
      print "    ## WARNING - FORCEMODE IS ON ##\n";
      print "    ##   DESTRUCTING ALL TABLES  ##\n";
      print "    ###############################\n";
    }
    
    foreach $table (keys %{$OpenCA::DBI::SQL->{TABLE}}) {
      print "    table: ".$table."\n" if ($self->{DEBUG});
      # check for existence
      if ($db eq "local") {
	$dsn  = $self->{localDB};
        $type = $self->{localType};
      } else {
	$dsn  = $self->{remoteDB};
        $type = $self->{remoteType};
      }
      print "      dsn: ".$dsn."\n" if ($self->{DEBUG});
      print "      db2-ld_library_path: ".$ENV{LD_LIBRARY_PATH}."\n" if ($self->{DEBUG});
      print "      db2-path: ".           $ENV{PATH}.           "\n" if ($self->{DEBUG});
      print "      db2-libpath".          $ENV{LIBPATH}.        "\n" if ($self->{DEBUG});
      print "      db2-classpath".        $ENV{CLASSPATH}.      "\n" if ($self->{DEBUG});
      if ($self->operateTable (DO=>"exist", 
                               DB => $dsn, 
                               TYPE => $type, 
                               TABLE => $table) != 0) {
	if ($force == 1) {
	  if ($self->operateTable (DO=>"drop", 
                                   DB => $dsn,
                                   TYPE => $type, 
                                   TABLE => $table) != 1) {
            $self->errno ( $OpenCA::DBI::ERROR->{ "CANNOT_REMOVE_".$table } );
	    return undef;
	  }
	} else {
          $self->errno ( $OpenCA::DBI::ERROR->{ $table."_TABLE_EXIST" } );
	  return undef;
	}
      }
      print "      try to create table\n" if ($self->{DEBUG});
      # create table
      if ($self->operateTable (DO=>"create", 
                               DB => $dsn, 
                               TYPE => $type, 
                               TABLE => $table) != 1) {
        $self->errno ( $OpenCA::DBI::ERROR->{ "CANNOT_CREATE_".$table } );
	return undef;
      }
      print "      table created\n" if ($self->{DEBUG});
      # if sequence then init now
      if ( ($table eq $OpenCA::DBI::SQL->{TABLE}->{SEQUENCE}) and 
           ($OpenCA::DBI::DB->{$type}->{SEQUENCE}->{INIT} ne "")
         ) {
        if ($self->operateTable (DO=>"init", 
                                 DB => $dsn, 
                                 TYPE => $type, 
                                 TABLE => $table) != 1) {
          $self->errno ( $OpenCA::DBI::ERROR->{ CANNOT_INIT_SEQUENCE } );
          return undef;
        }
      }
      print "      sequence generator initialized\n" if ($self->{DEBUG});
    }
  }
  print "  initDB successful completed\n" if ($self->{DEBUG});
  return 0;
}

sub operateTable {
  my $self = shift;
  my $keys = { @_ };
  
  my $target    = $keys->{DB};
  my $type      = $keys->{TYPE};
  my $table     = $keys->{TABLE};
  my $operation = $keys->{DO};
 
  print "      Entering sub operateTable\n" if ($self->{DEBUG});
 
  # the tables
  my (%tables, $dbh, $sth, $statement, $create);

  print "        build the create statements\n" if ($self->{DEBUG});

  ############################
  ## initial tablestructure ##
  ## change carefully !!!   ##
  ############################

  if ($table ne "SEQUENCE") {
    print "  table: ".$OpenCA::DBI::SQL->{TABLE}->{$table}."\n" if ($self->{DEBUG});
    $create = "create table ".$OpenCA::DBI::SQL->{TABLE}->{$table}." (";
    my $start = 0;
    if ($table eq "LOG") {
      $start = 1;
      $create .= $OpenCA::DBI::SQL->{VARIABLE}->{
                   $OpenCA::DBI::SQL->{TABLE_STRUCTURE}->{LOG}[0]
                 }[0]." ".
                 $OpenCA::DBI::DB->{$type}->{TYPE}->{SEQUENCE};
    }
    for (my $i=$start; 
         $i < scalar (@{$OpenCA::DBI::SQL->{TABLE_STRUCTURE}->{$table}}); 
         $i++) {
      if ($i == 0) {
        $create .= $OpenCA::DBI::SQL->{VARIABLE}->{
                     $OpenCA::DBI::SQL->{TABLE_STRUCTURE}->{$table}[0]
                   }[0]." ".
                   $OpenCA::DBI::DB->{$type}->{TYPE}->{
                     $OpenCA::DBI::SQL->{VARIABLE}->{
                       $OpenCA::DBI::SQL->{TABLE_STRUCTURE}->{$table}[0]
                     }[1]
                   }." ".
                   $OpenCA::DBI::DB->{$type}->{TYPE}->{PRIMARYKEY};
      } else {
        $create .= ", ".
                   $OpenCA::DBI::SQL->{VARIABLE}->{
                     $OpenCA::DBI::SQL->{TABLE_STRUCTURE}->{$table}[$i]
                   }[0]." ".
                   $OpenCA::DBI::DB->{$type}->{TYPE}->{
                     $OpenCA::DBI::SQL->{VARIABLE}->{
                       $OpenCA::DBI::SQL->{TABLE_STRUCTURE}->{$table}[$i]
                     }[1]
                   };
      }
    }
    $create .= ")";
  } else {
    $create = $OpenCA::DBI::DB->{$type}->{SEQUENCE}->{CREATE};
  }
  print "  create:".$create."\n" if ($self->{DEBUG});

  ############################
  ##      end of            ##
  ## initial tablestructure ##
  ## change carefully !!!   ##
  ############################

  ## this happens if a sequence has no create statement
  ## e.g. Informix 
  return 1 if ($create eq "");

  print "        try to connect the database\n" if ($self->{DEBUG});

  # Check which database should be checked
  if ($target eq "local") {
    print "          DB: local\n" if ($self->{DEBUG});
    print "          Dsn: ".$self->{localDB}."\n" if ($self->{DEBUG});
    print "          user: ".$self->{localUser}."\n" if ($self->{DEBUG});
    print "          passwd: ".$self->{localPasswd}."\n" if ($self->{DEBUG});
    $dbh = DBI->connect ($self->{localDB}, 
                         $self->{localUser},
                         $self->{localPasswd},
                         \%{$OpenCA::DBI::DB->{$self->{localType}}->{DBI_OPTION}});
  } else {
    print "          DB: remote\n" if ($self->{DEBUG});
    print "          dsn: ".$self->{remoteDB}."\n" if ($self->{DEBUG});
    print "          user: ".$self->{remoteUser}."\n" if ($self->{DEBUG});
    print "          passwd: ".$self->{remotePasswd}."\n" if ($self->{DEBUG});
    $dbh = DBI->connect ($self->{remoteDB},
                         $self->{remoteUser},
                         $self->{remotePasswd},
                         \%{$OpenCA::DBI::DB->{$self->{remoteType}}->{DBI_OPTION}});
  }
  
  if (not defined $dbh) {
    print "        connect failed\n" if ($self->{DEBUG});
    return -1;
  }
  if ($dbh->state != 0) {
    print "        connect failed\n" if ($self->{DEBUG});
    return -1;
  }
  print "        build the statement finally\n" if ($self->{DEBUG});

  # check table
  my $negator = 0;
  if ($operation eq "create") {
    $statement = $create;
  } elsif ($operation eq "drop") {
    if ($table eq "SEQUENCE") {
      $statement = $OpenCA::DBI::DB->{$type}->{SEQUENCE}->{DROP};
    } else {
      $statement = "drop table ".$OpenCA::DBI::SQL->{TABLE}->{$table};
    }
  } elsif ($operation eq "init") {
    $statement = $OpenCA::DBI::DB->{$type}->{SEQUENCE}->{INIT};
  } else {
    # check for existence of table
    if ($table eq $OpenCA::DBI::SQL->{TABLE}->{SEQUENCE}) {
      $statement = $create;
      $negator   = 1;
    } else {
      $statement = "select * from ".$OpenCA::DBI::SQL->{TABLE}->{$table};
    }
  }

  print "        statement: ".$statement."\n" if ($self->{DEBUG});
  ## can happen if operation performs for sequence generator
  return 1 if ($statement eq "");
  print "        run the statement\n" if ($self->{DEBUG});

  # evtl. 0 und -1 are better for returnvalues
  # attention not for final use because of the central $OpenCA::DBI::ERROR VARIABLE !!!
  $sth = $dbh->prepare ($statement);
  # if ($dbh->do ($statement) != 0) {
  if (not $sth->execute) {
    $dbh->disconnect;
    print "        query failed return 0 (EXCEPT OF NEGATOR)\n" if ($self->{DEBUG});
    return 1 if ($negator);
    return 0;
  } else {
    if ($operation ne "exist") {
      print "        commit necessary\n" if ($self->{DEBUG});
      if (not $dbh->commit) {
	print "        commit failed, perform rollback\n" if ($self->{DEBUG});
	$dbh->rollback;
	$dbh->disconnect;
	print "        return 0\n" if ($self->{DEBUG});
	return 0;
      }
      print "        commit succeeded\n" if ($self->{DEBUG});
    }
    $dbh->disconnect;
    print "        query succeeded return 1 (EXCEPT OF NEGATOR)\n" if ($self->{DEBUG});
    return 0 if ($negator);
    return 1;
  }
  
}

####################################
## end of database initialization ##
####################################

###########################################################
## old private functions which are not needed any longer ##
###########################################################

# not needed actually because there is no need for DER
#
# not enough what is with \0?
# 
# sub binary2text {
# 
#   my $self   = shift;
#   my $binary = shift;
# 
#   my $ret = $binary;
# 
#   $ret =~ s/"/\"/g;
# 
#   return $ret;  
# 
# }
#  
# sub text2binary {
#  
#   my $self = shift;
#   my $text = shift;
#  
#   my $ret = $text;
#  
#   $ret =~ s/\"/"/g;
#  
#   return $ret;
#  
# }

###########################################################
## old private functions which are not needed any longer ##
###########################################################

#################################
## storeItem related functions ##
#################################

## arguments miust be ransmitted via $arguments->{...}
sub storeItem {

  ## Store a provided Item (DATA) provided the exact
  ## DATATYPE. KEY (position in dB) data to match will
  ## be automatically chosen on a DATATYPE basis.
  
  ## The INFORM is used to get the data input format
  ## PEM|DER|NET|SPKAC
  
  my $self = shift;
  my $keys = { @_ };

  print "### new function call ###<br>\n".
        "Entering function storeItem<br>\n" if ($self->{DEBUG});
 
  my %arguments  = $self->storeItem_getArguments ( @_ );
  ## check for a correct run of storeItem_getArguments
  print "  table: ".$arguments {TABLE}."<br>\n" if ($self->{DEBUG});      

  return undef if ($self->storeItem_checkData ( \%arguments ) == undef);

  ## prepare for DBLOOP
  ## attention ERRORS must be exchanged
  ## ok not must but should so because we want to make good code ...
  print "  initializes db_hash<br>\n" if ($self->{DEBUG});  
  %{$arguments {db_hash}} = (STATUS => 0, 
              DBH    => 0,
              QUERY  => "",
              STH    => [],
              TYPE   => "",
              BIND_VALUES => [],
             );

  ## why do we have a sub getTimeString ???
  $arguments {datetime} = getTimeString ();

  ## loop until we can successful complete or fail finally
  print "  starting DBLOOP<br>\n" if ($self->{DEBUG});  
 DBLOOP: while () {

    ##   declare variables
    my $rv;

    ##   connect
    print "  try to connect<br>\n" if ($self->{DEBUG});
    if ( not defined $self->doConnect (\%{$arguments{db_hash}}) ) {
      return undef;
    }
    print "  Databasetype:".$arguments{db_hash} {TYPE}."<br>\n" if ($self->{DEBUG});

    ## is item existent and unique ?
    ## CRLs are not updateable
    print "  check for existence of item<br>\n" if ($self->{DEBUG});  
    if ( ($arguments {TABLE} ne "CRL") and $arguments {KEY}) {
      print "  is not a CRL<br>\n" if ($self->{DEBUG});  
      $arguments{db_hash}{QUERY} = "select * from ".
        $OpenCA::DBI::SQL->{TABLE}->{$arguments {TABLE}}." where ". 
	$OpenCA::DBI::SQL->{VARIABLE}->{$arguments {TABLE}."_SERIAL"}[0]."=?";
      undef @{$arguments{db_hash}{BIND_VALUES}};
      $arguments{db_hash}{BIND_VALUES}[0] = $arguments {KEY};

      print "  doQuery: ".$arguments{db_hash}{QUERY}."<br>\n" if ($self->{DEBUG});  
      if ( not defined $self->doQuery (\%{$arguments{db_hash}}) ) {
        print "  doQuery failure detected by function storeItem -> retry<br>\n" if ($self->{DEBUG});  
	$self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
	$self->doRollback (\%{$arguments{db_hash}});
	$self->doDisconnect (\%{$arguments{db_hash}}); #if negative should I abort here ?
	next DBLOOP;
      }
      $rv = $arguments{db_hash}{STH}[scalar @{$arguments{db_hash}{STH}} -1]->fetchrow_arrayref;
    }
    if (($arguments {TABLE} ne "CRL") and $arguments {KEY} and ($rv)) { 
      my $h = $self->storeItem_update ( \%arguments );
      return undef if ($h == undef);
      next DBLOOP  if ($h == -1);
    } else {
      my $h = $self->storeItem_insert ( \%arguments );
      return undef if ($h == undef);
      next DBLOOP  if ($h == -1);
    }

    my $h = $self->storeItem_logging ( \%arguments );
    return undef if ($h == undef);
    next DBLOOP  if ($h == -1);

    my $h = $self->storeItem_signing ( \%arguments );
    return undef if ($h == undef);
    next DBLOOP  if ($h == -1);

    ##   commit
    $rv = $self->doCommit (\%{$arguments{db_hash}});
    if (not defined $rv ) {
      $self->errno ( $OpenCA::DBI::ERROR->{COMMIT_FAILED} );
      $self->doRollback (\%{$arguments{db_hash}});
    }
    $self->doDisconnect (\%{$arguments{db_hash}}); #if negative should I abort here ?
    if ( not defined $rv ) {
      next DBLOOP;
    }
    return $arguments {KEY};
    
    ## next round
    
  }
  ## end of db-loop
  
  ## never reached
  $self->errno ( $OpenCA::DBI::ERROR->{UNEXPECTED_ERROR} );
  return undef;

}

## parse the arguments
sub storeItem_getArguments {

  my $self = shift;
  my $keys = { @_ };

  my %result;

  print "### new function call ###<br>\n".
        "Entering storeItem_getArguments<br>\n" if ($self->{DEBUG});

  $result{mode}       = $keys->{MODE};	## ACTUALLY only UPDATE or NULL
  $result{moduletype} = $keys->{MODULETYPE};
  $result{module}     = $keys->{MODULE};
  $result{object}     = $keys->{OBJECT};

  $result {TABLE} = $self->getTable ($keys->{DATATYPE});
  print "  table: ".$result {TABLE}."<br>\n" if ($self->{DEBUG});      

  ## get all searchable attributes
  @{$result {attributes}} = $self->getSearchAttributes( DATATYPE=>$result {TABLE} );
  
  my $attr;

  my $object = $keys->{OBJECT};

  ## storeItem

  for $attr ( @{$result {attributes}} ) {
  
    print "  attribute: ".$attr."<br>\n" if ($self->{DEBUG});      
    ##     Here we distinguish between parameteres in the header
    if( $attr =~ /^(RA|ROLE)$/ ) {
      $result {$attr} = $object->getParsed()->{HEADER}->{$attr};
      print "  value: ".$result {$attr}."<br>\n" if ($self->{DEBUG});      
    } else {
      $result {$attr} = $object->getParsed()->{$attr};
      print "  value: ".$result {$attr}."<br>\n" if ($self->{DEBUG});      
    }
  }

  ## enforce status
  $result {STATUS} = $self->getStatus ( STATUS   => $result {STATUS},
                                        DATATYPE => $keys->{DATATYPE} );
  if (not $result {STATUS}) {
    delete ($result {STATUS});
  } elsif ($self->{DEBUG}) {
    print "  status: ".$result {STATUS}."<br>\n";
  }

  ## storage formats
  ##   If the data is convertible, let's have only one internal
  ##   format to handle with
  $result {INFORM} = $keys->{INFORM};
  if ( not $result {INFORM} ) {
    $result {INFORM} = "PEM";
  }
  print "  inform: ".$result {INFORM}."<br>\n" if ($self->{DEBUG});

  if( $object->getParsed()->{TYPE} =~ /SPKAC|RENEW|REVOKE/ ) {
    $result {CONVERTED} = $object->getParsed()->{ITEM};
    $result {FORMAT} = $object->getParsed()->{TYPE};
  } else {
    $result {CONVERTED} = $object->getPEM();
    $result {FORMAT} = "PEM";
  }
  print "  format: ".$result {FORMAT}."<br>\n" if ($self->{DEBUG});
  print "  converted: ".$result {CONVERTED}."<br>\n" if ($self->{DEBUG});  

  ## check for the key 
  if ($result {TABLE} =~ /^(CERTIFICATE)$/i ) {
    $result {KEY} = $result {object}->getParsed()->{SERIAL};
  } elsif ($result {TABLE} =~ /^REQUEST$/i ) {
    $result {KEY} = $result {object}->getParsed()->{HEADER}->{SERIAL};
  } elsif ($result {TABLE} =~ /^CRL$/i ) {
    $result {KEY} = $self->build_date ($object->getParsed ()->{LAST_UPDATE});
  }else {
    $result {KEY} = $self->{backend}->getDigest( DATA=>$result {CONVERTED} );
  }
  
  if ($self->{DEBUG}) {
    print "  object->getParsed hash:<br>\n";
    for my $h (keys %{$object->getParsed()}) {
      print "  object-attribute:".$h."<br>\n";
      print "  object-value:".$object->getParsed ()->{$h}."<br>\n";
    }
  }

  print "  KEY:".$result{KEY}."<br>\n" if ($self->{DEBUG});
  print "### function storeITem_getArguments succesfully finished ###<br>\n" if ($self->{DEBUG});

  return %result;
}

## checks all the available data
## warning: function must called with storeItem_checkData { \%arguments} !!!
sub storeItem_checkData {

  my $self = shift;
  my $arguments = $_[0];

  ## check data
  print "### new function call ###<br>\n".
        "Entering storeItem_checkData<br>\n" if ($self->{DEBUG});
  
  ##   determinate table
  if (not $arguments->{TABLE}) {
    # this is not allowed (for recovery too)
    $self->errno ($OpenCA::DBI::ERROR->{WRONG_DATATYPE});
    return undef;
  }
  
  ## if VALID_* then take mode and in doubt use "UPDATE"
  ## else UPDATE
  ## special handling of CRLs
  ## all modes are now enforced !!!
  if ( not $arguments->{mode} ) {
    if ( $arguments->{STATUS} =~ /^(VALID|PENDING)$/ ) {
      if ((uc $arguments->{mode}) ne "UPDATE") {
        $arguments->{mode} = "INSERT";
      } elsif ($arguments->{TABLE} eq "CRL") {
        ## blocks updating CRLs
        ## create a new one please
        $arguments->{mode} = "INSERT";
      } else {
        $arguments->{mode} = "UPDATE";
      }
    } elsif ( $arguments->{TABLE} eq "CRL" ) {
      ## blocks updating CRLs
      ## create a new one please
      $arguments->{mode} = "INSERT";
    } else {
      $arguments->{mode} = "UPDATE";
    }
  }

  ## if no moduletype then unknown
  if (not $arguments->{moduletype}) {
    $arguments->{moduletype} = "UNKNOWN";
    if ($arguments->{module}) {
      $arguments->{module} .= " - UNKNOWN MODULETYPE";
    } else {
      $arguments->{module} = "UNKNOWN MODULETYPE AND UNKNOWN MODULE";
    }
  }
  ## if no module then "UNKNOWN MODULE"
  if (not $arguments->{module}) {
    $arguments->{module} = "UNKNOWN MODULE";
  }

  ##   if we have no object then return
  if (not $arguments->{object}) {
    $self->errno ($OpenCA::DBI::ERROR->{NO_OBJECT});
    return undef;
  }

  ##   cannot update without serial but serial is in the object
  if (($arguments->{mode} eq "UPDATE") and not $arguments->{KEY}) {
    $self->errno ($OpenCA::DBI::ERROR->{UPDATE_WITHOUT_KEY});
    return undef;
  }
  
  print "  data is complete<br>\n" if ($self->{DEBUG});  
  print "### leaving function storeItem_checkData successfully ###<br>\n" if ($self->{DEBUG});  

  return 1;
}

sub storeItem_update {

  my $self = shift;
  my $arguments = $_[0];

  if ($arguments->{mode} ne "UPDATE") {
    print "    insert requested but item exist\n" if ($self->{DEBUG});  
    $self->doRollback (\%{$arguments->{db_hash}});
    $self->doDisconnect (\%{$arguments->{db_hash}});
    $self->errno ( $OpenCA::DBI::ERROR->{ENTRY_EXIST} );
    return undef;
  }
  print "    update mode\n" if ($self->{DEBUG});  
  ## item existent
  ## ok this could be CRR, Request or Certificate
  ##   verify actual state (check signatures)
  ##     -- (I think that's not the job of the DBI-Module - so it is not implemented)
  ##   check all input data
  ##     -- this should be done earlier 
  ##     -- (attriubtes are checked directly before storing them)
  ##   is this statechange allowed (for example to prevent multiple DNs)
  ##     -- actually not implemented (do statechange and log it only)
  ##   try statechange
  ##     -- prepare query
  print "    prepare query\n" if ($self->{DEBUG});  
  $arguments->{db_hash}{QUERY} = "update ".$OpenCA::DBI::SQL->{TABLE}->{$arguments->{TABLE}}." set ".
  ##     -- adding data, format, info, status
    $OpenCA::DBI::SQL->{VARIABLE}->{DATA}[0]."=?, ".
    $OpenCA::DBI::SQL->{VARIABLE}->{FORMAT}[0]."=?, ".
    $OpenCA::DBI::SQL->{VARIABLE}->{INFO}[0]."=? ";
  undef @{$arguments->{db_hash}{BIND_VALUES}};
  $arguments->{db_hash}{BIND_VALUES} [0] = $arguments->{CONVERTED};
  $arguments->{db_hash}{BIND_VALUES} [1] = $arguments->{FORMAT};
  print "    try to parse header\n" if ($self->{DEBUG});  
  if (exists $arguments->{object}->getParsed ()->{HEADER}) {
    $arguments->{db_hash}{BIND_VALUES} [2] = $self->hash2txt (\%{$arguments->{object}->getParsed ()->{HEADER}});
  } else {
    $arguments->{db_hash}{BIND_VALUES} [2] = "";
  }
  print "Header of the object:<br>\n".$arguments->{db_hash}{BIND_VALUES} [2]."<br>\n" if ($self->{DEBUG});
  ##     -- adding searchattributes - never update a date !!!
  ##     -- getSearchAttributes don't return date as attribute
  for my $attr ( @{$arguments->{attributes}} ) {
    # so transformation should be correct for SQL
    if ($attr !~ /^KEY$/ ) {
      $arguments->{db_hash}{QUERY} .= ", ".$OpenCA::DBI::SQL->{VARIABLE}->{$attr}[0]."=?";
      $arguments->{db_hash}{BIND_VALUES} [scalar (@{$arguments->{db_hash}{BIND_VALUES}})] = $arguments->{$attr};
    }
  }

  ##     -- set serials
  $arguments->{db_hash}{QUERY} .= " where ".
    $OpenCA::DBI::SQL->{VARIABLE}->{$arguments->{TABLE}."_SERIAL"}[0]."=?";
  $arguments->{db_hash}{BIND_VALUES} [scalar (@{$arguments->{db_hash}{BIND_VALUES}})] = 
    $arguments->{KEY};

  foreach my $help (@{$arguments->{db_hash}{BIND_VALUES}}) {
    print "      bind_values: ".$help."\n" if ($self->{DEBUG});
  }
  print "    query complete, call doQuery\n" if ($self->{DEBUG});  

  if ( not defined $self->doQuery (\%{$arguments->{db_hash}}) ) {
    $self->errno ( $OpenCA::DBI::ERROR->{UPDATE_FAILED} );
    $self->doRollback (\%{$arguments->{db_hash}});
    $self->doDisconnect (\%{$arguments->{db_hash}}); #if negative should I abort here ?
    return -1;
  }
  return 1;
}

sub storeItem_insert {

  my $self = shift;
  my $arguments = $_[0];

  print "### new function call ###<br>\n" if ($self->{DEBUG});
  print "Entering storeItem_insert<br>\n" if ($self->{DEBUG});  
  if ($arguments->{mode} eq "UPDATE") {
    print "  illegal update<br>\n" if ($self->{DEBUG});  
    print "### leaving function storeItem_insert unsuccessfully<br>\n" if ($self->{DEBUG});  
    $self->doRollback (\%{$arguments->{db_hash}});
    $self->doDisconnect (\%{$arguments->{db_hash}}); 
    $self->errno ( $OpenCA::DBI::ERROR->{ENTRY_NOT_EXIST} );
    return undef;
  }
  print "    insert mode\n" if ($self->{DEBUG});  
  ## INSERT
  ##   mode='update' is allowed in the future to support revoking non-existing request 
  ##   check all input data
  ##     -- this should be done earlier 
  ##     -- (attriubtes are checked directly before storing them)
  ##   is this statechange allowed (for example renewal nonexistent request)
  ##     -- actually not implemented (do statechange and log it only)
  ##   create row with all additional attributes
  ##     -- prepare query
  print "  prepare query<br>\n" if ($self->{DEBUG});  
  $arguments->{db_hash}{QUERY} = "insert into ".
    $OpenCA::DBI::SQL->{TABLE}->{$arguments->{TABLE}}." ( ".
    $OpenCA::DBI::SQL->{VARIABLE}->{$arguments->{TABLE}."_SERIAL"}[0].", ".
    $OpenCA::DBI::SQL->{VARIABLE}->{DATA}[0].", ".
    $OpenCA::DBI::SQL->{VARIABLE}->{FORMAT}[0].", ".
    $OpenCA::DBI::SQL->{VARIABLE}->{INFO}[0];
  for my $attr ( @{$arguments->{attributes}} ) {
    $arguments->{db_hash}{QUERY} .= ", ".$OpenCA::DBI::SQL->{VARIABLE}->{$attr}[0]
      if ($attr !~ /^KEY$/);
  }
  $arguments->{db_hash}{QUERY} .= ") VALUES (";
  ##     -- adding data, format, info, status
  $arguments->{db_hash}{QUERY} .= " ?, ?, ?, ?";
  undef @{$arguments->{db_hash}{BIND_VALUES}};
  $arguments->{db_hash}{BIND_VALUES}[0] = $arguments->{KEY};
  $arguments->{db_hash}{BIND_VALUES}[1] = $arguments->{CONVERTED};
  $arguments->{db_hash}{BIND_VALUES}[2] = $arguments->{FORMAT};
  print "  try to parse header<br>\n" if ($self->{DEBUG});  
  if (not $arguments->{object}) {
    print "  fatal error: object lost<br>\n" if ($self->{DEBUG});
    print "###  leaving function  storeItem_insert unsuccessfully ###<br>\n" if ($self->{DEBUG});
    return undef;
  }
  if (exists $arguments->{object}->getParsed ()->{HEADER}) {
    $arguments->{db_hash}{BIND_VALUES}[3] = $self->hash2txt(\%{$arguments->{object}->getParsed ()->{HEADER}});
  } else {
    $arguments->{db_hash}{BIND_VALUES}[3] = "";
  }
  print "Header of the object:<br>\n".$arguments->{db_hash}{BIND_VALUES} [3]."<br>\n" if ($self->{DEBUG});
  ##     -- adding searchattributes - never update a date !!!
  ##     -- getSearchAttributes don't return date as attribute
  for my $attr ( @{$arguments->{attributes}} ) {
    if ($attr !~ /^KEY$/ ) {
      # so transformation should be correct for SQL
      print "      attr: ".$attr."\n" if ($self->{DEBUG});
      $arguments->{db_hash}{QUERY} .= ", ?";
      $arguments->{db_hash}{BIND_VALUES}[scalar (@{$arguments->{db_hash}{BIND_VALUES}})] = 
      $arguments->{$attr};
    }
  }
  $arguments->{db_hash}{QUERY} .= ")";
      
  foreach my $help (@{$arguments->{db_hash}{BIND_VALUES}}) {
    print "      bind_values: ".$help."\n" if ($self->{DEBUG});
  }
  print "    query complete, call doQuery\n" if ($self->{DEBUG});  

  if ( not defined $self->doQuery (\%{$arguments->{db_hash}}) ) {
    $self->errno ( $OpenCA::DBI::ERROR->{UPDATE_FAILED} );
    $self->doRollback (\%{$arguments->{db_hash}});
    $self->doDisconnect (\%{$arguments->{db_hash}}); #if negative should I abort here ?
    return -1;
  }

  return 1;

}

sub storeItem_logging {

  my $self = shift;
  my $arguments = $_[0];

  ##     log statechange
  ############################################################
  ## it is possible to recover completely from this log !!! ##
  ############################################################
  ## sub recover is actually not implemented                ##
  ## actually only:                                         ##
  ##                - write one logrecord after the other   ##
  ##                  to the databasetables                 ##
  ############################################################

  ## generate action_number
  print "    Databasetype:".$arguments->{db_hash}{TYPE}."\n"
    if ($self->{DEBUG});
  if ($OpenCA::DBI::DB->{$arguments->{db_hash}{TYPE}}->{SEQUENCE}->{GENERATE} ne "") {
    print "    generate sequence number\n" if ($self->{DEBUG});  
    $arguments->{db_hash}{QUERY} = $OpenCA::DBI::DB->{$arguments->{db_hash}{TYPE}}->{SEQUENCE}->{GENERATE};
    undef (@{$arguments->{db_hash}{BIND_VALUES}});
    print "      doQuery for generate new_action_number: ".$arguments->{db_hash}{QUERY}."\n" 
      if ($self->{DEBUG});  
    if ( not defined $self->doQuery (\%{$arguments->{db_hash}}) ) {
      print "    generate sequence number failed\n" if ($self->{DEBUG});  
      $self->errno ( $OpenCA::DBI::ERROR->{INSERT_FAILED} );
      $self->doRollback (\%{$arguments->{db_hash}});
      $self->doDisconnect (\%{$arguments->{db_hash}}); #if negative should I abort here ?
      return -1;
    }
    print "      generate successful\n" if ($self->{DEBUG});  
  }
  
  ## get action_number
  ## this is vendor dependend so encapsulated in extra code
  print "    getSequence\n" if ($self->{DEBUG});  
  $arguments->{new_action_number} = $self->getSequence (\%{$arguments->{db_hash}});
  if (not defined $arguments->{new_action_number}) {
    ## error is set by getSequence
    print "      getSequence failed\n" if ($self->{DEBUG});  
    $self->doRollback (\%{$arguments->{db_hash}});
    $self->doDisconnect (\%{$arguments->{db_hash}}); #if negative should I abort here ?
    return -1;      
  }
  
  print "    new_action_number: ".$arguments->{new_action_number}."\n" if ($self->{DEBUG});  
  
  print "    preparing log\n" if ($self->{DEBUG});  
  if ($OpenCA::DBI::DB->{$arguments->{db_hash}{TYPE}}->{SEQUENCE}->{GENERATE_BY_INSERT}) {
    print "      sequence GENERATE_BY_INSERT\n" if ($self->{DEBUG});  
    $arguments->{db_hash}{QUERY} = "update ".$OpenCA::DBI::SQL->{TABLE}->{LOG}." set ".
      $OpenCA::DBI::SQL->{VARIABLE}->{MODULETYPE}[0]."=?, ".
      $OpenCA::DBI::SQL->{VARIABLE}->{MODULE}[0]."=?, ".
      $OpenCA::DBI::SQL->{VARIABLE}->{LOG_SUBMIT_DATE}[0]."=?, ".
      # set by sync module $OpenCA::DBI::SQL->{VARIABLE}->{LOG_DO_DATE}[0].", ".
      $OpenCA::DBI::SQL->{VARIABLE}->{KEY}[0]."=?, ".
      $OpenCA::DBI::SQL->{VARIABLE}->{FORMAT}[0]."=?, ".
      $OpenCA::DBI::SQL->{VARIABLE}->{DATA}[0]."=?, ".
      $OpenCA::DBI::SQL->{VARIABLE}->{INFO}[0]."=? ";
    foreach my $attr (@{$arguments->{attributes}}) {
      $arguments->{db_hash}{QUERY} .= ", ".$OpenCA::DBI::SQL->{VARIABLE}->{$attr}[0]."=?";
    }
    $arguments->{db_hash}{QUERY} .= " where ".
      $OpenCA::DBI::SQL->{VARIABLE}->{ACTION_NUMBER}[0]."=".$arguments->{new_action_number};
  } else {
    print "      sequence not GENERATE_BY_INSERT\n" if ($self->{DEBUG});  
    $arguments->{db_hash}{QUERY} = "insert into ".$OpenCA::DBI::SQL->{TABLE}->{LOG}." (".
      $OpenCA::DBI::SQL->{VARIABLE}->{ACTION_NUMBER}[0].", ".
      $OpenCA::DBI::SQL->{VARIABLE}->{MODULETYPE}[0].", ".
      $OpenCA::DBI::SQL->{VARIABLE}->{MODULE}[0].", ".
      $OpenCA::DBI::SQL->{VARIABLE}->{LOG_SUBMIT_DATE}[0].", " .
      # set by sync-module $OpenCA::DBI::SQL->{VARIABLE}->{LOG_DO_DATE}[0].", ".
      # KEY is included via the searchable args
      # $OpenCA::DBI::SQL->{VARIABLE}->{KEY}[0].", ".
      $OpenCA::DBI::SQL->{VARIABLE}->{FORMAT}[0].", ".
      $OpenCA::DBI::SQL->{VARIABLE}->{DATA}[0].", ".
      $OpenCA::DBI::SQL->{VARIABLE}->{INFO}[0];
    foreach my $attr (@{$arguments->{attributes}}) {
      $arguments->{db_hash}{QUERY} .= ", ".$OpenCA::DBI::SQL->{VARIABLE}->{$attr}[0];
    }
    $arguments->{db_hash}{QUERY} .= ") VALUES (";
    $arguments->{db_hash}{QUERY} .= $arguments->{new_action_number};
    # next is date from crl, so I can set it to 'now'
    # is this really neccessary
    foreach my $attr (@{$arguments->{attributes}}) {
      ## $arguments->{db_hash}{QUERY} .= ", ?" if ($attr !~ /^KEY$/ );
      $arguments->{db_hash}{QUERY} .= ", ?";
    }
    # here we have moduletype, module, log_submit_date, format, data, info
    $arguments->{db_hash}{QUERY} .= ", ?, ?, ?, ?, ?, ? )";
  }
  undef @{$arguments->{db_hash}{BIND_VALUES}};
  $arguments->{db_hash}{BIND_VALUES} [0] = $arguments->{moduletype};
  $arguments->{db_hash}{BIND_VALUES} [1] = $arguments->{module};
  $arguments->{db_hash}{BIND_VALUES} [2] = $arguments->{datetime};
  # KEY is included via the searchable args
  # $arguments->{db_hash}{BIND_VALUES} [3] = $arguments->{KEY};
  $arguments->{db_hash}{BIND_VALUES} [3] = $arguments->{FORMAT};
  $arguments->{db_hash}{BIND_VALUES} [4] = $arguments->{CONVERTED};
  if (exists $arguments->{object}->getParsed ()->{HEADER}) {
    $arguments->{db_hash}{BIND_VALUES} [5] = $self->hash2txt (\%{$arguments->{object}->getParsed ()->{HEADER}});
  } else {
    $arguments->{db_hash}{BIND_VALUES} [5] = "";
  }
  my $i= scalar (@{$arguments->{db_hash}{BIND_VALUES}});;
  foreach my $attr (@{$arguments->{attributes}}) {
    ## $arguments->{db_hash}{BIND_VALUES} [$i] .= $arguments->{$attr} if ($attr !~ /^KEY$/ );
    $arguments->{db_hash}{BIND_VALUES} [$i] .= $arguments->{$attr};
    $i++;
  }
  print "      query: ".$arguments->{db_hash}{QUERY}."\n" if ($self->{DEBUG});      

  print "      doQuery for logging\n" if ($self->{DEBUG});  
  if ( not defined $self->doQuery (\%{$arguments->{db_hash}}) ) {
    $self->errno ( $OpenCA::DBI::ERROR->{INSERT_FAILED} );
    $self->doRollback (\%{$arguments->{db_hash}});
    $self->doDisconnect (\%{$arguments->{db_hash}}); #if negative should I abort here ?
    return -1;
  }

  return 1;
}

sub storeItem_signing {

  my $self = shift;
  my $arguments = $_[0];

  ##   storing log signatures separately
  ##     -- a difficult job for the future
  ##     -- actually not necessary

  ##   IDEA
  ##   ----
  ##   $logsecurity
  ##   $cert
  ##   $pwd
  ##   $key
  ##   $backend
  ##   for (my $i=0; $i< $logsecurity; $i++) {
  ##     $action_number_parent = int ($new_action_number / (2**$i));
  ##     $signdata = $data_from_anp + $data_from_nan;
  ##     $data = $backend->sign (DATA      => $signdata, 
  ##                             CERT_FILE => $cert,
  ##                             KEY_FILE  => $key,
  ##                             PWD       => $pwd);
  ##     if (not $data) {
  ##       $self->{rollback ...
  ##     }
  ##     write to log with:
  ##       - action_number = anp
  ##       - action_number_child = nan
  ##       - date = 'now'
  ##       - data = $data
  ##       - info reserved for future use
  ##     last if ($action_number_parent == 0);
  ##   }
  ###############################################################
  ##   wrong IDEA                                              ##
  ##   never overwrite a signature !!!                         ##
  ##   if the system is corupted the verification is it to !!! ##
  ##   so don't give additional help by corrupt another user's ##
  ##   correct signature                                       ##
  ###############################################################
  ##   next IDEA
  ##   ---------
  ##   $logsecurity
  ##   $cert
  ##   $pwd
  ##   $key
  ##   $backend
  ##   
  ##   same idea only localized to the actual entry which protect
  ##   older entries too
  ##
  ##   It is only possible to shurely detect attacks against the last
  ##   new logentries by signing periodically with a timestampserver.
  ##   Because we have actually no one it is wasted time to program
  ##   code for this case.
  ##   Without a timestampserver we cannot decide wether a server is
  ##   not frequently used or some manipulates our time and remove
  ##   all until the data comes which he like to pass through.
  ##   We can only give the warranty that there are no holes
  ##   in our logstream. An attacker cannot remove entry one and two
  ##   he must remove all entries.
  ##   The interesting question is how long do you need to detect the 
  ##   loss of logdata and perhaps real data.
  ##
  ##   IMPLEMENTATION

  ## warning: in releases higher than 1.0 the test must be
  ## against NO and OFF because false positive is better than a
  ## forgotten signing 

  if ( (uc $self->{SignLog} eq "ON") or (uc $self->{SignLog} eq "YES")) {
    print "  logging with signing is active!\n" if ($self->{DEBUG});
    ## produce the signatures
    my $i = 0;
    my @list = ();
    my $data;
    @list = OpenCA::DBIS->getSignatureAnchor (
              position       => $arguments->{new_action_number},
              logperformance => $self->{logperformance},
              logsecurity    => $self->{logsecurity});
      
    #############################################################
    ## is it secure to get the new data via select statement ? ##
    #############################################################
    $arguments->{db_hash}{QUERY} = "select * from ".
      $OpenCA::DBI::SQL->{TABLE}->{LOG}." where ".
        "(".$OpenCA::DBI::SQL->{VARIABLE}->{ACTION_NUMBER}[0]."=".$arguments->{new_action_number}.")";
    foreach my $h (@list) {
      $arguments->{db_hash}{QUERY} .= " or (".$OpenCA::DBI::SQL->{VARIABLE}->{ACTION_NUMBER}[0]."=".$h.")";
    }
    $arguments->{db_hash}{QUERY} .= " order by ".$OpenCA::DBI::SQL->{VARIABLE}->{ACTION_NUMBER}[0];
    print "    query:".$arguments->{db_hash}{QUERY}."\n" if ($self->{DEBUG});
    undef @{$arguments->{db_hash}{BIND_VALUES}};
    
    print "    doQuery\n" if ($self->{DEBUG});
    if ( not defined $self->doQuery (\%{$arguments->{db_hash}}) ) {
      print "    doQuery failed\n" if ($self->{DEBUG});
      $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
      $self->doRollback (\%{$arguments->{db_hash}});
      $self->doDisconnect (\%{$arguments->{db_hash}}); #if negative should I abort here ?
      return -1;
    }
    $data = "";
    while ( (my %help_h = 
             $self->getResultHash (
               TABLE => "LOG",
               ARRAY => $arguments->{db_hash}{STH}[scalar (@{$arguments->{db_hash}{STH}}) -1]
                          ->fetchrow_arrayref
                                  )
            )
          ) {
      $data .= OpenCA::DBIS->getMergedData (DATA => \%help_h);
    }
    print "      data:\n".$data."\n"              if ($self->{DEBUG});
    print "      cert:".  $self->{CERT_FILE}."\n" if ($self->{DEBUG});
    print "      key:".   $self->{KEY_FILE}."\n"  if ($self->{DEBUG});
    print "      pwd:".   $self->{PASSWD}."\n"    if ($self->{DEBUG});
    
    my ($cert, $signdata) = OpenCA::DBIS->getSignature 
                             (
                              DATA          => $data,
                              DEBUG         => $self->{DEBUG}, 
                              SHELL         => $self->{backend},
                              MESSAGEKEY    => $self->{MESSAGEKEY},
                              MESSAGELENGTH => $self->{MESSAGELENGTH},
                              CERT_FILE     => $self->{CERT_FILE},
                              KEY_FILE      => $self->{KEY_FILE},
                              PASSWD        => $self->{PASSWD}
                             );
                               
    if (not $signdata) {
      print "      signing failed\n" if ($self->{DEBUG});
      $self->doRollback (\%{$arguments->{db_hash}});
      $self->doDisconnect (\%{$arguments->{db_hash}}); #if negative should I abort here ?
      $self->errno ( $OpenCA::DBI::ERROR->{SIGNING_LOG_FAILED} );
      return undef;
    }
    
    my $obj = new OpenCA::X509 (SHELL  => $self->{backend},
                                INFILE => $cert); 
    
    print "CERT:".$cert."\n" if ($self->{DEBUG});

    print "      preparing signing\n" if ($self->{DEBUG});
    $arguments->{db_hash}{QUERY} = "insert into ".$OpenCA::DBI::SQL->{TABLE}->{SIGNATURE}." (".
      $OpenCA::DBI::SQL->{VARIABLE}->{ACTION_NUMBER}[0].", ".
      $OpenCA::DBI::SQL->{VARIABLE}->{DATE}[0].", ".
      $OpenCA::DBI::SQL->{VARIABLE}->{DATA}[0].", ".
      $OpenCA::DBI::SQL->{VARIABLE}->{CERTIFICATE_SERIAL}[0].") VALUES (";
    ## info is only for the future
    ## $OpenCA::DBI::SQL->{VARIABLE}->{INFO}[0].") VALUES (";
    
    $arguments->{db_hash}{QUERY} .= $arguments->{new_action_number}.", ?, ?, ?)";
    undef @{$arguments->{db_hash}{BIND_VALUES}};
    $arguments->{db_hash}{BIND_VALUES} [0] = $arguments->{datetime};
    $arguments->{db_hash}{BIND_VALUES} [1] = $signdata;
    $arguments->{db_hash}{BIND_VALUES} [2] = $obj->getParsed()->{SERIAL};
    print "      query: ".$arguments->{db_hash}{QUERY}."\n" if ($self->{DEBUG});
    
    print "      doQuery for signature\n" if ($self->{DEBUG});  
    if ( not defined $self->doQuery (\%{$arguments->{db_hash}}) ) {
      $self->errno ( $OpenCA::DBI::ERROR->{INSERT_FAILED} );
      $self->doRollback (\%{$arguments->{db_hash}});
      $self->doDisconnect (\%{$arguments->{db_hash}}); #if negative should I abort here ?
      return -1;
    }
    print "    signature completely written to database\n" if ($self->{DEBUG});  
  } ## end of signing code

  return 1;
}

####################################
## end of storeItem related stuff ##
####################################

sub updateStatus {
  
  my $self = shift;
  my $keys = { @_ };
 
  return $self->storeItem ( MODE     => "UPDATE",
                            OBJECT   => $keys->{OBJECT},
                            DATATYPE => $keys->{NEWTYPE}
                          );
  
}

sub getItem {

  ## Get an Item provided the exact data to match:
  ## DATATYPE, KEY. Will return, if exists, the data
  ## on the corresponding dB file.
  
  ## Actually, as the search function, the returned
  ## value will be a referenced object (REQ, X509,
  ## CRL, etc... ).
  
  my $self = shift;
  my $keys = { @_ };
  
  my ( $fileName, $item, $txtItem, $body, $header, $hash, $tmpBody );
  
  my $type     = $keys->{DATATYPE};
  my $status   = $keys->{STATUS};
  my $baseType = $self->getBaseType( DATATYPE=>$type );
  my $table    = $self->getTable ($type);

  print "### new function call ###<br>\n".
        "  Entering sub getItem<br>\n" if ($self->{DEBUG});

  if ($table ne $type) {
    $status  = $self->getStatus (STATUS=>$status, DATATYPE=>$type);
  }
  
  my $serial = $keys->{KEY};  ## Key passed when stored item
  my $mode   = $keys->{MODE}; ## Actually only RAW or NULL
  
  print "  table: ".$table."<br>\n" if ($self->{DEBUG});
  print "  status: ".$status."<br>\n" if ($self->{DEBUG});
  print "  serial: ".$serial."<br>\n" if ($self->{DEBUG});

  my %db_hash = (STATUS => 0, 
                 DBH    => 0,
                 STH    => [],
                 QUERY  => "",
                 BIND_VALUES => [],
                );

  if( $baseType eq $type ) {
    $type = "VALID_" . $type;
  }
  
  ## Let's make some needed check
  if (not $table) {
    $self->errno ( $OpenCA::DBI::ERROR->{ MISSING_ARG_TABLE } );
    return undef;
  }
  ## support for direct access to latest CRL
  if ((not $serial) && ($table ne "CRL")) {
    $self->errno ( $OpenCA::DBI::ERROR->{ MISSING_ARG_SERIAL } );
    return undef;
  }

  print "  data complete\n" if ($self->{DEBUG});  

  ## I hope the people only search for Certs, Requests and CRRs
  ## mmh this is impossible
  $db_hash{QUERY} = "select * from ".$OpenCA::DBI::SQL->{TABLE}->{$table}." where ";
  if ($serial) {
    $db_hash{QUERY} .= "(".$OpenCA::DBI::SQL->{VARIABLE}->{$table."_SERIAL"}[0]."=?)";
    if ($status) {
      $db_hash{QUERY} .= " and (".$OpenCA::DBI::SQL->{VARIABLE}->{STATUS}[0]." like '".$status."')";
    }
    $db_hash{BIND_VALUES} [0] = $serial;
  } else {
    ## to support most actual CRL (you can use it find the last cert etc. too)
    $db_hash{QUERY} .= $OpenCA::DBI::SQL->{VARIABLE}->{DATE}[0]." like (select MAX (".
      $OpenCA::DBI::SQL->{VARIABLE}->{DATE}[0].") from ".$OpenCA::DBI::SQL->{TABLE}->{$table}.")";
    @{$db_hash{BIND_VALUES}} = ();
  }
  print "  query: ".$db_hash{QUERY}."<br>\n" if ($self->{DEBUG});

  my ($rv);

  print "  DBLOOP<br>\n" if ($self->{DEBUG});

  ## loop with two possible db-runs
  ## check operation_state, number of runs and backupDB
 DBLOOP: while () {

    ##   connect
    if ( not defined $self->doConnect (\%db_hash) ) {
      return undef;
    }
 
    ## do_query
    print "   doquery: ".$db_hash{QUERY}."<br>\n" if ($self->{DEBUG});
    if ( not defined $self->doQuery (\%db_hash) ) {
      $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
      $self->doRollback (\%db_hash);
      $self->doDisconnect (\%db_hash); #if negative should I abort here ?
      next DBLOOP;
    }
    print "   query completed<br>\n" if ($self->{DEBUG});
    
    ## false is ok  
    $rv = $db_hash{STH}[scalar (@{$db_hash{STH}}) -1]->state;
    if (not $rv) {
      print "  item returned<br>\n" if ($self->{DEBUG}); 
      my %hash = $self->getResultHash (TABLE => $table,
                         ARRAY => $db_hash{STH}[scalar (@{$db_hash{STH}}) -1]->fetchrow_arrayref);
      my $data        = $hash{DATA};
      my $info        = $hash{INFO};
      my $priv_format = $hash{FORMAT};
      print "   data:<br>\n".$data."<br>\n" if ($self->{DEBUG});
      print "   info: ".$info."<br>\n" if ($self->{DEBUG});
      print "   format: ".$priv_format."<br>\n" if ($self->{DEBUG});
      print "   have all data<br>\n" if ($self->{DEBUG});

      ## now comes nearly 100 percent OpenCA::DB code

      ## We may want to convert to a default format all objects
      ## excluding the "TXT" ones...
      if ( ($priv_format !~ /^.*SPKAC.*$/ ) and
	   ($priv_format ne "RENEW") and 
	   ($priv_format ne "REVOKE") and
           ($priv_format ne "TXT")
	 ) {
	my $tmpdata = $self->{backend}->dataConvert( 
						    DATATYPE =>$baseType,
						    INFORM   => "PEM",
						    OUTFORM  => "PEM",
						    DATA     => $data );
	$data = $tmpdata;
      }
      ## This $txtItem have the original object as it was stored
      ## with all infos in it
      $txtItem = "";
      ## this is a protection against signed requests
      if ($info and $data !~ /^$OpenCA::DBI::beginHeader/i) {
        $txtItem .= $OpenCA::DBI::beginHeader."\n".$info."\n".$OpenCA::DBI::endHeader. "\n";
      };
      $txtItem .= $data;
      print "   txtItem:<br>\n".$txtItem."<br>\n" if ($self->{DEBUG});      

      ## db-connection no longer needed
      ## I can take rollback too, it is not important because 
      ## it was only a read action and the database has nothing to do
      $self->doCommit (\%db_hash);
      $self->doDisconnect (\%db_hash);
      
      ## If it was asked only the text version, we send out only that
      ## without generating an OBJECT from it
      if( $mode eq "RAW" ) {
	print "   return data RAW<br>\n" if ($self->{DEBUG});
	return $txtItem;
      }
      
      ## Build an Object from retrieved DATA
      if( $table =~ /^.*CERTIFICATE$/ ) {
	$item = new OpenCA::X509( SHELL=>$self->{backend},
				  INFORM=>"PEM",
				  DATA=>$txtItem );
      } elsif ( $table eq "CRL" ) {
	print "   try to create crl<br>\n" if ($self->{DEBUG});	
	$item = new OpenCA::CRL( SHELL=>$self->{backend},
				 INFORM=>"PEM",
				 DATA=>$txtItem );
 	print "   crl there<br>\n" if ($self->{DEBUG} and $item);	
 	print "   crl failed<br>\n" if ($self->{DEBUG} and not $item);	
      } elsif ( $table eq "REQUEST" ) {
	my $format = "PEM";
	
	if( $txtItem =~ /SPKAC\s*=|RENEW\s*=|REVOKE\s*=/ ) {
	  ( $format ) = ( $txtItem =~ /(SPKAC|RENEW|REVOKE)/ );
	}

	$item = new OpenCA::REQ( SHELL=>$self->{backend},
				 INFORM=>$format,
				 DATA=>$txtItem );
      } elsif ( $table eq "CRR") {
	my $format = "PEM";
	
	if( $txtItem =~ /SPKAC\s*=|RENEW\s*=|REVOKE\s*=/ ) {
	  ( $format ) = ( $txtItem =~ /(SPKAC|RENEW|REVOKE)/ );
	}
	
	$item = new OpenCA::CRR( SHELL => $self->{backend},
                                 DATA  => $txtItem );
      } else {
	## if we cannot build the object there is probably
	## an error, retrun a void ...
	print "   cannot build object return void<br>\n" if ($self->{DEBUG});
        $self->errno ( $OpenCA::DBI::ERROR->{ CANNOT_CREATE_OBJECT } );
	return undef;
      }

      $item->{parsedItem}->{DBKEY} = $serial;

      ## We return the object
      print "   return item<br>\n" if ($self->{DEBUG});
      return $item;
      
    } else {
      ## db-connection no longer needed
      ## I can take rollback too, it is not important because 
      ## it was only a read action and the database has nothing to do
      $self->doCommit (\%db_hash);
      $self->doDisconnect (\%db_hash);
      $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
      next DBLOOP;
    }
  }

  ## never reached
  $self->errno ( $OpenCA::DBI::ERROR->{UNEXPECTED_ERROR} );
  return undef;

}

sub getNextItem {

  ## Get an Item provided the exact data to match:
  ## DATATYPE, KEY. Will return, if exists, the data
  ## on the corresponding dB file.
  
  ## Actually, as the search function, the returned
  ## value will be a referenced object (REQ, X509,
  ## CRL, etc... ).
  
  my $self = shift;
  my $keys = { @_ };
  
  my $type    = $keys->{DATATYPE};
  my $table   = $self->getTable ($type);
  my $status  = $keys->{STATUS};

  if ($table ne $type) {
    $status  = $self->getStatus (STATUS=>$keys->{STATUS}, DATATYPE=>$type);
  }
 
  my $serial  = $keys->{KEY};  ## Key passed when stored item
  
  my %db_hash = (STATUS => 0, 
                 DBH    => 0,
                 STH    => [],
                 QUERY  => "",
                 BIND_VALUES => [],
                );

  ## Let's make some needed check
  if (not $table) {
    $self->errno ( $OpenCA::DBI::ERROR->{ MISSING_ARG_TABLE } );
    return undef;
  }
  if ( (not $serial) and ($serial != 0) ) {
    $self->errno ( $OpenCA::DBI::ERROR->{ MISSING_ARG_SERIAL } );
    return undef;
  }

  ## I hope the people only search for Certs, Requests and CRRs
  ## mmh this is impossible
  $db_hash{QUERY} = "select MIN (".$OpenCA::DBI::SQL->{VARIABLE}->{$table."_SERIAL"}[0].")".
    " from ".$OpenCA::DBI::SQL->{TABLE}->{$table}." where (".
    $OpenCA::DBI::SQL->{VARIABLE}->{$table."_SERIAL"}[0]." > ? ".
    ")";
  undef @{$db_hash{BIND_VALUES}};
  if ($status) {
    $db_hash{QUERY} .= " and (".$OpenCA::DBI::SQL->{VARIABLE}->{STATUS}[0]." like ?)";
    $db_hash{BIND_VALUES} [1] = $status;
  }
  $db_hash{BIND_VALUES} [0] = $serial; # date is not numeric
  if ( $serial =~ /^$/ ) {
    $db_hash{BIND_VALUES} [0] = "";
  }
  my $rv;

  ## loop with two possible db-runs
  ## check operation_state, number of runs and backupDB
 DBLOOP: while () {
    ##   connect
    if ( not defined $self->doConnect (\%db_hash) ) {
      return undef;
    }
    
    ## do_query
    if ( not defined $self->doQuery (\%db_hash) ) {
      $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
      $self->doRollback (\%db_hash);
      $self->doDisconnect (\%db_hash); #if negative should I abort here ?
      next DBLOOP;
    }
      
    my $ref = $db_hash{STH}[scalar (@{$db_hash{STH}}) -1]->fetchrow_arrayref;

    if (defined $ref) {
      # copy by value !!!
      $serial = $ref->[0];
    }


    ## I can take rollback too, it is not important because 
    ## it was only a read action and the database has nothing to do    
    $self->doCommit (\%db_hash);
    $self->doDisconnect (\%db_hash);
    if (defined $ref) {
      return $self->getItem (DATATYPE => $keys->{DATATYPE},
			     STATUS   => $keys->{STATUS},
			     KEY      => $serial,
			     MODE     => $keys->{MODE}
			    );
    } else {
      ## false is SQLSTATE '0000000' which means all is ok
      if (not $db_hash{STH}[scalar (@{$db_hash{STH}}) -1]->state) {
        $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
        return undef; ## no errors no results
      } else { # mmh this should never happen here
        $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
        next DBLOOP;
      }
    }
  }
  
  ## never reached
  $self->errno ( $OpenCA::DBI::ERROR->{UNEXPECTED_ERROR} );
  return undef;

}

sub getPrevItem {

  ## Get an Item provided the exact data to match:
  ## DATATYPE, KEY. Will return, if exists, the data
  ## on the corresponding dB file.
  
  ## Actually, as the search function, the returned
  ## value will be a referenced object (REQ, X509,
  ## CRL, etc... ).
  
  my $self = shift;
  my $keys = { @_ };
  
  my $type    = $keys->{DATATYPE};
  my $table   = $self->getTable ($type);
  my $status  = $keys->{STATUS};

  if ($table ne $type) {
    $status  = $self->getStatus (STATUS=>$keys->{STATUS}, DATATYPE=>$type);
  }
  
  my $serial    	= $keys->{KEY};  ## Key passed when stored item
  
  my %db_hash = (STATUS => 0, 
                 DBH    => 0,
                 STH    => [],
                 QUERY  => "",
                 BIND_VALUES => [],
                );
  
  ## Let's make some needed check
  if (not $table) {
    $self->errno ( $OpenCA::DBI::ERROR->{MISSING_ARG_TABLE} );
    return undef;
  }
  if (not $serial) {
    $self->errno ( $OpenCA::DBI::ERROR->{MISSING_ARG_SERIAL} );
    return undef;
  }

  ## I hope the people only search for Certs, Requests and CRRs
  ## mmh this is impossible
  ## Attention date is not numeric !!!
  $db_hash{QUERY} = "select MAX (".$OpenCA::DBI::SQL->{VARIABLE}->{$table."_SERIAL"}[0].")".
    " from ".$OpenCA::DBI::SQL->{TABLE}->{$table}." where (".
    $OpenCA::DBI::SQL->{VARIABLE}->{$table."_SERIAL"}[0]."< ? ".
    ")";
  undef @{$db_hash{BIND_VALUES}};
  if ($status) {
    $db_hash{QUERY} .= " and (".$OpenCA::DBI::SQL->{VARIABLE}->{STATUS}[0]."=?)";
    $db_hash{BIND_VALUES} [0] = $status;
  }
  $db_hash{BIND_VALUES} [0] = $serial; # date is not numeric

  my $rv;

  ## loop with two possible db-runs
  ## check operation_state, number of runs and backupDB
 DBLOOP: while () {

    ##   connect
    if ( not defined $self->doConnect (\%db_hash) ) {
      return undef;
    }
    
    ## do_query
    if ( not defined $self->doQuery (\%db_hash) ) {
      $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
      $self->doRollback (\%db_hash);
      $self->doDisconnect (\%db_hash); #if negative should I abort here ?
      next DBLOOP;
    }
      
    $rv = $db_hash{STH}[scalar (@{$db_hash{STH}}) -1]->rows;

    if ($rv == 1) {
      # copy by value !!!
      $serial = $db_hash{STH}[scalar (@{$db_hash{STH}}) -1]->fetchrow_arrayref->[0];
    }

    ## I can take rollback too, it is not important because 
    ## it was only a read action and the database has nothing to do    
    $self->doCommit (\%db_hash);
    $self->doDisconnect (\%db_hash);
    if ($rv == 1) {
      ## $rv > 1 is not possible because of SQL's MIN-Operator
      return $self->getItem (DATATYPE => $keys->{DATATYPE},
			     STATUS   => $keys->{STATUS},
			     KEY      => $serial,
			     MODE     => $keys->{MODE}
			    );
  
    } elsif ($rv == 0) {
      $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
      return undef; ## no errors no results
    } else { # $rv < 0 mmh this should never happen here
      $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
      next DBLOOP;
    }
  }
  
  ## never reached
  $self->errno ( $OpenCA::DBI::ERROR->{UNEXPECTED_ERROR} );
  return undef;

}

sub deleteItem {
  ## it's not neccessary to delete an object if it is revoked/marked as deleted
  return 1;
}

sub destroyItem {
  ## attention this code is not for normal use only for recovery reasons !
  ## if you want to say a request is deleted than storeItem with
  ## STATUS = $OpenCA::DBI::status->{DELETED}

  ## Get an Item provided the exact data to match:
  ## DATATYPE, KEY. Will return, if exists, the data
  ## on the corresponding dB file.
  
  ## Actually, as the search function, the returned
  ## value will be a referenced object (REQ, X509,
  ## CRL, etc... ).
  
  my $self = shift;
  my $keys = { @_ };
  
  my $type  = $keys->{DATATYPE};
  my $table = $self->getTable ($type);
  
  my $serial = $keys->{KEY};  ## Key passed when stored item
  
  my %db_hash = (STATUS => 0, 
                 DBH    => 0,
                 STH    => [],
                 QUERY  => "",
                 BIND_VALUES => [],
                );

  ## Let's make some needed check
  if (not $table) {
    $self->errno ( $OpenCA::DBI::ERROR->{MISSING_ARG_TABLE} );
    return undef;
  }
  if (not $serial) {
    $self->errno ( $OpenCA::DBI::ERROR->{MISSING_ARG_SERIAL} );
    return undef;
  }

  ## I hope the people only search for Certs, Requests and CRRs
  ## mmh this is impossible
  ## Attention date is not numeric !!!
  $db_hash{QUERY} = "delete from ".$OpenCA::DBI::SQL->{TABLE}->{$table}." where ".
    $OpenCA::DBI::SQL->{VARIABLE}->{$table."_SERIAL"}[0]."= ? ".
  undef @{$db_hash{BIND_VALUES}};
  $db_hash{BIND_VALUES} [0] = $serial; # date is not numeric

  ## loop with two possible db-runs
  ## check operation_state, number of runs and backupDB
 DBLOOP: while () {

    ##   connect
    if ( not defined $self->doConnect (\%db_hash) ) {
      return undef;
    }
    
    ## do_query
    if ( not defined $self->doQuery (\%db_hash) ) {
      $self->errno ( $OpenCA::DBI::ERROR->{DELETE_FAILED} );
      $self->doRollback (\%db_hash);
      $self->doDisconnect (\%db_hash); # if negative should I abort here ?
      next DBLOOP;
    }

    if (not defined $self->doCommit (\%db_hash) ) {
      $self->doRollback (\%db_hash);
      $self->doDisconnect (\%db_hash); # if negative should I abort here ?
      next DBLOOP;
    }
    $self->doDisconnect (\%db_hash); # if negative should I abort here ?
      
    ## successful
    return 1;
  }
  
  ## never reached
  $self->errno ( $OpenCA::DBI::ERROR->{UNEXPECTED_ERROR} );
  return undef;

}

sub elements {

  ## Get an Item provided the exact data to match:
  ## DATATYPE, KEY. Will return, if exists, the data
  ## on the corresponding dB file.
  
  ## Actually, as the search function, the returned
  ## value will be a referenced object (REQ, X509,
  ## CRL, etc... ).
  
  my $self = shift;
  my $keys = { @_ };
  
  my $type   = $keys->{DATATYPE};
  my $table  = $self->getTable ($type);
  my $status = $keys->{STATUS};

  print "### new function call ###<br>\n".
        "  Entering function elements<br>\n" if ($self->{DEBUG});

  if ($table ne $type) {
    $status = $self->getStatus (STATUS=>$keys->{STATUS}, DATATYPE=>$type);
  }
    
  my %db_hash = (STATUS => 0, 
                 DBH    => 0,
                 STH    => [],
                 QUERY  => "",
                 BIND_VALUES => [],
                );
  
  ## Let's make some needed check
  if (not $table) {
    $self->errno ( $OpenCA::DBI::ERROR->{MISSING_ARG_TABLE} );
    return undef;
  }
  my $count;

  ## I hope the people only search for Certs, Requests and CRRs
  ## mmh this is impossible
  ## Attention date is not numeric !!!
  $db_hash{QUERY} = "select count(*)  from ".$OpenCA::DBI::SQL->{TABLE}->{$table};
  undef @{$db_hash{BIND_VALUES}};
  if ($status) {
    $db_hash{QUERY} .= " where ".$OpenCA::DBI::SQL->{VARIABLE}->{STATUS}[0]." like ?";
    $db_hash{BIND_VALUES} [0] = $status;
  }
  
  my $rv;

  ## loop with two possible db-runs
  ## check operation_state, number of runs and backupDB
 DBLOOP: while () {

    ##   connect
    if (not defined $self->doConnect (\%db_hash) ) {
      return undef;
    }
    
    ## do_query
    if (not defined $self->doQuery (\%db_hash) ) {
      $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
      $self->doRollback (\%db_hash);
      $self->doDisconnect (\%db_hash); #if negative should I abort here ?
      next DBLOOP;
    }

    ## here I have to use state because DB2 
    ## returns rows:=-1 even if there is a result
    ## false means here a successful performed SQL-query ('00000000')
    $rv = $db_hash{STH}[scalar (@{$db_hash{STH}}) -1]->state;
    print "  state: \$rv=".$rv."<br>\n" if ($self->{DEBUG});
         
    if (not $rv) {
      # copy by value !!!
      $count = $db_hash{STH}[scalar (@{$db_hash{STH}}) -1]->fetchrow_arrayref->[0];
    }

    ## I can take rollback too, it is not important because 
    ## it was only a read action and the database has nothing to do    
    $self->doCommit (\%db_hash);
    $self->doDisconnect (\%db_hash);
    if (not $rv) {
      ## $rv > 1 is not possible because of SQL's COUNT-Operator
      print "  elements comleted successful<br>\n".
            "### leaving function elements ###<br>\n" if ($self->{DEBUG});
      return $count;
    ## } elsif ($rv == 0) {
    ##   $self->errno ( $OpenCA::DBI::ERROR->{UNEXPECTED_ERROR} );
    ##   print "  elements comleted unsuccessful<br>\n".
    ##         "### leaving function elements ###<br>\n" if ($self->{DEBUG});
    ##   return undef; ## unexpected error
    } else { # $rv < 0 mmh this should never happen here
      $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
      print "  next round - db-request failed<br>\n" if ($self->{DEBUG});
      next DBLOOP;
    }
  }
  
  ## never reached
  $self->errno ( $OpenCA::DBI::ERROR->{UNEXPECTED_ERROR} );
  return undef;

}

sub searchItems { # new one !!!

  ## Get an Item provided the exact data to match:
  ## DATATYPE, KEY. Will return, if exists, the data
  ## on the corresponding dB file.
  
  ## Actually, as the search function, the returned
  ## value will be a referenced object (REQ, X509,
  ## CRL, etc... ).
  
  my $self = shift;
  my $keys = { @_ };
  
  my (@retList, @objRetList);

  print "### new function call ###<br>\n".
        "  Entering function searchItems<br>\n" if ($self->{DEBUG});
 
  my %arguments = $self->getArguments ( @_ ); 
  print "dbi-status:".$arguments {STATUS}."<br>\n" if ($self->{DEBUG});

  my $mode   	= $keys->{MODE}; ## Actually only ROWS or NULL
  
  my %db_hash = (STATUS => 0, 
                 DBH    => 0,
                 STH    => [],
                 QUERY  => "",
                 BIND_VALUES => [],
                );
  undef @{$db_hash{BIND_VALUES}};

  ## Let's make some needed check
  if (not $arguments {TABLE}) {
    $self->errno ( $OpenCA::DBI::ERROR->{MISSING_ARG_TABLE} );
    return undef;
  }
  
  ## let's prepare the question
  my $and = 0;
  $db_hash{QUERY} = "select * from ".$OpenCA::DBI::SQL->{TABLE}->{$arguments {TABLE}};
  ## check for unique identifier scan
  if ( $keys->{SERIAL} and ($arguments {TABLE} =~ /CERTIFICATE/ ) ) {
    if ($and) {
      $db_hash{QUERY} .= " and ";
    } else {
      $db_hash{QUERY} .= " where ";
      $and = 1;
    }
    $db_hash{QUERY} .= "(".$OpenCA::DBI::SQL->{VARIABLE}->{CERTIFICATE_SERIAL}[0]."=?)";
    ## prepare bind_values
    $db_hash{BIND_VALUES} [scalar (@{$db_hash{BIND_VALUES}})] = $keys->{SERIAL};
    ## delete from keys
    delete $keys->{SERIAL};
  }
    
  print "  query now:".$db_hash{QUERY}."<br>\n" if ($self->{DEBUG});

  ## For every keyword let's get the list of values
  my @attributes = $self->getSearchAttributes (DATATYPE=>$arguments {TABLE});
  my $attr;
  for $attr ( @attributes ) {
    print "  scan attribute: ".$attr."<br>\n" if ($self->{DEBUG});
    if ($arguments {$attr}) {
      print "  attribute's content: ".$arguments {$attr}."<br>\n" if ($self->{DEBUG});
      ## get from keys
      if ($and) {
	$db_hash{QUERY} .= " and ";
      } else {
	$db_hash{QUERY} .= " where ";
	$and = 1;
      }
      if ($attr =~ /^KEY$/) {
        $db_hash{QUERY} .= "(".
          $OpenCA::DBI::SQL->{VARIABLE}->{$arguments {TABLE}."_SERIAL"}[0]."=?)";
      } else {
        $db_hash{QUERY} .= "(".$OpenCA::DBI::SQL->{VARIABLE}->{$attr}[0]." like ?)";
      }
      ## prepare bind_values
      $db_hash{BIND_VALUES} [scalar (@{$db_hash{BIND_VALUES}})] = 
        $arguments {$attr};
      ## delete from keys
      delete $keys->{$attr};
    }
  }
  print "  query:".$db_hash{QUERY}."<br>\n" if ($self->{DEBUG});
  ## keys should be empty ?
  ## if (scalar %$keys) {
  ##   return $OpenCA::DBI::ERROR->{UNSUPPORTED_SEARCH_ATTRIBUTE};
  ## }  
  ## print "  no unsupported attribute\n" if ($self->{DEBUG});
  
  my $rv = 0;

  ## loop with two possible db-runs
 DBLOOP: while () {
    
    ##   connect
    if (not defined $self->doConnect (\%db_hash) ) {
      return undef;
    }
    
    ## do_query
    $rv = $self->doQuery (\%db_hash);
    if (not defined $rv ) {
      $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
      $self->doRollback (\%db_hash);
      $self->doDisconnect (\%db_hash); #if negative should I abort here ?
      next DBLOOP;
    } else {

      ## original "stolen" from OpenCA::DB sub searchItemDB

      print "  state(false is OK): ".
	$db_hash{STH}[scalar (@{$db_hash{STH}})-1]->state."<br>\n" if ($self->{DEBUG});
      print "  rows: ".
	$db_hash{STH}[0]->rows."<br>\n" if ($self->{DEBUG});
	## $db_hash{STH}[scalar (@{$db_hash{STH}})-1]->rows."<br>\n" if ($self->{DEBUG});
      ## Results
      ## be warned fetchrow_hashref doesn't work with DB2
      while ( (my $h =  $db_hash{STH}[scalar (@{$db_hash{STH}}) -1]->fetchrow_arrayref) ) {
        print "  item: ".
              $h->[0].
              "<br>\n" if ($self->{DEBUG});
	push ( @retList, $h->[0] );
      }

      ## I can take rollback too, it is not important because 
      ## it was only a read action and the database has nothing to do
      $self->doCommit (\%db_hash);
      $self->doDisconnect (\%db_hash);      
      
      ## because of searchItemDB + searchItem 
      ## but what it's doing ?
      if( $mode eq "ROWS" ) {
        print "  function searchItems completed successful<br>\n".
              "### leaving function searchItems ###<br>\n" if ($self->{DEBUG});
        return ($#retList+1);
      }
      
      for my $i (@retList) {
	my $obj;
	
	next if ( not $obj = $self->getItem( DATATYPE=>$keys->{DATATYPE}, KEY=>$i ));
	print "  add an object to the returnlist of searchItem\n" if ($self->{DEBUG});
	push( @objRetList, $obj );
      }

      print "  function searchItems completed successful<br>\n".
            "### leaving function searchItems ###<br>\n" if ($self->{DEBUG});
      return @objRetList;

    }
  }

  ## never reached
  $self->errno ( $OpenCA::DBI::ERROR->{UNEXPECTED_ERROR} );
  return undef;

}

sub listItems {
  my $self = shift;
  my $keys = { @_ };

  my $dataType	= $keys->{DATATYPE};
  my $items 	= $keys->{ITEMS};
  my $from 	= $keys->{FROM};
  ## my $to 		= $keys->{TO};
  my $mode	= $keys->{MODE};

  my ( @ret, $retItems, $i, $tmpObj, $dbKey );

  print "### new function call ###<br>\n".
        "Entering function listItems<br>\n" if ($self->{DEBUG});

  if( not $dataType ) {
    $self->errno ( $OpenCA::DBI::ERROR->{MISSING_ARG_DATATYPE} );
    return undef;
  }

  ## check sql-type of key of table
  my $table = $self->getTable ($dataType);
  if (not $table) {
    $self->errno ( $OpenCA::DBI::ERROR->{MISSING_ARG_TABLE} );
    return undef;
  }
  my $pseudo_sql_type = 
    $OpenCA::DBI::SQL->{VARIABLE}->{
      $OpenCA::DBI::SQL->{TABLE_STRUCTURE}->{$table}[0]
    }[1];
  my $is_int = 0;
  $is_int = 1 if ( $pseudo_sql_type =~ /INT/i );

  ## set intial values
  if ( $is_int ) {
    $from = 0 if (not $from);
  } else {
    $from = "" if (not $from);
  }
  $dbKey = $from;

  ## if all items are requested
  $items = -1 if (not $items);

  ## get the items
  for ( my $i = 0; $i != ($items-1); $i++ ) {

    last if ( not $tmpObj = $self->getNextItem( DATATYPE=>$dataType,
                                                MODE=>$mode,
                                                KEY=>$dbKey )
            );
    if ( $mode ne "RAW" ) {
      $dbKey = $tmpObj->getParsed()->{DBKEY};
    } else {
      $dbKey = $tmpObj;
    }
    push( @ret, $tmpObj );
  }

  print "  listItem completed successful<br>\n".
        "### leaving function successfully ###<br>\n" if ($self->{DEBUG});
  return @ret;
}

##################################################
## original unchanged functions from OpenCA::DB ##
##################################################

# For logical reasons I don't touch this code
# This is original from OpenCA::DB so please
# ask Massimiliano Pala if anything is unclear
# madwolf@openca.org
#
sub getBaseType {

  ## What is with CRR and why I divide CERTIFICATE and CA_CERTIFICATE ?
  ## These are not my Problems but what do the programs with this info ?

  my $self = shift;
  
  my $keys = { @_ };
  my $dataType = $keys->{DATATYPE};
  
  my $ret;
  
  if ( $dataType =~ /CA_CERTIFICATE/ ) {
    $ret = "CA_CERTIFICATE";
  } elsif ( $dataType =~ /CERTIFICATE/ ) {
    $ret = "CERTIFICATE";
  } elsif ( $dataType =~ /CRL/ ) {
    $ret = "CRL";
  } elsif ( $dataType =~ /REQUEST/ ) {
    $ret = "REQUEST";
  } else {
    ## Unsupported DATATYPE
    $self->errno ( $OpenCA::DBI::ERROR->{UNSUPPORTED_OBJECT} );
    return undef;
  }
  
  return $ret;
}

sub rows {

	## Returns the number of item matching the request. You can search
	## for generic DATATYPE such as CERTIFICATE|REQUEST|CRL
	## or restricted type (EXPIRED_CERTIFICATE|REVOKED_CERTIFICATE|
	## VALID_CERTIFICATE...
	##
	## This function should be used in conjunction with searching function
	## use the elements sub instead if you wish to know how many specific
	## dB elements are there (such as VALID_CERTIFICATES, etc ... )

	my $self = shift;
	my $keys = { @_ };

	return $self->searchItems( MODE=>"ROWS", @_ );
}

sub byKey { $a->{KEY} <=> $b->{KEY} };

sub hash2txt {
  my $self  = shift;

  my $keys = $_[0];
 
  my $record = "";
  my ( $i, $key, $val );
 
  for $key (keys %{$keys}) {
    print "OpenCA::DBI->hash2txt: key=$key val=".$keys->{$key}."<br>\n"
      if ($self->{DEBUG});
    if ($keys->{$key} =~ /\n/) {
      ## multicolumn
      $record .= "$key=\n".$OpenCA::DBI::beginAttribute.
                 "\n".$keys->{$key}."\n".$OpenCA::DBI::endAttribute."\n";
    } else {
      ## single column
      $record .= "$key=".$keys->{$key}."\n";
    }
  }
  $record =~ s/(\n)$//;

  print "OpenCA::DBI->hash2txt: record=".$record."<br>\n" if ($self->{DEBUG}); 
  return $record;
}

## actually completely unused
## but present for compatibility reasons
sub txt2hash {
        my $self = shift;
        my $keys = { @_ };
 
        my $txt      = $keys->{TXT};
 
        my ( $ret, $key, $val, $line );

        ## begin of copy from X509.pm

        my $active_multicolumn = 0;
        foreach my $i ( split ( /\n/, $txt ) ) {
                if ($active_multicolumn) {
                  ## multicolumn
                  if ($i =~ /^$OpenCA::DBI::endAttribute$/) {
                    ## end of multicolumn
                    $active_multicolumn = 0;
                  } else {
                    ## additional data
                    $ret->{key} .= "\n".$i;
                  }
                } elsif ($i =~ /^$OpenCA::DBI::beginAttribute$/) {
                  ## begin of multicolumn
                  $active_multicolumn = 1;
                } else {
                  ## no multicolumn
                  ## if multicolumn then $ret->{key} is initially empty)                          $i =~ s/\s*=\s*/=/;
                  ( $key, $val ) = ( $i =~ /(.*)\s*=\s*(.*)\s*/ );
                  $ret->{$key} = $val;
                }
        } 

        ## end of copy from X509.pm

        return $ret;
} 

#########################################################
## end of original unchanged functions from OpenCA::DB ##
#########################################################

###################
## new functions ##
###################

## new extended function for getSearchAttributes which doesn't
## return the index (SERIAL, KEY or DATE)
sub getSearchAttributes {
        my $self = shift;
        my $keys = { @_ };

        my $type = $keys->{DATATYPE};
        my @ret = ();

        if ( not $type ) {
          $self->errno ( $OpenCA::DBI::ERROR->{MISSING_ARG_DATATYPE} );
          return undef;
        }

        if ( $type =~ /REQUEST/ ) {
                @ret = ( "KEY", 
                         "STATUS",
                         "DN",
                         "CN",
                         "EMAIL",
                         "RA",
                         "OPERATOR",
                         "ROLE" );
        } elsif ( $type =~ /CA_CERTIFICATE/ ) {
                @ret = ( "KEY",
                         "STATUS",
                         "DN",
                         "CN",
                         "EMAIL" );
        } elsif ( $type =~ /CERTIFICATE/ ) {
                @ret = ( "KEY",
                         "STATUS",
                         "DN",
                         "CN",
                         "EMAIL",
                         "ROLE" );
        } elsif ( $type =~ /CRR/ ) {
                @ret = ( "KEY",
                         "STATUS",
                         "CERTIFICATE_SERIAL",
                         "DN",
                         "CN",
                         "EMAIL",
                         "RA",
                         "OPERATOR",
                         "SUBMIT_DATE" );
        } elsif ( $type =~ /CRL/ ) {
                @ret = ( "KEY",
                         "STATUS",
                         "LAST_UPDATE",
                         "NEXT_UPDATE" );
        };

        return @ret;
}

## returns now iso-time
sub getTimeString {

	my $self = shift;
	my  ( $ret, @T );

	@T = gmtime( time() );
        ## iso is yyyy-mm-dd hh:mm:ss
	$ret = sprintf( "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d",
			 $T[5]+1900, $T[4], $T[3], $T[2], $T[1], $T[0] );
	# $ret = sprintf( "%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d,%6.6d",
	#		 $T[5]+1900, $T[4], $T[3], $T[2], $T[1], $T[0], ${$} );

	return $ret;

}

## parse the arguments for all functions
sub getArguments {

  my $self = shift;
  my $keys = { @_ };

  my %result;

  print "### new function call ###<br>\n".
        "  Entering getArguments<br>\n" if ($self->{DEBUG});
 
  $result {TABLE} = $self->getTable ($keys->{DATATYPE});

  ## get all searchable attributes
  my @attributes = $self->getSearchAttributes( DATATYPE => $result {TABLE} );
  my $attr;

  for $attr ( @attributes ) {
    
    print "  attribute: ".$attr."<br>\n" if ($self->{DEBUG});      
    $result {$attr} = $keys->{$attr};
    print "  value: ".$result {$attr}."<br>\n" if ($self->{DEBUG});      
  }

  ## enforce status
  $result {STATUS} = $self->getStatus ( STATUS   => $result {STATUS},
                                          DATATYPE => $keys->{DATATYPE} );
  if (not $result {STATUS}) {
    delete ($result {STATUS});
  } elsif ($self->{DEBUG}) {
    print "  status: ".$result {STATUS}."<br>\n";
  }

  print "  completed successful<br>\n".
        "### leaving function getArguments ###<br>\n" if ($self->{DEBUG});
  return %result;
}


## this is a standardinterface to get the table from the original
## datatype. so we can use the normal interface of OpenCA::DB
sub getTable {
  my $self = shift;
  my $datatype = $_[0];
  
  my $ret;
  
  if ( $datatype =~ /.*CA_CERTIFICATE/ ) {
    $ret = "CA_CERTIFICATE";
  } elsif ( $datatype =~ /.*CERTIFICATE/ ) {
    $ret = "CERTIFICATE";
  } elsif ( $datatype =~ /.*CRL/ ) {
    $ret = "CRL";
  } elsif ( $datatype =~ /.*REQUEST/ ) {
    $ret = "REQUEST";
  } elsif ( $datatype =~ /.*CRR/ ) {
    $ret = "CRR";
  } else {
    ## Unsupported DATATYPE
    ## log and signature are no objects actually
    $ret = "";
  }
  
  return $ret;  
}

## this function support to work with old and new code
## this means that I check for STATUS and if it is not existent
## I try to extract it from the datatype
sub getStatus {
  my $self = shift;
  my $keys = { @_ };

  my $status   = $keys->{STATUS};
  my $datatype = $keys->{DATATYPE};

  print "### new function call ###<br>\n".
        "  Entering getStatus<br>\n" if ($self->{DEBUG});

  if ($status) {
    print "    status predefined: ".$status."<br>\n" if ($self->{DEBUG});
    ## check for legal status
    if ( $OpenCA::DBI::STATUS->{$status} ) {
      print "  legal status<br>\n".
            "### leaving function successful ###<br>\n" if ($self->{DEBUG});
      return $status;
    } else {
      print "  illegal status<br>\n".
            "### leaving function unsuccessful ###<br>\n" if ($self->{DEBUG});
      $self->errno ( $OpenCA::DBI::ERROR->{ILLEGAL_STATUS} );
      return undef;
    }
  } else {
    print "  no status given using datatype: ".$datatype."<br>\n" if ($self->{DEBUG});
    ## try to extract status from datatype
    ## erase all behind the first "_" incl. this "_" itself
    my $old = $datatype;
    $datatype =~ s/_.*//g;
    ## if no status is transmitted I switch to "" -> valid
    $datatype = "" if ($old eq $datatype); 
    $datatype = uc $datatype;
    print "    given mode is: \"".$datatype."\"<br>\n" if ($self->{DEBUG});
    ## check for legal status
    if ( $OpenCA::DBI::STATUS->{$datatype} ) {
      print "  legal status<br>\n".
            "### leaving function successful ###<br>\n" if ($self->{DEBUG});
      return $datatype;
    } else {
      print "  illegal status<br>\n".
            "### leaving function unsuccessful ###<br>\n" if ($self->{DEBUG});
      $self->errno ( $OpenCA::DBI::ERROR->{ILLEGAL_STATUS} );
      return undef;
    }
  }
}

## please see comment about doFunctions
## returns a new unique action_number
sub getSequence {
  my $self = shift;
  my $keys = $_[0]; # this is a accossiative array (hash)

  my ($dsn, $user, $passwd);
  my @attr = {RaiseError => 0, Taint => 0, AutoCommit =>0};

  print "      Entering getSequence\n" if ($self->{DEBUG});

  if ($keys->{TYPE} eq "Pg") {
    print "        Pg\n" if ($self->{DEBUG});
    $keys->{QUERY} = "select last_value from ".$OpenCA::DBI::SQL->{TABLE}->{SEQUENCE};
    undef @{$keys->{BIND_VALUES}};
    print "        query:".$keys->{QUERY}."\n" if ($self->{DEBUG});
    if (not defined $self->doQuery ($_[0]) ) {
      $self->errno ( $OpenCA::DBI::ERROR->{SEQUENCE_GENERATOR_FAILED} );
      return undef;
    }
    print "        not failed\n" if ($self->{DEBUG});
    return $keys->{STH}[scalar (@{$keys->{STH}}) -1]->fetchrow_arrayref->[0];
  } elsif ($keys->{TYPE} eq "mysql") {
    print "        mysql\n" if ($self->{DEBUG});
    ## the last sql-query was the insert command
    return $keys->{STH}[scalar (@{$keys->{STH}}) -1]->{insertid};
  } elsif ( $keys->{TYPE} =~ /^DB2$/ ) {
    print "        DB2\n" if ($self->{DEBUG});
    ## the last sql-query was the insert command to sequence
    $keys->{QUERY} = "select distinct IDENTITY_VAL_LOCAL() from ".
                     $OpenCA::DBI::SQL->{TABLE}->{SEQUENCE} ;
    undef @{$keys->{BIND_VALUES}};
    print "        query:".$keys->{QUERY}."\n" if ($self->{DEBUG});
    if (not defined $self->doQuery ($_[0]) ) {
      $self->errno ( $OpenCA::DBI::ERROR->{SEQUENCE_GENERATOR_FAILED} );
      return undef;
    }
    print "        not failed\n" if ($self->{DEBUG});
    return $keys->{STH}[scalar (@{$keys->{STH}}) -1]->fetchrow_arrayref->[0];
  } elsif ($keys->{TYPE} eq "Oracle") {
    print "        Oracle\n" if ($self->{DEBUG});
    $keys->{QUERY} = "select ".$OpenCA::DBI::SQL->{TABLE}->{SEQUENCE}.
                     ".currval from DUAL";
    undef @{$keys->{BIND_VALUES}};
    print "        query:".$keys->{QUERY}."\n" if ($self->{DEBUG});
    if (not defined $self->doQuery ($_[0]) ) {
      $self->errno ( $OpenCA::DBI::ERROR->{SEQUENCE_GENERATOR_FAILED} );
      return undef;
    }
    print "        not failed\n" if ($self->{DEBUG});
    return $keys->{STH}[scalar (@{$keys->{STH}}) -1]->fetchrow_arrayref->[0];
  }
  ## unknown database
  ## so now we have to take the next db
  ## to understand what this do please look at the doQuery function
  $keys->{STATUS} ++;
  $self->errno ($openCA::DBI::ERROR->{DB_TYPE_UNKNOWN});
  return undef;
}

sub build_date {
  my $self = shift;
  my $date = $_[0];
  my %help;
  my $new_date;

  ##  Mar 10 19:36:45 2001 GMT

  ## Month
  if ( $date =~ /^ *JAN/i ) {
    ##  january
    $help {MONTH} = "01";
  } elsif ( $date =~ /^ *FEB/i ) {
    ## february
    $help {MONTH} = "02";
  } elsif ( $date =~ /^ *MAR/i ) {
    ## march
    $help {MONTH} = "03";
  } elsif ( $date =~ /^ *APR/i ) {
    ## april
    $help {MONTH} = "04";
  } elsif ( $date =~ /^ *MAY/i ) {
    ## may
    $help {MONTH} = "05";
  } elsif ( $date =~ /^ *JUN/i ) {
    ## june
    $help {MONTH} = "06";
  } elsif ( $date =~ /^ *JUL/i ) {
    ## july
    $help {MONTH} = "07";
  } elsif ( $date =~ /^ *AUG/i ) {
    ## august
    $help {MONTH} = "08";
  } elsif ( $date =~ /^ *SEP/i ) {
    ## september
    $help {MONTH} = "09";
  } elsif ( $date =~ /^ *OCT/i ) {
    ## october
    $help {MONTH} = "10";
  } elsif ( $date =~ /^ *NOV/i ) {
    ## november
    $help {MONTH} = "11";
  } elsif ( $date =~ /^ *DEC/i ) {
    ## december
    $help {MONTH} = "12";
  } else {
    ## return illegal
    $self->errno ( $OpenCA::DBI::ERROR->{ILLEGAL_DATE} );
    return undef;
  }

  ## day
  $date =~ s/^ *//;
  $date = substr ($date, 4, length ($date)-4);
  $help {DAY} = substr ($date, 0, 2);

  ## hour
  $help {HOUR} = substr ($date, 3, 2);

  ## minute
  $help {MINUTE} = substr ($date, 6, 2);

  ## second
  $help {SECOND} = substr ($date, 9, 2);

  ## year
  $help {YEAR} = substr ($date, 12, 4);

  ## build date
  $new_date = $help {YEAR}.
              $help {MONTH}.
              $help {DAY}.
              $help {HOUR}.
              $help {MINUTE}.
              $help {SECOND};

   return $new_date; 

}

#######################################################################
## all doFunctions need hashes (accossiative arrays as arguments!!!) ##
##      call function (\%attr) not function (\{test=>$value})        ##
## because so I cannot return any value                              ##
#######################################################################

## please use for all doXyz queries only one $errors-variable and 
## one $status-variable. the variables store information about the
## number of used connections and the errors

## before the first call please initialize 
## $status = 0;
## $errors = 0;

## this function manages the database connections. it manages via 
## the status-variable the errorrecovery too. so please
## use for all of your doConnect-calls during one operation only
## one status-variable
sub doConnect {
  my $self = shift;
  my $keys = $_[0]; # this is a accossiative array (hash)

  my ($dsn, $user, $passwd);
  my $adder;

  # these variables are inout-vars !!! 
  # so only use them for read operations not for write !!!
  my $status = $keys->{STATUS};
  # my $dbh    = $keys{DBH};    # database handle

  print "### new function call ###<br>\n" if ($self->{DEBUG});
  print "Entering sub doConnect<br>\n" if ($self->{DEBUG});
  print "  status: ".$status."<br>\n" if ($self->{DEBUG});
  print "  errors: ".$self->{ERRNO}."<br>\n" if ($self->{DEBUG});

  ## status can have the following values
  ## 0 initial call
  ## 1 first  connect failed
  ## 2 second connect failed
  ## => failed so $status+1

  ## check what's requested
  if ($status >= 2) {
    ## second connect failed
    print "  second connect failed<br>\n" if ($self->{DEBUG});
    return undef;
  } elsif (($status == 1) and ($self->{backupDB} ne "")) {
    ## using backup because first connect failed
    print "  first connect failed so using backup<br>\n" if ($self->{DEBUG});
    $dsn          = $self->{backupDB};
    $user         = $self->{backupUser};
    $passwd       = $self->{backupPasswd};
    $keys->{TYPE} = $self->{backupType};
  } else {
    ## no failure so use standardDB
    print "  connect never failed so using standard<br>\n" if ($self->{DEBUG});
    $dsn          = $self->{standardDB};
    $user         = $self->{standardUser};
    $passwd       = $self->{standardPasswd};
    $keys->{TYPE} = $self->{standardType};
  }

  print "  Databasetype:".$keys->{TYPE}."<br>\n" if ($self->{DEBUG});

  ## dsn etc. defined so lets try
  print "  try to connect<br>\n" if ($self->{DEBUG});
  $keys->{DBH} = DBI->connect ($dsn, $user, $passwd, 
                               \%{$OpenCA::DBI::DB->{$keys->{TYPE}}->{DBI_OPTION}});
  if ($keys->{DBH}->state != 0) {
    ## connect failed try again
    print "  connect failed<br>\n" if ($self->{DEBUG});
    $keys->{STATUS} ++;
    if ($status >= 2) {
      ## second failure
      $self->errno ( $OpenCA::DBI::ERROR->{SECOND_CONNECT_FAILED} );
      return undef;
    } else {
      ## first failure so retry
      $self->errno ( $OpenCA::DBI::ERROR->{CONNECT_FAILED} );
      return $self->doConnect (\%{$keys});
    }
  } else {
    ## all ok 
    print "  function succeeded<br>\n" if ($self->{DEBUG});
    print "### leaving function doConnect successfully ###<br>\n" if ($self->{DEBUG});
    return 1;
  }
}

## here I handle the hole query inclusive all
## errordetection etc.
sub doQuery {
  my $self = shift;
  my $keys = $_[0];

  # these variables are inout-vars !!!
  # so only use them for read operations not for write !!!
  my $status = $keys->{STATUS};
  # my $dbh    = $keys->{DBH};    # database handle
  # my $sth    = $keys->{STH};    # statement handle

  # these variables are in-vars
  my $query     = $keys->{QUERY};
  my @bind_vals = @{$keys->{BIND_VALUES}};

  print "### new function call ###<br>\n" if ($self->{DEBUG});
  print "  Entering sub doQuery<br>\n" if ($self->{DEBUG});
  print "  query: ".$query."<br>\n" if ($self->{DEBUG});
  foreach my $help (@bind_vals) {
    print "  bind_values: ".$help."<br>\n" if ($self->{DEBUG});
  }

  # check for second failure
  if ($status >= 2) {
    print "  earlier database failure detected<br>\n" if ($self->{DEBUG});
    return undef;
  }

  ## query empty so not a DB-failure
  return undef if ($query eq "");

  ## prepare
  print "  prepare statement<br>\n" if ($self->{DEBUG});
  print "  statement nr.: ".(scalar (@{$keys->{STH}}) +1)."<br>\n" if ($self->{DEBUG});
  $keys->{STH}[scalar (@{$keys->{STH}})] = $keys->{DBH}->prepare ($query);
  if ( (my $h = $keys->{STH}[scalar (@{$keys->{STH}}) -1]->state) != 0) {
    print "  prepare failed<br>\n" if ($self->{DEBUG});
    print "  query: ".$query."<br>\n" if ($self->{DEBUG});
    print "  returned errorcode: ".$h."<br>\n" if ($self->{DEBUG});
    $keys->{STATUS} ++;
    $self->errno ( $OpenCA::DBI::ERROR->{PREPARE_FAILED} );
    return undef;
  }

  ## execute
  print "      execute statement<br>\n" if ($self->{DEBUG});
  $keys->{STH}[scalar (@{$keys->{STH}}) -1]->execute (@bind_vals);
  if (not $keys->{STH}[scalar (@{$keys->{STH}}) -1]->state) {
    print "  execute succeeded<br>\n" if ($self->{DEBUG});
    print "### leaving function doQuery successfully ###<br>\n" if ($self->{DEBUG});
    return 1;
  } else {
    print "  execute failed<br>\n" if ($self->{DEBUG});
    print "### leaving function doQuery unsuccessfully ###<br>\n" if ($self->{DEBUG});
    $keys->{STATUS} ++;
    $self->errno ( $OpenCA::DBI::ERROR->{EXECUTE_FAILED} );
    return undef;
  }
}

## rollback never touch the status because 
## rollback is normally the action if a
## statement fails
sub doRollback {
  my $self = shift;
  my $keys = $_[0];

  # these variables are inout-vars !!!
  # so only use them for read operations not for write !!!
  #my $dbh    = $keys->{DBH};    # database handle

  if ($keys->{DBH}->rollback) {
    return 1;
  } else {
    $self->errno ( $OpenCA::DBI::ERROR->{ROLLBACK_FAILED} );
    return undef;
  }
}

## commit sets the status-variable
sub doCommit {
  my $self = shift;
  my $keys = $_[0];

  # these variables are inout-vars !!!
  # so only use them for read operations not for write !!!
  my $status = $keys->{STATUS};
  # my $dbh    = $keys->{DBH};    # database handle

  # check for second failure
  if ($status >= 2) {
    print "      earlier database failure detected\n" if ($self->{DEBUG});
    return undef;
  }
  
  if ($keys->{DBH}->commit ) {
    return 1;
  } else {
    $keys->{STATUS} ++;
    $self->errno ( $OpenCA::DBI::ERROR->{COMMIT_FAILED} );
    return undef;
  }
}

## doDisconnect don't set the status-variable because commit
## and rollback called before disconnect so success is not important
sub doDisconnect {
  
  my $self = shift;
  my $keys = $_[0];

  # these variables are inout-vars !!!
  # so only use them for read operations not for write !!!
  #my $dbh    = $keys->{DBH};    # database handle

  if ($keys->{DBH}->disconnect ) {
    return 1;
  } else {
    $self->errno ( $OpenCA::DBI::ERROR->{DISCONNECT_FAILED} );
    return undef;
  }
}

## this function is neccessary because DB2 doesn't support
## the function fetchrow_hashref
sub getResultHash {

  my $self = shift;
  my $keys = { @_ };
  my %result;

  print "### new function call ###<br>\n".
        "  Entering function getResultHash<br>\n" if ($self->{DEBUG});

  for (my $i = 0;
       $i < scalar (@{$OpenCA::DBI::SQL->{TABLE_STRUCTURE}->{$keys->{TABLE}}});
       $i++) {
    $result {$OpenCA::DBI::SQL->{TABLE_STRUCTURE}->{$keys->{TABLE}}[$i]} =
      $keys->{ARRAY}->[$i];
    print "  column:".$OpenCA::DBI::SQL->{TABLE_STRUCTURE}->{$keys->{TABLE}}[$i]."<br>\n".
          "  value:".$keys->{ARRAY}->[$i]."<br>\n" if ($self->{DEBUG});
  }

  print "### leaving function getResultHash ###<br>\n" if ($self->{DEBUG});

  return %result;
  
}

############################
## begin of errorhandling ##
############################

sub errno {
  my $self = shift;

  if ( defined $_[0] ) {
    ## set errorcode
    if ( ($_[0] > 20000) and ($_[0] < 40000) ) {
      ## add error via bitops
      if ( ($self->{ERRNO} > 20000) and ($self->{ERRNO} < 40000) ) {
        ## bitwise
        $self->{ERRNO} |= $_[0];
      } else {
        ## new
        $self->{ERRNO} = $_[0];
      }
    } else {
      ## set new error
      $self->{ERRNO} = $_[0];
    }
    ## this helps us handling crashes during new ()
    $OpenCA::DBI::ERRNO = $self->{ERRNO};
  }

  if ( defined $self->{ERRNO} ) {
    return $self->{ERRNO};
  } else {
    return $OpenCA::DBI::ERRNO;
  }
}

sub errval {
  my $self = shift;
  my $text = "";
  my $code;

  if ( defined $self->{ERRNO} ) {
    $code = $self->{ERRNO};
  } else {
    $code = $OpenCA::DBI::ERRNO;
  }
  
  if ( ($code > 20000) and ($code < 40000) ) {
    ## bitwise
    my $help = 8192;
    my $tmp = $code - 20000;
    while ($help) {
      if ($help <= $tmp) {
        $text .= " ".$OpenCA::DBI::MESSAGE->{$help};
        $tmp -= $help;
      }
      $help /= 2;
    }
  } else {
    ## simple error
    $text = $OpenCA::DBI::MESSAGE->{$code};
  }

  return $text;
}

##########################
## end of errorhandling ##
##########################

#################################
## these functions do not work ##
#################################

sub der2txt {
  ## \0   => 00
  ## x => 1x
  my $ret ="";
  for (my $i=0;$i < length ($_[0]); $i++) {
    if (substr ($_[0], $i, 1) == '\0') {
      $ret .= "00";
    } else {
      $ret .= "1".substr ($_[0], $i, 1);
    }
  }
  return $ret;
}

sub txt2der {
  ## 00 => \0
  ## 1x => x
  my $ret ="";
  for (my $i=0;$i < int (length ($_[0]) / 2); $i++) {
    if (substr ($_[0], $i*2, 1) == "0") {
      $ret .= '\0';
    } else {
      $ret .= substr ($_[0], $i*2 +1, 1);
    }
  }
  return $ret;
}

##########################
## end of new functions ##
##########################

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

OpenCA::DBI - Perl Certificates DBI Extension.

=head1 SYNOPSIS

use OpenCA::DBI;

=head1 DESCRIPTION

This module makes available a lot of low level database functionality to 
the OpenCA-scripts. The interface is like the OpenCA::DB-module's interface.

Nevertheless the configuration is completely different because this
module tries to support several databases and not only one. The
documentation is devided into 

=over

=item * 
dependencies

=item * 
configuration - new ()

=item * 
public functions

=item * 
private functions

=back

The modules name comes from the DBI module which is used for the
databaseconnectivity.

=head2 DEPENDENCIES

the module use the following other modules

=over

=item *
OpenCA::REQ

=item *
OpenCA::X509

=item *
OpenCA::CRL

=item *
OpenCA::CRR

=item *
OpenCA::OpenSSL

=item *
OpenCA::Tools

=item *
DBI

=item *
OpenCA::DBIS (actually not but in some weeks) 

=back

=head2 USAGE

$new_object = new OpenCA::DBI (option1 => $value1, ...);

=head2 All names are case sensitive !!!

=head2 CONFIGURATION - new ()

This is perhaps the most complicated part for the users of this
module.

You configure and init a new object of the class OpenCA::DBI by
calling the function new. The usage is:

The often used remote and local means  remote database and local 
database.

Actually OpenCA does not have a sync-module so the use of a local
database insteed of the central remote database makes absolut no sense.
The code for the documented options is written but deactivated by 
enforcing special settings of the options.

=over 4

=item
SHELL => $object

object of class OpenCA::OpenSSL

=item
mode => mode_name

the following modes are available

 mode         |  db 
 ----------------------
 secure       |  remote
 standard     |  local

"secure" is enforced because the synchronization doing module of
OpenCA is not implemented. Attention, the code is implemented for
this feature so if you take the code and remove the line

      $self->{mode}          = "secure";

then the described mechanism works.

=item
failsafe => (on|off)

if failsafe is on and an action fails a failover is encouraged
by using the other database. 

Actually failsafe is always set to "off". (Code is written and works
so you can activate this feature but this is senseless because the 
Sync-module is not implemented yet.)

=item
second_chance => (yes|no)

If no backup is set due to the settings of failsafe a "yes"
enforce a second try on the standarddatabase.

Actually "no" is enforced but manually you can made this option 
working. The enforced "no" is only there for easier testing.

=item
logsecurity => integer_value

The default setting is 0. You can set integer values higher than -1 
(so >=0).

=item
logperformance => integer_value

The default setting is 8. You can set integer values higher than 7 
(so >=8).

So this is the time to write something about the signing code.

The log signing algorithm creates a signature from the following logrecords:

=over 8

=item 

-> actual (serial of the actual logrecord)

=item 

-> actual - 2**0

=item

-> actual - 2**1

=item

-> ...

=item

-> actual - 2**k (last value with result >= 0)

=back

=over 8

=item 

1. Now the records 0..(logperformance-1) are ignored.

=item 

2. The records logperformance..t are removed until k-t equals
logsecurity. If logsecurity equals 0 then the second operation is not
performed and all records are signed.

=back

=item

logperformance is an option which protects us against the possibilities
of systems which has a high system load factor. logsecurity defines the 
used references.

=item
remoteType => Pg

DBI type of the database

=item
remoteName => database_name

be warned this string is a must for every databasesystem! Several 
databases does not need the setting of host or port because the 
information is stored in an interfaces-file like on Sybase. So the
"database_name" is the string needed by the databasedrivers of the 
different vendors. For more information please look at the
documentation of the DBD::vendor_name drivers (e.g. Informix,
Interbase, mSQL, MySQL, Oracle, Pg, Sybase)

=item
remoteHost => hostname

host where the database is located - so remote has only a logical 
meaning. Actually until you use no VPN-software it is strongly 
recommended that the database is on your local machine. The use 
of DNS is not necessary and not recommended because the use of pure
IP protects you against DNS spoofing. Alternatively you can insert 
the used hostname in your /etc/hosts

=item
remotePort       => port_number

=item
remoteUser       => user

=item
remotePasswd => passwd

=item
localType       => Pg

=item
localName       => database_name

=item
localHost       => hostname

=item
localPort       => port_number

=item
localUser       => user

=item
localPasswd => passwd

=item
CERT_FILE => cert.pem

This is for logging only. The cert is used for signing.

=item
KEY_FILE => priv.key

This is for logging only. The key is used for signing.

=item
PASSWD => passwd

This is for logging only. The passphrase is used for signing.

=item
DEBUG => true_value

If you enter nothing then there is nothing. If you enter a value which perl
interprets as true then debugging is on.

=back

(The values of mode, failsafe and second_chance are not case sensitive.)

=head2 PUBLIC FUNCTIONS

The supported public functions are:

=over

=item * 
new - see CONFIGURATION -new ()

Please see the description of the configuration of OpenCA::DBI which describe
the "new" function.

=item * 
initDB

This function initializes the databases. It knows the following options:

=over 4

=item
DB => @databases

You can pass an array which can include "remote", "local" or "remote" and 
"local". If nothing is included then the value is set to "remote". The 
databases will then initialized.

This means the function tries to do all the sql-create commands which are
needed for operation of the OpenCA::DBI module.

These tables are:

	request
        ca_certificate
	certificate
	crr
	crl
	log
	signature

=item
MODE => (NONE|FORCE|FORCE_LOCAL|FORCE_REMOTE|FORCE_ALL)

=back

=item

If successful then the function returns a 1. If not successfull then undef is 
returned. Please read this section carefully because I perhaps switch to
returnvalue 1 for success. Comments are welcome.

=item * 
storeItem

=over 4

=item
DATATYPE => (old_type|basic_type)

The old_types which are accepted are the same like in the OpenCA::DB module.
These are strings like PENDING_REQUEST or REVOKED_CERTIFICATE.

The basic_type means you can enter normal basic types like:

	REQUEST
	CA_CERTIFICATE
	CERTIFICATE
	CRR
	CRL

If you use basic types and you not set the option "status" status is setting
to "VALID". If you use old_types then the status will be extracted from the
string via the private function getStatus.

=item
STATUS => (VALID|RENEWED|UPDATED|PENDING|APPROVED|
           SUSPENDED|REVOKED|DELETED|ARCHIVED|EXPIRED|)

The status can be any of the above terms. If status is not seeded I use first
the DATATYPE if it is an old_type and if not not then the status is "VALID".

=item
INFORM => (PEM|DER|SPKAC|)

This option is actually a little bit unclear because I get the data via objects
so I don't need the format because I get the data directly from the object.
If the format is not detectable I use PEM.

RE<eacute>sumE<eacute>: this is waste!

=item
OBJECT => $openca_object

This is an OpenCA object which has to be stored. This could be
	OpenCA::REQ
        OpenCA::X509
        OpenCA::CRR
	OpenCA::CRL

=item
MODULETYPE => (CA|PKIManager|RA|WebGateway|)

This for logging only. If you set it you can read the log in the database and 
can verify via OpenCA::DBI::MODULETYPE->{number_from_db} the moduletype which
has done this action.

=item
MODULE => module_name

This is for logging only. If you set it you can read the log in the database 
and can verify which module has done this action (it is stored as ascii so
it is humanreadable - means you can read it as databaseadmin).

=back

=item

Last a small comment to the code which do the signing. Because this code is
a highlevel feature I will move this in the future to the OpenCA::DBIS module
so not be shocked if you are looking into the code and don't find the code.
If the code moved you will find a notice about the version were the move starts
here.

Version: not moved yet.

=item * 
getItem

=over 4

=item
DATATYPE => (old_type|basic_type)

The old_types which are accepted are the same like in the OpenCA::DB module.
These are strings like PENDING_REQUEST or REVOKED_CERTIFICATE.

The basic_type means you can enter normal basic types like:

	REQUEST
	CERTIFICATE
	CRR
	CRL

If you use basic types and you not set the option "status" status is setting
to "VALID". If you use old_types then the status will be extracted from the
string via the private function getStatus.

=item
STATUS => (VALID|RENEWED|UPDATED|PENDING|APPROVED|
           SUSPENDED|REVOKED|DELETED|ARCHIVED|EXPIRED|)

The status can be any of the above terms. If status is not seeded I use first
the DATATYPE if it is an old_type and if not then the status is ignored.

=item
KEY => key

This is the key (the unique identifier) of this special requested object.
So this can be a serial number or a md5 etc..

If KEY is not given then I return the last element. This feature is useful
for CRLs and only actually allowed for CRLs!!! If you search the latest one 
you have only to call:

$openca_dbi->getItem (DATATYPE => "CRL");

I think this is a good feature.

If you need this feature for other objects you must uncomment the following
line in getItem:

return if ((not $serial) && ($table ne "CRL"));

=item
MODE => (RAW|)

RAW causes the return of the plain text of stored data. Nothing causes the
return of an object.

=back

=item * 
getNextItem

The same options like getItem except MODE which is not supported. An object
will be returned at every time. The function determines only the next key
itself and then passes the request to the function getItem. The option KEY
is required.

=item * 
getPrevItem

The same options like getItem except MODE which is not supported. An object
will be returned at every time. The function determines only the next key
itself and then passes the request to the function getItem. The option KEY
is required.

=item * 
destroyItem

=over 4

=item
DATATYPE => (old_style|basic_type)

=item
KEY => key

=back

=item

destroyItem really delete the request from the database. Attention this function
is reserved for a fututre recovery algorithm! therefore the operation will not
be logged!

So please "hands off" if you not very shure what you are doing!!!

Use deleteItem (which do nothing ;-)) or better (best)

B<storeItem (DATATYPE=> xyz, MODE=>"UPDATE", STATUS=>"DELETED", OBJECT=>xyz);>

=item * 
deleteItem

This is a dummy to be proof against old codeparts which think they must remove
the object from VALID_CERTIFICATE after they store the certificate to
REVOKED_CERTIFICATE.

=item * 
elements

=over 4

=item
DATATYPE => (old_type|basic_type)

The old_types which are accepted are the same like in the OpenCA::DB module.
These are strings like PENDING_REQUEST or REVOKED_CERTIFICATE.

The basic_type means you can enter normal basic types like:

	REQUEST
	CERTIFICATE
	CRR
	CRL

If you use basic types and you not set the option "status" the function returns
the number of all elements of this table.

=item
STATUS => (VALID|RENEWED|UPDATED|PENDING|APPROVED|
           SUSPENDED|REVOKED|DELETED|ARCHIVED|EXPIRED|)

If not used the scan performs on the hole table.

=back

=item

This function counts the elements which are in the same table and have the same 
status (if status is set via STATUS or DATATYPE).

=item * 
searchItem

The options are the well known options DATATYPE, MODE and STATUS (please see 
above).

The new options are all possible searchattributes. To get them please use the
new function getAttributes! The old functions support some types not. The 
function getAttribute don't return the unique identifiers, but you can get the
unique identifiers of the tables via 
OpenCA::DBI::SQL->{VARIABLE}->{tablename."_SERIAL"}[0] 
(Attention - the tablename is stored in big letters!)

=item * 
getTimeString

This function returns an ISO-timestring (2001-01-14 18:24:06).

=back

Unchanged public functions (from OpenCA::DB v0.8.7a):

=over 4

=item * 
rows

Same options like searchItem. The function calls searchItem and count the 
returned objects. Simple but errorproof

=back

Working but unclear status (private or public???)
(directly taken from OpenCA::DB v0.8.7a)

=over 4

=item * 
listItem

This function is directly taken over from OpenCA::DB v0.8.7a. Because I don't
know for what it is used I don't change and use it.

=back

The following unsupported functions are not supported because they perform
operations which are not necessary or possible for RDBMSs (Relational
DataBase Management Systems). These systems take care by themselves on
things like number of elements, locks, next and preview operators etc..

Unsupported functions (empty dummies):

=over 4

=item * 
getIndex

=item * 
saveIndex

=item * 
getReferences

I don't know what this function does.

=back

If someone can emulate the unsupported functions or can determine
the state of listItem please contact me (Michael Bell <michael.bell@web.de>.

=head2 PRIVATE FUNCTIONS

The new private functions are:

=over 4

=item *
storeItem_getArguments

is called from storeItem and returns a hash with all needed variables

=item *
storeItem_checkData

checks the data which will be transmitted to storeItem

=item *
storeItem_update

performs the update-operations

=item *
storeItem_insert

performs the insert operations

=item *
storeItem_logging

build the data for the log and store the data into database

=item *
storeItem_signing

if logsignng is activated then this function performs the signing
and store the signatur einto the database

=item * 
getTable

It extract from a datatype (old or new) the tableand return it.

=item * 
getStatus

It extracts from STATUS and DATATYPE the status. If STATUS is present 
DATATYPE will be ignored.

=item * 
getSequence

This function has the job to return a new ACTION_NUMBER for the table log.
This is done by a function to keep the vendordependent code away from the not
vendordependent code. Sequences, sequence generators etc. are not 
standardized. The option is a db_hash_write called hash. Pleae see B<doConnect>
for a detailed description of this code.

=item * 
doConnect,
doQuery,
doRollback,
doCommit,
doDisconnect

All of these function get an hash as option. The hash is structured like 
follows:

 my %db_hash = (STATUS => 0,
                DBH    => 0,
                STH    => [],
                QUERY  => "",
                BIND_VALUES => [],
               );

B<STATUS> is the errorstate of the connection. Please never 
touch this value it is absolut internal and highly critical.

B<ERRORS> include all errors which are happened during the use of this hash.
All errors are available via
$openca_dbi_object::ERROR->{error_name}. 

B<DBH> is the actual used databasehandle from DBI->connect.

B<STH> is an array with all statementhandles of the actual DBH. The handle
for the last doQuery is available via $hash{STH}[scalar (@{$hash{STH}}) -1].
Actually I don't use other than the last result of a statement but somewhere
in the future ...

B<QUERY> this is the actual query which you have only to set for doQuery.

B<BIND_VALUES> this is the actual array of binded values which you have only 
to set for doQuery.

=back

=over 4

=item * 
getBaseType

=item * 
listItems           (not used but perhaps not private!!!)

=item * 
byKey               (not used)

=item * 
getSearchAttributes

The only argument is the tablename via getiSearchAttributes ("REQUEST");
The returned value is an array with the available attributes.

=item * 
hash2txt

=item * 
txt2hash (not used)

=back

=head1 SUPPORTED DATABASES

Every subscribed item has the same behaviour for remoteXYZ and localXYZ.

=head2 PostgreSQL

 option           |  default  |  required
 ----------------------------------------
 remoteType       |    Pg     |    yes
 remoteName       |    -      |    yes
 remoteHost       | localhost |    no
 remotePort       |   5432    |    no
 remoteUser       |    -      |    yes
 remotePasswd     |    -      |    yes

If you would not set the remoteUser then DBD::Pg would use the username of the
processowner. Because this is special for the Pg-driver this feature is not
supported or used by the OpenCA::DBI-module and cause an undef return value for
the new () call.

Be shure that YOU set a password!

You can test this with nessus (http://www.nessus.org).

This was and is the most common error of us (some
anonymous people of the staff of the datacenter of
the Humboldt-University of Berlin ;-D).

=head2 MySQL

Attention the name which you must enter is mysql!!!

 option           |  default  |  required
 ----------------------------------------
 remoteType       |   mysql   |    yes
 remoteName       |    -      |    yes
 remoteHost       | localhost |    no
 remotePort       |    ?      |    no
 remoteUser       |    -      |    yes
 remotePasswd     |    -      |    yes

Because I have not the time to test MySQL please write any mistake in this
documentation suddenly to me. I don't know the standard MySQL-Port so I
hope the DBD::mysql module knows it ;-)

Please don't use MySQL in a realworld-PKI. This database
is deprecated because it doesn't support the ACID-features
actually and I have no chance to grant the integrity
of your PKI-DB.

 A tomicity
 C onsistency
 I solation
 D urability

=head2 DB2

 option           |  default  |  required
 ----------------------------------------
 remoteType       |    DB2    |    yes
 remoteName       |    -      |    yes
 remoteHost       |    -      |    no
 remotePort       |    -      |    no
 remoteUser       |    -      |    yes
 remotePasswd     |    -      |    yes

If you get the error "The total environment is not set ..."
Please read the CAVEATS-file like recommended by
IBM. If this not help then you must do the following:

$HOME is the home of the db2-instance

cp $HOME/sqllib/db2profile $HOME_OF_HTTPD_USER/

vi /etc/init.d/apache (or where ever your apache-
startupscript is placed)
> . $HOME_OF_HTTPD_USER/db2profile

vi /etc/httpd/httpd.conf
go to the position of your virtual host or 
otherwise enter it in the right global context
>PassEnv LD_LIBRARY_PATH
>PassEnv PATH
>PassEnv LIBPATH
>PassEnv CLASSPATH
>PassEnv DB2INSTANCE
>PassEnv DB2DIR
>PassEnv INSTHOME

Perhaps you don't need some of the environmentvariables
but my installation works with this environment and
this should only be a point where you can start.

=head2 Oracle

 option           |  default  |  required
 ----------------------------------------
 remoteType       |  Oracle   |    yes
 remoteName       |    -      |    yes
 remoteHost       |    -      |    no
 remotePort       |    -      |    no
 remoteUser       |    -      |    yes
 remotePasswd     |    -      |    yes

Warning, this port is completely untested. It was only added because
of a user request but I get never a feedback.

=head1 LICENSE

This library is free for commercial and non-commercial use as long as
the following conditions are aheared to.  The following conditions
apply to all code found in this distribution, be it the RC4, RSA,
lhash, DES, etc., code; not just the SSL code.  The documentation
included with this distribution is covered by the same copyright terms

Copyright remains Massimiliano Pala's and Michael Bell's, and as such any
Copyright notices in the code are not to be removed.
If this package is used in a product, Massimiliano Pala and Michael Bell
should be given attribution as the author of the parts of the library used.
This can be in the form of a textual message at program startup or
in documentation (online or textual) provided with the package.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. All advertising materials mentioning features or use of this software
   must display the following acknowledgement:
   "This product includes OpenCA software written by Massimiliano Pala
    (madwolf@openca.org) and the OpenCA Group (www.openca.org)"
4. If you include any Windows specific code (or a derivative thereof) from 
   some directory (application code) you must include an acknowledgement:
   "This product includes OpenCA software (www.openca.org)"

THIS SOFTWARE IS PROVIDED BY OPENCA DEVELOPERS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.

The licence and distribution terms for any publically available version or
derivative of this code cannot be changed.  i.e. this code cannot simply be
copied and put under another distribution licence
[including the GNU Public Licence.]

=head1 AUTHORS

 Massimiliano Pala <madwolf@openca.org> (OpenCA::DB)
 Michael Bell <michael.bell@web.de> (OpenCA::DBI)

=head1 SEE ALSO

OpenCA::OpenSSL, OpenCA::X509, OpenCA::CRL, OpenCA::REQ,
OpenCA::TRIStateCGI, OpenCA::Configuration, OpenCA::Tools,
OpenCA::DBIS, OpenCA::OpenSSL::Configuration

=head1 P.S. EXAMPLE

	Block: {
	doConnect
	  if doConnect returns negative then last BLOCK 
	  (final error, all options failsafe or 
	  second_chance did not help.)
	  best thing is now to say return -1; insteed of
      	  last BLOCK;
	doQuery until the first returncode is -1
        then doRollback
             doDisconnect
	if never doQery fails 
	then doCommit
	if returnvalue is -1
	then doRollback
     	     doDisconnect
	else doDisconnect

	if somethig fails except doConnect "next BLOCK"
	}

you can repeat this block so often as you want until the first time
doConnect returns undef. So long this not happens you can try to get a 
successful transaction.

=cut

