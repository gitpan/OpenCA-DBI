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

## special thanks
##
## MySQL:	Julio Sánchez Fernández <jsanchez@users.sf.net>
## Oracle:	balamood@vt.edu (if somebody knows the fullname I add it
##
## please write a note to us if one of the addresses is wrong

use strict;

package OpenCA::DBI;

our ($errno, $errval);

## We must store/retrieve CRLs,CERTs,REQs objects:
## proper instances of object management classes are
## needed.
## see http://www.informatik.hu-berlin.de/~mbell/OpenCA/OpenCA_DBI/OpenCA_DBI.html
## for more information about the datastructure

use OpenCA::REQ;
use OpenCA::X509;
use OpenCA::CRL;
use OpenCA::OpenSSL;
use OpenCA::Tools;
use DBI;

## the other use directions depends from the used databases

## $Revision: 1.95 $

# code contributed by Andreas Fitzner
($OpenCA::DBI::VERSION = '$Revision: 1.95 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg; 

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
                              },
                     ## I use here several duplicate array
                     ## somewhere I have to stop the complexity ...
                     VARIABLE => {
                                  DATE                  => ["submit_date",          "TEXT"],
                                  SUBMIT_DATE           => ["submit_date",          "TEXT"],
                                  FORMAT                => ["format",        "TEXT"],
                                  DATA                  => ["data",          "LONGTEXT"],

                                  SERIAL                => ["serial",        "BIGINT"],
                                  KEY                   => ["mykey",         "TEXT_KEY"],

                                  CERTIFICATE_SERIAL    => ["cert_key",      "BIGINT"],
                                  # same like certificate_serial but for CRR
                                  REVOKE_CERTIFICATE_SERIAL    => ["cert_key",      "BIGINT"],
                                  CA_CERTIFICATE_SERIAL => ["ca_cert_key",   "TEXT_KEY"],
                                  REQUEST_SERIAL        => ["req_key",       "BIGINT"],
                                  CSR_SERIAL            => ["req_key",       "BIGINT"],
                                  CRR_SERIAL            => ["crr_key",       "BIGINT"],
                                  CRL_SERIAL            => ["crl_key",       "TEXT_KEY"],

                                  LOG_SERIAL            => ["action_number", "BIGINT"],
                                  SIGNATURE_SERIAL      => ["action_number", "BIGINT"],
                                  # end of redefined variables
                                  
                                  # for searching
                                  DN                    => ["dn",            "TEXT"],
                                  # same like dn but for CRRs
                                  REVOKE_CERTIFICATE_DN => ["dn",            "TEXT"],
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
                                  PUBKEY                => ["public_key",    "TEXT"],
                                  NOTAFTER              => ["notafter",      "BIGINT"],
                                  SCEP_TID              => ["scep_tid",      "TEXT"],
                                  LOA                   => ["loa",           "TEXT"],
                                  
                                  # logging and integrity support
                                  DATATYPE              => ["datatype",      "TEXT"],
                                  STATUS                => ["status",        "TEXT"],
                                  REASON                => ["reason",        "TEXT"],
                                  ACTION_NUMBER         => ["action_number", "BIGINT"],
                                  MODULETYPE            => ["moduletype",    "TEXT"],
                                  MODULE                => ["module",        "TEXT"],
                                  LOG_SUBMIT_DATE       => ["log_submit_date",   "TEXT"],
                                  LOG_DO_DATE           => ["log_do_date",   "TEXT"],
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
               "DN",
               "CN",
               "EMAIL",
               "RA",
               "Operator",
               "STATUS",
               "ROLE",
               ## should be part of the header itself
               ## "HEADER_SIGNATURE",
               "PUBKEY",
               "SCEP_TID",
               "LOA"
              ],
   CERTIFICATE => [
                   "CERTIFICATE_SERIAL",
                   "FORMAT",
                   "DATA",
                   "DN",
                   "CN",
                   "EMAIL",
                   "STATUS",
                   "ROLE",
                   ## why a signature should be searchable?
                   ## "ROLE_SIGNATURE",
                   ## should be part of the header itself
                   ## "HEADER_SIGNATURE",
                   "PUBKEY",
                   "NOTAFTER",
                   "CSR_SERIAL",
                   "LOA"
                  ],
   CA_CERTIFICATE => [
                      ## real serial senseless because at every time zero
                      "CA_CERTIFICATE_SERIAL",
                      "FORMAT",
                      "DATA",
                      "DN",
                      "CN",
                      "EMAIL",
                      "STATUS",
                      "PUBKEY",
                      "NOTAFTER"
                     ],
   CRR => [
           "CRR_SERIAL",
           "REVOKE_CERTIFICATE_SERIAL",
           "SUBMIT_DATE",
           "FORMAT",
           "DATA",
           "REVOKE_CERTIFICATE_DN",
           "CN",
           "EMAIL",
           "RA",
           "Operator",
           "STATUS",
           "REASON",
           "LOA",
           ## should be part of the header itself
           ## "HEADER_SIGNATURE"
          ],
   CRL => [
           "CRL_SERIAL",
           "STATUS",
           "FORMAT",
           "DATA",
           "LAST_UPDATE",
           "NEXT_UPDATE",
          ],
  };

$OpenCA::DBI::STATUS = {
			EXIST       => 1,
			VALID       => 2,
			RENEW       => 3,
			UPDATED     => 4,
			PENDING     => 5,
			APPROVED    => 6,
			SUSPENDED   => 7,
			REVOKED     => 8,
			DELETED     => 9,
			ARCHIVED    => 10,
			EXPIRED     => 11,
                        NONEXISTENT => 12,
                        ANY         => 13,
                        NEW         => 14,
                        SIGNED      => 15
		       };

#########################
## end of DB Org-stuff ##
#########################

#################
## error-codes ##
#################

$OpenCA::DBI::ERROR = {
  
  SUCCESS            => 0,
  DO_NOT_COMMIT      => 11111, # protects the database from commiting if the modul crashs
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
  AUTOCOMMIT                   => 10019,

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
  ILLEGAL_ARGUMENT             => 10068,

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
  10019 => "AUTOCOMMMIT is on.",
  
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
  10068 => "There is an illegal or unsupported argument.",

  11111 => "Do not commit if the database or the module itself fails.",
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
                    Pg => {
                           TYPE => {
                                    ## numeric available but not documented
                                    TEXT       => "text",
                                    LONGTEXT   => "text",
                                    TEXT_KEY   => "text",
                                    BIGINT     => "int8",
                                    PRIMARYKEY => "PRIMARY KEY NOT NULL",
                                   },
                           DBI_OPTION => {
                                          RaiseError => 0, 
                                          Taint => 0, 
                                          AutoCommit => 0},
                           LIMIT => "__QUERY__ LIMIT __MAXITEMS__"
                          },
                    mysql => {
                              TYPE => {
                                       ## numeric available but not documented
                                       TEXT       => "TEXT",
                                       LONGTEXT   => "TEXT",
                                       TEXT_KEY   => "VARCHAR (255)",
                                       BIGINT     => "BIGINT",
                                       PRIMARYKEY => "NOT NULL PRIMARY KEY",
                                      },
                              DBI_OPTION => {RaiseError => 0,
                                             AutoCommit => 0},
                              CREATE_TABLE_OPTION => "TYPE=BDB",
                              LIMIT => "__QUERY__ LIMIT __MAXITEMS__"
                             },
                    DB2 => {
                            TYPE => {
                                     TEXT       => "long varchar",
                                     LONGTEXT   => "long varchar",
                                     ## 255 is the limit for a index key in db2
                                     TEXT_KEY   => "varchar (255)",
                                     BIGINT     => "decimal (31, 0)",
                                     PRIMARYKEY => "PRIMARY KEY NOT NULL",
                                    },
                            DBI_OPTION => {
                                           RaiseError => 0, 
                                           Taint => 0, 
                                           AutoCommit => 0},
                            LIMIT => "__QUERY__ FETCH FIRST __MAXITEMS__ ROWS ONLY"
                           },
                    Oracle => {
                            TYPE => {
                                     TEXT       => "varchar2 (1999)",
                                     LONGTEXT   => "LONG",
                                     ## 2000 is the limit for varchar in Oracle7
                                     TEXT_KEY   => "varchar2 (1999)",
                                     BIGINT     => "number (38)",
                                     PRIMARYKEY => "PRIMARY KEY NOT NULL",
                                    },
                            DBI_OPTION => {
                                           RaiseError => 0, 
                                           Taint => 0, 
                                           AutoCommit => 0,
                                           LongReadLen => 32767},
                            LIMIT => "select * from ( __QUERY__ ) where rownum <= __MAXITEMS__"
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
	      backend => undef,
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

  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

  # non-DB-specific

  $self->{DEBUG}          = 1 if ($keys->{DEBUG});

  $self->{backend}        = $keys->{SHELL};

  print "  defining the class parameters<br>\n" if ($self->{DEBUG});

  # The minimum I need is remote: 
  # type, host, port, name, user, passwd

  $self->{DB_Type}   = $keys->{DB_Type};
  $self->{DB_Host}   = $keys->{DB_Host};
  $self->{DB_Port}   = $keys->{DB_Port};
  $self->{DB_Name}   = $keys->{DB_Name};
  $self->{DB_User}   = $keys->{DB_User};
  $self->{DB_Passwd} = $keys->{DB_Passwd};

  # Check for all neccessary variables to initialize OpenCA:DBI 
  print "    checking the configuration for enough data<br>\n" if ($self->{DEBUG});

  # backend is not required actually
  # if ( not $self->{backend} ) {
  #   $self->errno ( $OpenCA::DBI::ERROR->{ MISSING_BACKEND } );
  #   return undef;
  # }
  if (
       (not $self->{DB_Type}) or
       (not $self->{DB_Name}) or
       (not $self->{DB_User}) or
       (not $self->{DB_Passwd})
     ) {
    $self->errno ( $OpenCA::DBI::ERROR->{MISSING_PRIMARY_DATABASE} );
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
  print "    preparing the database (vendor dependent)<br>\n" 
    if ($self->{DEBUG});

  ## WARNING I don't include any attributes into the DSN
  ## because I don't know how widely version 1.10 of DBI is used actually
  ## END of WARNING

  $self->{DSN} = "dbi:".$self->{DB_Type}.":";
  if ($self->{DB_Type} eq "Pg") {
    print "      Pg detected<br>\n" if ($self->{DEBUG});
    $self->{DSN} .= "dbname=".$self->{DB_Name};
    $self->{DSN} .= ";"."host=".$self->{DB_Host} if ($self->{DB_Host});
    $self->{DSN} .= ";"."port=".$self->{DB_Port} if ($self->{DB_Port});
  } elsif ($self->{DB_Type} eq "mysql") {
    print "      mysql detected<br>\n" if ($self->{DEBUG});
    $self->{DSN} .= "database=".$self->{DB_Name};
    $self->{DSN} .= ";"."host=".$self->{DB_Host} if ($self->{DB_Host});
    $self->{DSN} .= ";"."port=".$self->{DB_Port} if ($self->{DB_Port});
    ## not clean but safe
    $self->{DSN} .= ";mysql_ssl=0";
  } elsif ($self->{DB_Type} =~ /^DB2$/ ) {
    print "      DB2 detected<br>\n" if ($self->{DEBUG});
    $self->{DSN} .= $self->{DB_Name};
  } elsif ($self->{DB_Type} =~ /^Oracle$/ ) {
    print "      Oracle detected<br>\n" if ($self->{DEBUG});
    ## you can use tnsname or sidname
    $self->{DSN} .= $self->{DB_Name};
  } else {
   $self->errno ( $OpenCA::DBI::ERROR->{DB_TYPE_UNKNOWN} );
   return undef;
  }
  print "      DB: ".$self->{DSN}."<br>\n" if ($self->{DEBUG});

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

  print "  connecting to database<br>\n" if ($self->{DEBUG});

  $self->{STH} = [];

  ## dsn etc. defined so lets try
  print "  try to connect<br>\n" if ($self->{DEBUG});
  $self->{DBH} = DBI->connect ($self->{DSN},
                               $self->{DB_User},
                               $self->{DB_Passwd}, 
                               \%{$OpenCA::DBI::DB->{$self->{DB_Type}}->{DBI_OPTION}});
  if (not $self->{DBH} or $self->{DBH}->state != 0) {
    ## connect failed try again
    print "  connect failed<br>\n" if ($self->{DEBUG});
    $self->errno ( $OpenCA::DBI::ERROR->{CONNECT_FAILED} );
    return undef;
  }

  print "  Checking AutoCommit to be off ...<br>\n" if ($self->{DEBUG});
  if ($self->{DBH}->{AutoCommit} == 1) {
    print "  AutoCommit is on so I'm aborting ...<br>\n" if ($self->{DEBUG});
    $self->errno ( $OpenCA::DBI::ERROR->{AUTOCOMMIT} );
    return undef;
  }
  print "  AutoCommit is off<br>\n" if ($self->{DEBUG});

  print "  OpenCA::DBI should now complete<br>\n" if ($self->{DEBUG});

  $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} ); 
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
  
  print "  Entering Loop for different databases<br>\n" if ($self->{DEBUG});
 
  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

  my $mode   = $keys->{MODE};

  if ($self->{DEBUG}) {
    print "Entering sub initDB\n";
    print "  MODE: ".$mode."<br>\n";
  }

  ## Accepted modes are
  ## NONE
  ## FORCE  to force table creation

  my ($db, $force, $table, $dsn); 
  # force ?
  $force = 0;
  if ( $mode =~ /^FORCE$/i ) {
      $force = 1;
  }
  print "    force: ".$force."<br>\n" if ($self->{DEBUG});
  if ($self->{DEBUG} and $force) {
    print "    ###############################<br>\n";
    print "    ## WARNING - FORCEMODE IS ON ##<br>\n";
    print "    ##   DESTRUCTING ALL TABLES  ##<br>\n";
    print "    ###############################<br>\n";
  }
    
  foreach $table (keys %{$OpenCA::DBI::SQL->{TABLE}}) {
    print "    table: ".$table."<br>\n" if ($self->{DEBUG});
    # check for existence
    print "      dsn: ".$self->{DSN}."\n" if ($self->{DEBUG});
    print "      the folloing debugging-output is for DB2<br>\n" if ($self->{DEBUG});
    print "      ld_library_path: ".$ENV{LD_LIBRARY_PATH}."<br>\n" if ($self->{DEBUG});
    print "      path: ".           $ENV{PATH}.           "<br>\n" if ($self->{DEBUG});
    print "      libpath".          $ENV{LIBPATH}.        "<br>\n" if ($self->{DEBUG});
    print "      classpath".        $ENV{CLASSPATH}.      "<br>\n" if ($self->{DEBUG});
    if (defined $self->operateTable (DO=>"exist", TABLE => $table)) {
      if ($force) {
        if (not defined $self->operateTable (DO=>"drop", TABLE => $table)) {
          $self->errno ( $OpenCA::DBI::ERROR->{ "CANNOT_REMOVE_".$table } );
          $self->rollback ();
	  return undef;
	}
      } else {
        $self->errno ( $OpenCA::DBI::ERROR->{ $table."_TABLE_EXIST" } );
        $self->rollback ();
        return undef;
      }
    }
    print "      try to create table<br>\n" if ($self->{DEBUG});
    # create table
    if (not defined $self->operateTable (DO=>"create", TABLE => $table)) {
      $self->errno ( $OpenCA::DBI::ERROR->{ "CANNOT_CREATE_".$table } );
      $self->rollback ();
      return undef;
    }
    print "      table created<br>\n" if ($self->{DEBUG});
  }

  if (not defined $self->commit ()) {
    $self->rollback ();
    return undef;
  }

  print "  initDB successful completed<br>\n" if ($self->{DEBUG});
  $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
  return 1;
}

sub operateTable {
  my $self = shift;
  my $keys = { @_ };
  
  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

  my $table     = $keys->{TABLE};
  my $operation = $keys->{DO};
 
  print "Entering sub operateTable<br>\n" if ($self->{DEBUG});
 
  # the tables
  my (%tables, $dbh, $sth, $statement, $create);

  print "        build the create statements<br>\n" if ($self->{DEBUG});

  ############################
  ## initial tablestructure ##
  ## change carefully !!!   ##
  ############################

  print "  table: ".$OpenCA::DBI::SQL->{TABLE}->{$table}."<br>\n" if ($self->{DEBUG});
  $create = "create table ".$OpenCA::DBI::SQL->{TABLE}->{$table}." (";
  for (my $i=0; 
       $i < scalar (@{$OpenCA::DBI::SQL->{TABLE_STRUCTURE}->{$table}}); 
       $i++) {
    if ($i == 0) {
      $create .= $OpenCA::DBI::SQL->{VARIABLE}->{
                   $OpenCA::DBI::SQL->{TABLE_STRUCTURE}->{$table}[0]
                 }[0]." ".
                 $OpenCA::DBI::DB->{$self->{DB_Type}}->{TYPE}->{
                   $OpenCA::DBI::SQL->{VARIABLE}->{
                     $OpenCA::DBI::SQL->{TABLE_STRUCTURE}->{$table}[0]
                   }[1]
                 }." ".
                 $OpenCA::DBI::DB->{$self->{DB_Type}}->{TYPE}->{PRIMARYKEY};
    } else {
      $create .= ", ".
                 $OpenCA::DBI::SQL->{VARIABLE}->{
                   $OpenCA::DBI::SQL->{TABLE_STRUCTURE}->{$table}[$i]
                 }[0]." ".
                 $OpenCA::DBI::DB->{$self->{DB_Type}}->{TYPE}->{
                   $OpenCA::DBI::SQL->{VARIABLE}->{
                     $OpenCA::DBI::SQL->{TABLE_STRUCTURE}->{$table}[$i]
                   }[1]
                 };
    }
  }
  $create .= ")";
  $create .= " ".$OpenCA::DBI::DB->{$self->{DB_Type}}->{CREATE_TABLE_OPTION}
    if (exists $OpenCA::DBI::DB->{$self->{DB_Type}}->{CREATE_TABLE_OPTION});

  print "  create:".$create."<br>\n" if ($self->{DEBUG});

  ############################
  ##      end of            ##
  ## initial tablestructure ##
  ## change carefully !!!   ##
  ############################

  print "        build the statement finally<br>\n" if ($self->{DEBUG});

  # check table
  my $negator = 0;
  if ($operation eq "create") {
    $statement = $create;
  } elsif ($operation eq "drop") {
    $statement = "drop table ".$OpenCA::DBI::SQL->{TABLE}->{$table};
  } else {
    $statement = "select * from ".$OpenCA::DBI::SQL->{TABLE}->{$table};
  }

  print "        statement: ".$statement."<br>\n" if ($self->{DEBUG});
  ## can happen if operation performs for sequence generator
  if ($statement eq "") {
    $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
    return 1;
  }
  print "        run the statement<br>\n" if ($self->{DEBUG});

  # attention not for final use because of the central $OpenCA::DBI::ERROR VARIABLE !!!

  # because of a postgres-bug we must commit all changes here
  if ($self->{DB_Type} =~ /Pg/i) {
      $self->commit();
  }
  if (not defined $self->doQuery ( QUERY => $statement )) {
    print "        query failed return undef (EXCEPT OF NEGATOR)<br>\n" if ($self->{DEBUG});
    # because of a postgres-bug we must rollback here to rescue the following operations
    if ($self->{DB_Type} =~ /Pg/i) {
        $self->rollback();
    }
    if ($negator) {
      $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
      return 1;
    }
    return undef;
  }

  print "        query succeeded return 1 (EXCEPT OF NEGATOR)<br>\n" if ($self->{DEBUG});
  return undef if ($negator);
  $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
  return 1;
  
}

####################################
## end of database initialization ##
####################################

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

  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

  print "### new function call ###<br>\n".
        "Entering function storeItem<br>\n" if ($self->{DEBUG});
 
  my %arguments  = $self->storeItem_getArguments ( @_ );
  ## check for a correct run of storeItem_getArguments
  print "  storeItem: table: ".$arguments {TABLE}."<br>\n" if ($self->{DEBUG});      

  ## errno set by function
  return undef if (not defined $self->storeItem_checkData ( \%arguments ) );

  ## why do we have a sub getTimeString ???
  $arguments {datetime} = getTimeString ();

  ##   declare variables
  my $rv;

  ## normal insertion of object
  if ($arguments {MODE} =~ /UPDATE/i) { 
    return undef if (not defined $self->storeItem_update ( \%arguments ));
  } else {
    return undef if (not defined $self->storeItem_insert ( \%arguments ));
  }

  ###########################################
  ## be warned: a serial can be a zero !!! ##
  ###########################################
  print "  storeItem: succeeded - KEY: ".$arguments {KEY}."<br>\n" if ($self->{DEBUG});  
  $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
  return $arguments {KEY};
    
}

## parse the arguments
sub storeItem_getArguments {

  my $self = shift;
  my $keys = { @_ };

  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

  my %result;

  print "### new function call ###<br>\n".
        "Entering storeItem_getArguments<br>\n" if ($self->{DEBUG});

  $result{MODE}       = $keys->{MODE};
  $result{MODULETYPE} = $keys->{MODULETYPE};
  $result{MODULE}     = $keys->{MODULE};
  $result{object}     = $keys->{OBJECT};

  $result {TABLE} = $self->getTable ($keys->{DATATYPE});
  print "  storeItem_getArguments: table: ".$result {TABLE}."<br>\n" if ($self->{DEBUG});

  ## get all searchable attributes
  @{$result {attributes}} = $self->getSearchAttributes( DATATYPE=>$result {TABLE} );
  
  my $attr;

  my $object = $keys->{OBJECT};

  ## storeItem

  for $attr ( @{$result {attributes}} ) {
 
    print "  storeItem_getArguments: attribute: ".$attr."<br>\n" if ($self->{DEBUG});      
    ##     Here we distinguish between parameteres in the header
    if( $attr =~ /^(LOA|RA|ROLE|CSR_SERIAL|OPERATOR|SCEP_TID)$/i ) {
      if ( defined $object->getParsed()->{HEADER}->{$attr} ) {
        $result {$attr} = $object->getParsed()->{HEADER}->{$attr};
        print "  storeItem_getArguments: value: ".$result {$attr}."<br>\n" if ($self->{DEBUG});      
      }
    } elsif( $attr =~ /^(DN|PUBKEY|REVOKE_CERTIFICATE_DN|REVOKE_CERTIFICATE_SERIAL|REASON|SUBMIT_DATE|LAST_UPDATE|NEXT_UPDATE)$/i ) {
      if ( defined $object->getParsed()->{$attr} ) {
        $result {$attr} = $object->getParsed()->{$attr};
        print "  storeItem_getArguments: value: ".$result {$attr}."<br>\n" if ($self->{DEBUG});      
      }
    } elsif( $attr =~ /^(EMAIL)$/i ) {
      if ( defined $object->getParsed()->{EMAILADDRESS} ) {
        $result {EMAILADDRESS} = $object->getParsed()->{EMAILADDRESS};
        $result {EMAIL} = $object->getParsed()->{EMAILADDRESS};
        print "  storeItem_getArguments: value: ".$result {EMAILADDRESS}."<br>\n" if ($self->{DEBUG});      
      }
    } else {
      if ( defined $object->getParsed()->{DN_HASH}->{$attr} ) {
        $result {$attr} = $object->getParsed()->{DN_HASH}->{$attr}[0];
        print "  storeItem_getArguments: value: ".$result {$attr}."<br>\n" if ($self->{DEBUG});      
      }
    }
  }

  ## if it is a cert then we have to set notafter to handle expired certs
  $result {NOTAFTER} = $self->{backend}->getNumericDate ($object->getParsed()->{NOTAFTER})
    if ($object->getParsed()->{NOTAFTER});

  ## enforce status
  $result {STATUS} = $self->getStatus ( STATUS   => $result {STATUS},
                                        DATATYPE => $keys->{DATATYPE} );
  if ($result {STATUS} =~ /EXPIRED/i) {
    $result {STATUS} = "VALID";
  }
  if (not $result {STATUS}) {
    delete ($result {STATUS});
    print "  storeItem_getArguments: status: erased because empty<br>\n" if ($self->{DEBUG});
  } elsif ($self->{DEBUG}) {
    print "  storeItem_getArguments: status: ".$result {STATUS}."<br>\n";
  }

  ## storage formats
  ##   If the data is convertible, let's have only one internal
  ##   format to handle with
  $result {INFORM} = $keys->{INFORM};
  if ( not $result {INFORM} ) {
    $result {INFORM} = "PEM";
  }
  print "  storeItem_getArguments: inform: ".$result {INFORM}."<br>\n" if ($self->{DEBUG});

  $result {KEY} = $result {object}->getSerial ($result {TABLE});
  $result {CONVERTED} = $object->getItem ();
  if( $result {TABLE} =~ /(REQUEST|CRR)/i ) {
    $result {FORMAT} = $object->getParsed()->{TYPE};
  } else {
    $result {FORMAT} = "PEM";
  }
  print "  storeItem_getArguments: KEY:".$result{KEY}."<br>\n" if ($self->{DEBUG});
  print "  storeItem_getArguments: format: ".$result {FORMAT}."<br>\n" if ($self->{DEBUG});
  print "  storeItem_getArguments: converted: ".$result {CONVERTED}."<br>\n" if ($self->{DEBUG});  

  if ($self->{DEBUG}) {
    print "  storeItem_getArguments: object->getParsed hash:<br>\n";
    for my $h (keys %{$object->getParsed()}) {
      print "  storeItem_getArguments: object-attribute:".$h."<br>\n";
      print "  storeItem_getArguments: object-value:".$object->getParsed ()->{$h}."<br>\n";
    }
  }

  print "### function storeItem_getArguments succesfully finished ###<br>\n" if ($self->{DEBUG});

  $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
  return %result;
}

## checks all the available data
## warning: function must called with storeItem_checkData { \%arguments} !!!
sub storeItem_checkData {

  my $self = shift;
  my $arguments = $_[0];

  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

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
  if ( not $arguments->{MODE} ) {
    if ( $arguments->{STATUS} =~ /^(VALID|NEW|RENEW)$/ ) {
      if ((uc $arguments->{MODE}) ne "UPDATE") {
        $arguments->{MODE} = "INSERT";
      } elsif ($arguments->{TABLE} eq "CRL") {
        ## blocks updating CRLs
        ## create a new one please
        $arguments->{MODE} = "INSERT";
      } else {
        $arguments->{MODE} = "UPDATE";
      }
    } elsif ( $arguments->{TABLE} eq "CRL" ) {
      ## blocks updating CRLs
      ## create a new one please
      $arguments->{MODE} = "INSERT";
    } else {
      $arguments->{MODE} = "UPDATE";
    }
  }

  ## if no moduletype then unknown
  if (not $arguments->{MODULETYPE}) {
    $arguments->{MODULETYPE} = "UNKNOWN";
    if ($arguments->{MODULE}) {
      $arguments->{MODULE} .= " - UNKNOWN MODULETYPE";
    } else {
      $arguments->{MODULE} = "UNKNOWN MODULETYPE AND UNKNOWN MODULE";
    }
  }
  ## if no module then "UNKNOWN MODULE"
  if (not $arguments->{MODULE}) {
    $arguments->{MODULE} = "UNKNOWN MODULE";
  }

  ##   if we have no object then return
  if (not $arguments->{object}) {
    $self->errno ($OpenCA::DBI::ERROR->{NO_OBJECT});
    return undef;
  }

  my $query;
  my @bind_values;

  ## is item existent and unique ?
  print "  OpenCA::DBI->storeItem_checkData: check for existence of item<br>\n" if ($self->{DEBUG});  
  $query = "select * from ".$OpenCA::DBI::SQL->{TABLE}->{$arguments->{TABLE}}." where ". 
           $OpenCA::DBI::SQL->{VARIABLE}->{$arguments->{TABLE}."_SERIAL"}[0]."=?";
  undef @bind_values;
  $bind_values[0] = $arguments->{KEY};

  print "  OpenCA::DBI->storeItem_checkData: doQuery: ".$query."<br>\n" if ($self->{DEBUG});  
  if ( not defined $self->doQuery ( QUERY => $query, BIND_VALUES => \@bind_values) ) {
    print "  OpenCA::DBI->storeItem_checkData: doQuery failure detected<br>\n" if ($self->{DEBUG});  
    $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
    return undef;
  }
 
  my $rv = $self->{STH}[scalar @{$self->{STH}} -1]->fetchrow_arrayref;

  ## normal insertion of object
  if (defined $rv and $rv) {
    if (defined $arguments->{MODE} and ($arguments->{MODE} =~ /INSERT/)) {
      print "  OpenCA::DBI->storeItem_checkData: illegal insert<br>\n" if ($self->{DEBUG});  
      $self->errno ( $OpenCA::DBI::ERROR->{ENTRY_EXIST} );
      return undef;
    } else {
      $arguments->{MODE} = "UPDATE";
    }
  } else {
    if (defined $arguments->{MODE} and ($arguments->{MODE} =~ /UPDATE/)) {
      print "  OpenCA::DBI->storeItem_checkData: illegal update<br>\n" if ($self->{DEBUG});  
      $self->errno ( $OpenCA::DBI::ERROR->{ENTRY_NOT_EXIST} );
      return undef;
    } else {
      $arguments->{MODE} = "INSERT";
    }
  }

  print "  data is complete<br>\n" if ($self->{DEBUG});  
  print "### leaving function storeItem_checkData successfully ###<br>\n" if ($self->{DEBUG});  

  $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
  return 1;
}

sub storeItem_update {

  my $self = shift;
  my $arguments = $_[0];

  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

  my $query;
  my @bind_values;

  print "    update mode\n" if ($self->{DEBUG});  
  ## item existent
  ## ok this could be CRR, Request or Certificate
  ##   verify actual state (check signatures)
  ##     -- (I think that's not the job of the DBI-Module - so it is not implemented)
  ##   check all input data
  ##     -- this should be done earlier 
  ##     -- (attriubtes are checked directly before storing them)
  ##   is this statechange allowed (for example to prevent multiple DNs)
  ##     -- actually not implemented (do statechange only)
  ##   try statechange
  ##     -- prepare query
  print "    prepare query\n" if ($self->{DEBUG});  
  $query = "update ".$OpenCA::DBI::SQL->{TABLE}->{$arguments->{TABLE}}." set ".
  ##     -- adding data, format, status
    $OpenCA::DBI::SQL->{VARIABLE}->{DATA}[0]."=?, ".
    $OpenCA::DBI::SQL->{VARIABLE}->{FORMAT}[0]."=? ";
  undef @bind_values;
  $bind_values [0] = $arguments->{CONVERTED};
  $bind_values [1] = $arguments->{FORMAT};
  ##     -- adding searchattributes - never update a date !!!
  ##     -- getSearchAttributes don't return date as attribute
  for my $attr ( @{$arguments->{attributes}} ) {
    # so transformation should be correct for SQL
    if ($attr !~ /^KEY$/ and $arguments->{$attr}) {
      $query .= ", ".$OpenCA::DBI::SQL->{VARIABLE}->{$attr}[0]."=?";
      $bind_values [scalar @bind_values] = $arguments->{$attr};
    }
  }
  if ($arguments->{TABLE} =~ /CERTIFICATE/i) {
    $query .= ", ".$OpenCA::DBI::SQL->{VARIABLE}->{NOTAFTER}[0]."=?";
    $bind_values [scalar @bind_values] = $arguments->{NOTAFTER};
  }

  ##     -- set serials
  $query .= " where ".
    $OpenCA::DBI::SQL->{VARIABLE}->{$arguments->{TABLE}."_SERIAL"}[0]."=?";
  $bind_values [scalar @bind_values] = 
    $arguments->{KEY};

  foreach my $help (@bind_values) {
    print "      bind_values: ".$help."\n" if ($self->{DEBUG});
  }
  print "    query complete, call doQuery\n" if ($self->{DEBUG});  

  if ( not defined $self->doQuery ( QUERY => $query, BIND_VALUES => \@bind_values) ) {
    $self->errno ( $OpenCA::DBI::ERROR->{UPDATE_FAILED} );
    return undef;
  }

  $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
  return 1;
}

sub storeItem_insert {

  my $self = shift;
  my $arguments = $_[0];

  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

  my $query;
  my @bind_values;

  print "### new function call ###<br>\n" if ($self->{DEBUG});
  print "Entering storeItem_insert<br>\n" if ($self->{DEBUG});  
  ## INSERT
  ##   mode='update' is allowed in the future to support revoking non-existing request 
  ##   check all input data
  ##     -- this should be done earlier 
  ##     -- (attriubtes are checked directly before storing them)
  ##   is this statechange allowed (for example renewal nonexistent request)
  ##     -- actually not implemented (do statechange only)
  ##   create row with all additional attributes
  ##     -- prepare query
  print "  prepare query<br>\n" if ($self->{DEBUG});  
  $query = "insert into ".
    $OpenCA::DBI::SQL->{TABLE}->{$arguments->{TABLE}}." ( ".
    $OpenCA::DBI::SQL->{VARIABLE}->{$arguments->{TABLE}."_SERIAL"}[0].", ".
    $OpenCA::DBI::SQL->{VARIABLE}->{DATA}[0].", ".
    $OpenCA::DBI::SQL->{VARIABLE}->{FORMAT}[0]." ";
  for my $attr ( @{$arguments->{attributes}} ) {
    $query .= ", ".$OpenCA::DBI::SQL->{VARIABLE}->{$attr}[0]
      if ($attr !~ /^KEY$/ and $arguments->{$attr});
  }
  if ($arguments->{TABLE} =~ /CERTIFICATE/i) {
    $query .= ", ".$OpenCA::DBI::SQL->{VARIABLE}->{NOTAFTER}[0];
  }
  $query .= ") VALUES (";
  ##     -- adding data, format, status
  $query .= " ?, ?, ?";
  undef @bind_values;
  $bind_values [0] = $arguments->{KEY};
  $bind_values [1] = $arguments->{CONVERTED};
  $bind_values [2] = $arguments->{FORMAT};
  print "  try to parse header<br>\n" if ($self->{DEBUG});  
  ##     -- adding searchattributes - never update a date !!!
  ##     -- getSearchAttributes don't return date as attribute
  for my $attr ( @{$arguments->{attributes}} ) {
    if ($attr !~ /^KEY$/ and $arguments->{$attr}) {
      # so transformation should be correct for SQL
      print "      attr: ".$attr."\n" if ($self->{DEBUG});
      $query .= ", ?";
      $bind_values [scalar @bind_values] = $arguments->{$attr};
    }
  }
  if ($arguments->{TABLE} =~ /CERTIFICATE/i) {
    $query .= ", ?";
    $bind_values [scalar @bind_values] = $arguments->{NOTAFTER};
  }
  $query .= ")";
      
  foreach my $help (@bind_values) {
    print "      bind_values: ".$help."\n" if ($self->{DEBUG});
  }
  print "    query complete, call doQuery\n" if ($self->{DEBUG});  

  if ( not defined $self->doQuery (QUERY => $query, BIND_VALUES => \@bind_values) ) {
    $self->errno ( $OpenCA::DBI::ERROR->{INSERT_FAILED} );
    return undef;
  }

  $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
  return 1;

}

####################################
## end of storeItem related stuff ##
####################################

sub updateStatus {
  
  my $self = shift;
  my $keys = { @_ };
 
  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

  ## get the key
  my $key;
  if ($keys->{DATATYPE} =~ /CA_CERTIFICATE/i) {
    my $converted = $keys->{OBJECT}->getPEMHeader();
    $converted   .= $keys->{OBJECT}->getPEM();
    $converted   .= $keys->{OBJECT}->getParsed()->{KEY};
  }
  if ($keys->{OBJECT}) {
    $key = $keys->{OBJECT}->getSerial ($keys->{DATATYPE});
  } else {
    return undef;
  }

  ## verify status (or existance)
  if (not $self->getItem ( DATATYPE => $keys->{DATATYPE}, KEY => $key )) {
    $self->errno ( $OpenCA::DBI::ERROR->{ENTRY_NOT_EXIST} );
    return undef;
  }

  ## change tatus
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
  
  print "OpenCA::DBI->getItem: ### new function call ###<br>\n".
        "OpenCA::DBI->getItem: Entering sub getItem<br>\n" if ($self->{DEBUG});

  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

  my ( $fileName, $item, $body, $header, $hash, $tmpBody );
  
  my %arguments = $self->getArguments ( @_ );
  return undef if (not defined %arguments);

  my $query;
  my @bind_values;

  ## support for direct access to latest CRL
  if ((not defined $arguments{KEY}) && ($arguments{TABLE} ne "CRL")) {
    $self->errno ( $OpenCA::DBI::ERROR->{ MISSING_ARG_SERIAL } );
    return undef;
  }

  print "OpenCA::DBI->getItem: data complete\n" if ($self->{DEBUG});  

  ## I hope the people only search for Certs, Requests and CRRs
  ## mmh this is impossible
  $query = "select * from ".$OpenCA::DBI::SQL->{TABLE}->{$arguments{TABLE}}." where ";
  if (defined $arguments{KEY}) {
    if ($arguments{TABLE} =~ /CA_CERTIFICATE/i)
    {
        $query .= "(".$OpenCA::DBI::SQL->{VARIABLE}->{$arguments{TABLE}."_SERIAL"}[0]." like ?)";
    } else {
        $query .= "(".$OpenCA::DBI::SQL->{VARIABLE}->{$arguments{TABLE}."_SERIAL"}[0]."=?)";
    }
    if ($arguments{STATUS}) {
      $query .= " and (".$OpenCA::DBI::SQL->{VARIABLE}->{STATUS}[0]." like '".$arguments{STATUS}."')";
      $query .= $self->handleExpiredCert ( \%arguments ) if ($arguments{NOTAFTER});
    }
    $bind_values [0] = $arguments{KEY};
  } else {
    ## to support most actual CRL (you can use it find the last cert etc. too)
    $query .= $OpenCA::DBI::SQL->{VARIABLE}->{DATE}[0]." like (select MAX(".
      $OpenCA::DBI::SQL->{VARIABLE}->{LAST_UPDATE}[0].") from ".$OpenCA::DBI::SQL->{TABLE}->{$arguments{TABLE}}.")";
    undef @bind_values;
  }
  print "OpenCA::DBI->getItem: query: ".$query."<br>\n" if ($self->{DEBUG});

  my ($rv);

  ## do_query
  if ( not defined $self->doQuery (QUERY => $query, BIND_VALUES => \@bind_values) ) {
    $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
    return undef;
  }
  print "OpenCA::DBI->getItem: query completed<br>\n" if ($self->{DEBUG});
    
  ## false is ok  
  $rv = $self->{STH}[scalar (@{$self->{STH}}) -1]->state;

  if ($rv) {
    ## db-connection no longer needed
    ## I can take rollback too, it is not important because 
    ## it was only a read action and the database has nothing to do
    $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
    return undef;
  }

  print "OpenCA::DBI->getItem: check that there is a non-empty result<br>\n"
	if ($self->{DEBUG});

  ## STH->rows doesn't work with Oracle (DB2 doesn't like rows sometimes too)
  my $arrayref = $self->{STH}[scalar (@{$self->{STH}}) -1]->fetchrow_arrayref;
  if (not defined $arrayref or not $arrayref) {
    return undef;
  }

  return $self->getResultItem (ARGUMENTS => \%arguments, ARRAYREF => $arrayref);

}

sub getNextItem {

  ## Get an Item provided the exact data to match:
  ## DATATYPE, KEY. Will return, if exists, the data
  ## on the corresponding dB file.
  
  ## Actually, as the search function, the returned
  ## value will be a referenced object (REQ, X509,
  ## CRL, etc... ).
  
  my $self = shift;

  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

  my %arguments = $self->getArguments ( @_ );
  return undef if (not defined %arguments);

  my $query;
  my @bind_values; 

  ## Let's make some needed check
  if (not $arguments{TABLE}) {
    $self->errno ( $OpenCA::DBI::ERROR->{ MISSING_ARG_TABLE } );
    return undef;
  }
  if ( (not $arguments{KEY}) and ($arguments{KEY} != 0) ) {
    $self->errno ( $OpenCA::DBI::ERROR->{ MISSING_ARG_SERIAL } );
    return undef;
  }

  ## I hope the people only search for Certs, Requests and CRRs
  ## mmh this is impossible
  my $and = 0;
  undef @bind_values;
  $query = "select MIN(".$OpenCA::DBI::SQL->{VARIABLE}->{$arguments{TABLE}."_SERIAL"}[0].")".
    " from ".$OpenCA::DBI::SQL->{TABLE}->{$arguments{TABLE}};
  if (defined $arguments{KEY}) {
    $query .= " where (".
              $OpenCA::DBI::SQL->{VARIABLE}->{$arguments{TABLE}."_SERIAL"}[0]." > ? ".
              ")";
    $bind_values [0] = $arguments{KEY};
    $and = 1;
  }
  if ($arguments{STATUS}) {
    if ($and) {
      $query .= " and ";
    } else {
      $query .= " where ";
    }
    ## the like is necessary for IBM DB2
    $query .= " (".$OpenCA::DBI::SQL->{VARIABLE}->{STATUS}[0]." like ?)";
    $bind_values [scalar @bind_values] = $arguments{STATUS};
    $query .= $self->handleExpiredCert ( \%arguments ) if ($arguments{NOTAFTER}); 
  }
  print "  OpenCA::DBI->getNextItem: query: ".$query."<br>\n" if ($self->{DEBUG});

  ## do_query
  if ( not defined $self->doQuery (QUERY => $query, BIND_VALUES => \@bind_values) ) {
    $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
    return undef;
  }
      
  my $ref = $self->{STH}[scalar (@{$self->{STH}}) -1]->fetchrow_arrayref;

  if (defined $ref) {
    # copy by value !!!
    $arguments{KEY} = $ref->[0];
  }

  if (defined $arguments{KEY}) {
    return $self->getItem (DATATYPE => $arguments{TABLE},
                           KEY      => $arguments{KEY},
                           MODE     => $arguments{MODE}
                          );
  } else {
    ## false is SQLSTATE '0000000' which means all is ok
    if (not $self->{STH}[scalar (@{$self->{STH}}) -1]->state) {
      $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
      return 0; ## no errors no results
    } else { # mmh this should never happen here
      $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
      return undef;
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
  
  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

  my %arguments = $self->getArguments ( @_ );
  return undef if (not defined %arguments);

  my $query;
  my @bind_values;

  ## Let's make some needed check
  if (not $arguments{TABLE}) {
    $self->errno ( $OpenCA::DBI::ERROR->{MISSING_ARG_TABLE} );
    return undef;
  }
  if (not $arguments{KEY} and ($arguments{KEY} != 0)) {
    $self->errno ( $OpenCA::DBI::ERROR->{MISSING_ARG_SERIAL} );
    return undef;
  }

  ## I hope the people only search for Certs, Requests and CRRs
  ## mmh this is impossible
  ## Attention date is not numeric !!!
  $query = "select MAX(".$OpenCA::DBI::SQL->{VARIABLE}->{$arguments{TABLE}."_SERIAL"}[0].")".
    " from ".$OpenCA::DBI::SQL->{TABLE}->{$arguments{TABLE}};
  undef @bind_values;

  my $where = 0;
  if (defined $arguments{KEY})
  {
      $where = 1;
      $query .= " where (".$OpenCA::DBI::SQL->{VARIABLE}->{$arguments{TABLE}."_SERIAL"}[0]."< ? ".")";
      $bind_values [0] = $arguments{KEY}; # date is not numeric
  }
  if ($arguments{STATUS}) {
    ## the like is necessary for IBM DB2
    if ($where)
    {
        $query .= " and ";
    } else {
        $query .= " where ";
    }
    $query .= " (".$OpenCA::DBI::SQL->{VARIABLE}->{STATUS}[0]." like ?)";
    $bind_values [scalar @bind_values] = $arguments{STATUS};
    $query .= $self->handleExpiredCert ( \%arguments ) if ($arguments{NOTAFTER});
  }

  my $rv;

  ## do_query
  if ( not defined $self->doQuery (QUERY => $query, BIND_VALUES => \@bind_values) ) {
    $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
    return undef;
  }

  my $ref = $self->{STH}[scalar (@{$self->{STH}}) -1]->fetchrow_arrayref;

  if (defined $ref) {
    # copy by value !!!
    $arguments{KEY} = $ref->[0];
  }

  if (defined $arguments{KEY}) {
    return $self->getItem (DATATYPE => $arguments{TABLE},
                           KEY      => $arguments{KEY},
                           MODE     => $arguments{MODE}
                          );
  } else {
    ## false is SQLSTATE '0000000' which means all is ok
    if (not $self->{STH}[scalar (@{$self->{STH}}) -1]->state) {
      $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
      return 0; ## no errors no results
    } else { # mmh this should never happen here
      $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
      return undef;
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
  
  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

  my $type  = $keys->{DATATYPE};
  my $table = $self->getTable ($type);
  
  my $serial = $keys->{KEY};  ## Key passed when stored item

  my $query;
  my @bind_values;

  ## Let's make some needed check
  if (not $table) {
    $self->errno ( $OpenCA::DBI::ERROR->{MISSING_ARG_TABLE} );
    return undef;
  }
  if (not $serial and ($serial != 0)) {
    $self->errno ( $OpenCA::DBI::ERROR->{MISSING_ARG_SERIAL} );
    return undef;
  }

  ## I hope the people only search for Certs, Requests and CRRs
  ## mmh this is impossible
  ## Attention date is not numeric !!!
  $query = "delete from ".$OpenCA::DBI::SQL->{TABLE}->{$table}." where ".
    $OpenCA::DBI::SQL->{VARIABLE}->{$table."_SERIAL"}[0]."= ? ".
  undef @bind_values;
  $bind_values [0] = $serial; # date is not numeric

  ## do_query
  if ( not defined $self->doQuery (QUERY => $query, BIND_VALUES => \@bind_values) ) {
    $self->errno ( $OpenCA::DBI::ERROR->{DELETE_FAILED} );
    return undef;
  }

  ## successful
  $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
  return 1;

}

sub elements {

  ## Get an Item provided the exact data to match:
  ## DATATYPE, KEY. Will return, if exists, the data
  ## on the corresponding dB file.
  
  ## Actually, as the search function, the returned
  ## value will be a referenced object (REQ, X509,
  ## CRL, etc... ).
  
  my $self = shift;
  
  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

  my %arguments = $self->getArguments ( @_ );
  return undef if (not defined %arguments);
  
  print "### new function call ###<br>\n".
        "  Entering function elements<br>\n" if ($self->{DEBUG});

  my $query;
  my @bind_values;    
  
  ## Let's make some needed check
  if (not $arguments{TABLE}) {
    $self->errno ( $OpenCA::DBI::ERROR->{MISSING_ARG_TABLE} );
    return undef;
  }
  my $count;

  ## I hope the people only search for Certs, Requests and CRRs
  ## mmh this is impossible
  ## Attention date is not numeric !!!
  $query = "select count(*)  from ".$OpenCA::DBI::SQL->{TABLE}->{$arguments{TABLE}};
  undef @bind_values;
  if ($arguments{STATUS}) {
    ## the like is necessary for IBM DB2
    $query .= " where ".$OpenCA::DBI::SQL->{VARIABLE}->{STATUS}[0]." like ?";
    $bind_values [0] = $arguments{STATUS};
    $query .= $self->handleExpiredCert ( \%arguments ) if ($arguments{NOTAFTER});
  }
  
  my $rv;

  ## do_query
  if (not defined $self->doQuery (QUERY => $query, BIND_VALUES => \@bind_values) ) {
    $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
    return undef;
  }

  ## here I have to use state because DB2 
  ## returns rows:=-1 even if there is a result
  ## false means here a successful performed SQL-query ('00000000')
  $rv = $self->{STH}[scalar (@{$self->{STH}}) -1]->state;
  print "  state: \$rv=".$rv."<br>\n" if ($self->{DEBUG});
         
  if (not $rv) {
    # copy by value !!!
    $count = $self->{STH}[scalar (@{$self->{STH}}) -1]->fetchrow_arrayref->[0];
  }

  if (not $rv) {
    ## $rv > 1 is not possible because of SQL's COUNT-Operator
    print "  elements comleted successful<br>\n".
          "### leaving function elements ###<br>\n" if ($self->{DEBUG});
    $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
    return $count;
  ## } elsif ($rv == 0) {
  ##   $self->errno ( $OpenCA::DBI::ERROR->{UNEXPECTED_ERROR} );
  ##   print "  elements comleted unsuccessful<br>\n".
  ##         "### leaving function elements ###<br>\n" if ($self->{DEBUG});
  ##   return undef; ## unexpected error
  } else { # $rv < 0 mmh this should never happen here
    $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
    print "  next round - db-request failed<br>\n" if ($self->{DEBUG});
    return undef;
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
  
  $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );

  my (@retList, @objRetList);

  print "### new function call ###<br>\n".
        "  Entering function searchItems<br>\n" if ($self->{DEBUG});
 
  print "    OpenCA::DBI::errno: ".$errno."<br>\n" if ($self->{DEBUG});
  my %arguments = $self->getArguments ( @_ );
  print "    OpenCA::DBI::errno: ".$errno."<br>\n" if ($self->{DEBUG});
  return undef if ($errno);
  print "dbi-status:".$arguments {STATUS}."<br>\n" if ($self->{DEBUG});

  my $query;
  my @bind_values;
  undef @bind_values;

  ## Let's make some needed check
  if (not $arguments {TABLE}) {
    $self->errno ( $OpenCA::DBI::ERROR->{MISSING_ARG_TABLE} );
    return undef;
  }
  
  ## let's prepare the question
  my $and = 0;
  $query = "select * from ".$OpenCA::DBI::SQL->{TABLE}->{$arguments {TABLE}};
  ## check for unique identifier scan
  if ( $arguments{KEY} and ($arguments {TABLE} =~ /^CERTIFICATE/ ) ) {
    if ($and) {
      $query .= " and ";
    } else {
      $query .= " where ";
      $and = 1;
    }
    $query .= "(".$OpenCA::DBI::SQL->{VARIABLE}->{CERTIFICATE_SERIAL}[0]."=?)";
    ## prepare bind_values
    $bind_values [scalar (@bind_values)] = $arguments{KEY};
    ## delete from keys
    delete $arguments{KEY};
  }
    
  print "  query now:".$query."<br>\n" if ($self->{DEBUG});

  ## For every keyword let's get the list of values
  my @attributes = $self->getSearchAttributes (DATATYPE=>$arguments {TABLE});
  my $attr;
  for $attr ( @attributes ) {
    print "  scan attribute: ".$attr."<br>\n" if ($self->{DEBUG});
    if ($arguments {$attr}) {
      print "  attribute's content: ".$arguments {$attr}."<br>\n" if ($self->{DEBUG});
      ## get from keys
      if ($and) {
	$query .= " and ";
      } else {
	$query .= " where ";
	$and = 1;
      }
      if ($attr =~ /^KEY$/) {
        $query .= "(".
          $OpenCA::DBI::SQL->{VARIABLE}->{$arguments {TABLE}."_SERIAL"}[0]."=?)";
      } elsif ($OpenCA::DBI::SQL->{VARIABLE}->{$attr}[1] =~ /BIGINT/i) {
        print "    OpenCA::DBI->searchItems: BIGINT: ".
              $attr." --&gt; ".
              $OpenCA::DBI::SQL->{VARIABLE}->{$attr}[1]."<br>\n"
            if ($self->{DEBUG});
        $query .= "(".$OpenCA::DBI::SQL->{VARIABLE}->{$attr}[0]." = ?)";
      } else {
        print "    OpenCA::DBI->searchItems: TEXT: ".
              $attr." --&gt; ".
              $OpenCA::DBI::SQL->{VARIABLE}->{$attr}[1]."<br>\n"
            if ($self->{DEBUG});
        $query .= "(".$OpenCA::DBI::SQL->{VARIABLE}->{$attr}[0]." like ?)";
      }
      if ($attr =~ /STATUS/i) {
        $query .= $self->handleExpiredCert ( \%arguments ) if ($arguments{NOTAFTER});
      }
      ## prepare bind_values
      $bind_values [scalar (@bind_values)] = 
        $arguments {$attr};
      ## delete from keys
      delete $arguments{$attr};
    }
  }

  ## order by key to support correct listings
  $query.= " order by ".
           $OpenCA::DBI::SQL->{VARIABLE}->{$arguments {TABLE}."_SERIAL"}[0];

  print "  query:".$query."<br>\n" if ($self->{DEBUG});
  
  my $rv = 0;

  ## do_query
  $rv = $self->doQuery (QUERY => $query, BIND_VALUES => \@bind_values);
  if (not defined $rv ) {
    $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
    return undef;
  } else {

    ## original "stolen" from OpenCA::DB sub searchItemDB

    print "  state(false is OK): ".
      $self->{STH}[scalar (@{$self->{STH}})-1]->state."<br>\n" if ($self->{DEBUG});
    print "  rows (this is buggy in DBD::DB2 and DBD::Oracle)): ".
      $self->{STH}[0]->rows."<br>\n" if ($self->{DEBUG});
    ## $self->{STH}[scalar (@{$self->{STH}})-1]->rows."<br>\n" if ($self->{DEBUG});
    ## Results
    ## be warned fetchrow_hashref doesn't work with DB2
    while ( (my $h =  $self->{STH}[scalar (@{$self->{STH}}) -1]->fetchrow_arrayref) ) {
      print "  item: ".
            $h->[0].
            "<br>\n" if ($self->{DEBUG});
      push ( @retList, $h->[0] );
    }

    ## because of searchItemDB + searchItem 
    ## but what it's doing ?
    if( $arguments {MODE} eq "ROWS" ) {
      print "  function searchItems completed successful<br>\n".
            "### leaving function searchItems ###<br>\n" if ($self->{DEBUG});
      $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
      return ($#retList+1);
    }
      
    for my $i (@retList) {
      my $obj;
	
      next if ( not $obj = $self->getItem( DATATYPE => $arguments{TABLE},
                                           STATUS   => $arguments{STATUS}, 
                                           KEY      => $i ));
      print "  add an object to the returnlist of searchItem\n" if ($self->{DEBUG});
      push( @objRetList, $obj );
    }

    print "  function searchItems completed successful<br>\n".
          "### leaving function searchItems ###<br>\n" if ($self->{DEBUG});
    $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
    return @objRetList;

  }

  ## never reached
  $self->errno ( $OpenCA::DBI::ERROR->{UNEXPECTED_ERROR} );
  return undef;

}

sub listItems {
  my $self = shift;
  my $keys = { @_ };

  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

  my $dataType	= $keys->{DATATYPE};
  my $items 	= $keys->{ITEMS};
  my $from 	= $keys->{FROM};
  ## my $to 		= $keys->{TO};
  my $mode	= $keys->{MODE};

  my ( @ret, $retItems, $i, $tmpObj );

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

  ## if all items are requested
  $items = -1 if (not $items);

  my %arguments = $self->getArguments ( @_ );
  return undef if (not defined %arguments);

  my $query;
  my @bind_values; 

  ## Let's make some needed check
  if (not $arguments{TABLE}) {
    $self->errno ( $OpenCA::DBI::ERROR->{ MISSING_ARG_TABLE } );
    return undef;
  }

  ## I hope the people only search for Certs, Requests and CRRs
  ## mmh this is impossible
  my $and = 0;
  undef @bind_values;
  $query = "select * from ".$OpenCA::DBI::SQL->{TABLE}->{$arguments{TABLE}};
  if (defined $from) {
    $query .= " where (".
              $OpenCA::DBI::SQL->{VARIABLE}->{$arguments{TABLE}."_SERIAL"}[0]." >= ? ".
              ")";
    $bind_values [0] = $from;
    $and = 1;
  }
  if ($arguments{STATUS}) {
    if ($and) {
      $query .= " and ";
    } else {
      $query .= " where ";
    }
    ## the like is necessary for IBM DB2
    $query .= " (".$OpenCA::DBI::SQL->{VARIABLE}->{STATUS}[0]." like ?)";
    $bind_values [scalar @bind_values] = $arguments{STATUS};
    $query .= $self->handleExpiredCert ( \%arguments ) if ($arguments{NOTAFTER}); 
  }
  print "  OpenCA::DBI->listItems: query: ".$query."<br>\n" if ($self->{DEBUG});

  ## build query limit
  my $hquery = $OpenCA::DBI::DB->{$self->{DB_Type}}->{LIMIT};
  $hquery =~ s/__QUERY__/$query/;
  $hquery =~ s/__MAXITEMS__/$items/;
  $query  = $hquery;
  print "  OpenCA::DBI->listItems: limited query: ".$query."<br>\n" if ($self->{DEBUG});

  ## do_query
  if ( not defined $self->doQuery (QUERY => $query, BIND_VALUES => \@bind_values) ) {
    $self->errno ( $OpenCA::DBI::ERROR->{SELECT_FAILED} );
    return undef;
  }

  my $arrayref;
  while ($arrayref = $self->{STH}[scalar (@{$self->{STH}}) -1]->fetchrow_arrayref) {

    $tmpObj = $self->getResultItem (ARGUMENTS => \%arguments, ARRAYREF => $arrayref);

    if ( $mode ne "RAW" ) {
      push (@ret, $tmpObj);
    } else {
      push (@ret, $tmpObj->getSerial($dataType));
    }

    print "  OpenCA::DBI->listItems: added item ".$tmpObj->getSerial($dataType)." to result<br>\n"
      if ($self->{DEBUG});
  }
  
  print "  listItems completed successful<br>\n".
        "### leaving function successfully ###<br>\n" if ($self->{DEBUG});
  $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
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

       $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

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
                         "ROLE",
                         "PUBKEY",
                         "SCEP_TID",
                         "LOA" );
        } elsif ( $type =~ /CA_CERTIFICATE/ ) {
                @ret = ( "KEY",
                         "STATUS",
                         "DN",
                         "CN",
                         "EMAIL",
                         "PUBKEY" );
        } elsif ( $type =~ /CERTIFICATE/ ) {
                @ret = ( "KEY",
                         "STATUS",
                         "DN",
                         "CN",
                         "EMAIL",
                         "ROLE",
                         "PUBKEY",
                         "CSR_SERIAL",
                         "LOA" );
        } elsif ( $type =~ /CRR/ ) {
                @ret = ( "KEY",
                         "STATUS",
                         "REVOKE_CERTIFICATE_SERIAL",
                         "REVOKE_CERTIFICATE_DN",
                         "CN",
                         "EMAIL",
                         "RA",
                         "OPERATOR",
                         "SUBMIT_DATE",
                         "REASON",
                         "LOA" );
        } elsif ( $type =~ /CRL/ ) {
                @ret = ( "KEY",
                         "STATUS",
                         "LAST_UPDATE",
                         "NEXT_UPDATE" );
        };

        $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
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
  my $check;

  my %result;
  if (exists $keys->{DEBUG})
  {
      $self->{DEBUG} = $keys->{DEBUG};
      delete $keys->{DEBUG};
  }

  print "### new function call ###<br>\n".
        "  Entering getArguments<br>\n" if ($self->{DEBUG});

  foreach my $key (keys %$keys)
  {
      $check->{$key} = $keys->{$key};
      print "    OpenCA::DBI->getArguments: check: $key=".$check->{$key}."<br>\n"
          if ($self->{DEBUG});
  }
  delete $check->{FROM};
  delete $check->{ITEMS};
 
  $result {TABLE} = $self->getTable ($keys->{DATATYPE});
  $result {MODE}  = $keys->{MODE};
  delete $check->{MODE};
  print "  OpenCA::DBI->getArguments: TABLE:".$result {TABLE}."<br>\n" if ($self->{DEBUG});
  print "  OpenCA::DBI->getArguments: MODE:".$result {MODE}."<br>\n" if ($self->{DEBUG});

  ## get all searchable attributes
  my @attributes = $self->getSearchAttributes( DATATYPE => $result {TABLE} );
  my $attr;

  for $attr ( @attributes ) {
    
    print "  OpenCA::DBI->getArguments: attribute: ".$attr."<br>\n" if ($self->{DEBUG});
    if ($attr =~ /^EMAIL$/ and not $keys->{$attr})
    {
        $result {EMAIL} = $keys->{EMAILADDRESS};
        delete $check->{EMAILADDRESS};
    } else {
        $result {$attr} = $keys->{$attr};
        delete $check->{$attr};
    }
    print "  OpenCA::DBI->getArguments: value: ".$result {$attr}."<br>\n" if ($self->{DEBUG});      
  }

  ## enforce status
  $result {STATUS} = $self->getStatus ( STATUS   => $result {STATUS},
                                          DATATYPE => $keys->{DATATYPE} );
  if ($result {STATUS} =~ /EXPIRED/i) {
    $result {STATUS} = "VALID";
    my $today = gmtime;
    $result {NOTAFTER} =  $self->{backend}->getNumericDate ($today);
    $result {STATUS_OLD} = "EXPIRED";
  } elsif ( ($result {STATUS} =~ /VALID/i) and ($result {TABLE} =~ /CERTIFICATE/i) ) {
    my $today = gmtime;
    $result {NOTAFTER} =  $self->{backend}->getNumericDate ($today);
    $result {STATUS_OLD} = "VALID";
  }
  if (not $result {STATUS}) {
    delete ($result {STATUS});
  } elsif ($self->{DEBUG}) {
    print "  OpenCA::DBI->getArguments: status: ".$result {STATUS}."<br>\n";
  }
  delete $check->{STATUS};
  delete $check->{DATATYPE};

  if (scalar (keys %$check))
  {
      if ($self->{DEBUG}) {
          print "    OpenCA::DBI->getArguments: ILLEGAL ARGUMENT<br>\n";
          foreach my $key (keys %$check)
          {
              print "        $key: ".$check->{$key}."<br>\n";
          }
      }
      $self->errno ( $OpenCA::DBI::ERROR->{ILLEGAL_ARGUMENT} );
      return undef;
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
  
  if ( $datatype =~ /CA_CERTIFICATE/ ) {
    $ret = "CA_CERTIFICATE";
  } elsif ( $datatype =~ /CERTIFICATE/ ) {
    $ret = "CERTIFICATE";
  } elsif ( $datatype =~ /CRL/ ) {
    $ret = "CRL";
  } elsif ( $datatype =~ /REQUEST/ ) {
    $ret = "REQUEST";
  } elsif ( $datatype =~ /CRR/ ) {
    $ret = "CRR";
  } else {
    ## Unsupported DATATYPE
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

  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

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
      $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
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
    $datatype = $old if ($datatype =~ /^CA$/i);
    $datatype = "" if ($old eq $datatype); 
    $datatype = uc $datatype;
    print "    given mode is now: \"".$datatype."\"<br>\n" if ($self->{DEBUG});
    ## check for legal status
    if ( $datatype =~ /^$/ )
    {
      print "  no status<br>\n".
            "### leaving function unsuccessful but without error ###<br>\n" if ($self->{DEBUG});
      $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
      return $datatype;
    } elsif ( $OpenCA::DBI::STATUS->{$datatype} ) {
      print "  legal status<br>\n".
            "### leaving function successful ###<br>\n" if ($self->{DEBUG});
      $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
      return $datatype;
    } else {
      print "  illegal status<br>\n".
            "### leaving function unsuccessful but without error ###<br>\n" if ($self->{DEBUG});
      $self->errno ( $OpenCA::DBI::ERROR->{ILLEGAL_STATUS} );
      return undef;
    }
  }
}

sub build_date {
  my $self = shift;
  my $date = $_[0];
  my %help;
  my $new_date;

  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

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

  $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
  return $new_date; 

}

sub doQuery {
  my $self = shift;
  my $keys = { @_ };

  $self->errno ( $OpenCA::DBI::ERROR->{DO_NOT_COMMIT} );

  print "### new function call ###<br>\n" if ($self->{DEBUG});
  print "  Entering sub doQuery<br>\n" if ($self->{DEBUG});

  # these variables are in-vars
  my $query     = $keys->{QUERY};
  my @bind_values = @{$keys->{BIND_VALUES}} if ($keys->{BIND_VALUES});

  print "  query: ".$query."<br>\n" if ($self->{DEBUG});
  foreach my $help (@bind_values) {
    print "  bind_values: ".$help."<br>\n" if ($self->{DEBUG});
  }

  ## query empty so not a DB-failure
  return undef if ($query eq "");

  ## prepare
  print "  prepare statement<br>\n" if ($self->{DEBUG});
  print "  statement nr.: ".(scalar (@{$self->{STH}}) +1)."<br>\n" if ($self->{DEBUG});
  $self->{STH}[scalar (@{$self->{STH}})] = $self->{DBH}->prepare ($query);
  if ( (my $h = $self->{STH}[scalar (@{$self->{STH}}) -1]->state) != 0) {
    print "  prepare failed<br>\n" if ($self->{DEBUG});
    print "  query: ".$query."<br>\n" if ($self->{DEBUG});
    print "  returned errorcode: ".$h."<br>\n" if ($self->{DEBUG});
    $self->errno ( $OpenCA::DBI::ERROR->{PREPARE_FAILED} );
    return undef;
  }

  ## execute
  print "      execute statement<br>\n" if ($self->{DEBUG});
  $self->{STH}[scalar (@{$self->{STH}}) -1]->execute (@bind_values);
  if (not $self->{STH}[scalar (@{$self->{STH}}) -1]->state) {
    print "  execute succeeded<br>\n" if ($self->{DEBUG});
    print "### leaving function doQuery successfully ###<br>\n" if ($self->{DEBUG});
    $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
    return 1;
  } else {
    print "  execute failed<br>\n" if ($self->{DEBUG});
    print "### leaving function doQuery unsuccessfully ###<br>\n" if ($self->{DEBUG});
    $self->errno ( $OpenCA::DBI::ERROR->{EXECUTE_FAILED} );
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

## this function is a ready to build an answer from the arguments and
## from the resulting array
sub getResultItem {

  ## parameters are
  ##   ARGUMENTS
  ##   ARRAYREF
  
  my $self = shift;
  my $keys = { @_ };

  my $item;

  print "OpenCA::DBI->getResultItem: ### new function call ###<br>\n".
        "OpenCA::DBI->getResultItem: Entering sub getResultItem<br>\n" if ($self->{DEBUG});

  my %arguments = %{$keys->{ARGUMENTS}};
  return undef if (not defined %arguments);

  my $arrayref = $keys->{ARRAYREF};;
  return undef if (not defined $arrayref);

  print "OpenCA::DBI->getResultItem: all params present<br>\n" if ($self->{DEBUG}); 
  my %hash = $self->getResultHash (TABLE => $arguments{TABLE},
                                   ARRAY => $arrayref);

  my $data        = $hash{DATA};
  my $priv_format = $hash{FORMAT};
  print "OpenCA::DBI->getResultItem: data:<br>\n".$data."<br>\n" if ($self->{DEBUG});
  print "OpenCA::DBI->getResultItem: format: ".$priv_format."<br>\n" if ($self->{DEBUG});
  print "OpenCA::DBI->getResultItem: have all data<br>\n" if ($self->{DEBUG});

  print "OpenCA::DBI->getResultItem: data of item:<br>\n".$data."<br>\n" if ($self->{DEBUG});      

  ## If it was asked only the text version, we send out only that
  ## without generating an OBJECT from it
  if( $arguments{MODE} eq "RAW" ) {
    print "OpenCA::DBI->getResultItem: return data RAW<br>\n" if ($self->{DEBUG});
    $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
    return $data;
  }
    
  ## Build an Object from retrieved DATA
  if( $arguments{TABLE} =~ /CERTIFICATE/ ) {
    $item = new OpenCA::X509( SHELL      => $self->{backend},
                              INFORM     => "PEM",
                              DATA       => $data);
  } elsif ( $arguments{TABLE} eq "CRL" ) {
    print "OpenCA::DBI->getItem: try to create crl<br>\n" if ($self->{DEBUG});	
    $item = new OpenCA::CRL( SHELL      => $self->{backend},
                             INFORM     => "PEM",
                             DATA       => $data);
    print "OpenCA::DBI->getResultItem: crl there<br>\n" if ($self->{DEBUG} and $item);	
    print "OpenCA::DBI->getResultItem: crl failed<br>\n" if ($self->{DEBUG} and not $item);	
  } elsif ( $arguments{TABLE} =~ /(REQUEST|CRR)/i ) {
    $item = new OpenCA::REQ( SHELL      => $self->{backend},
                             DATA       => $data);
  } else {
    ## if we cannot build the object there is probably
    ## an error, retrun a void ...
    print "OpenCA::DBI->getResultItem: cannot build object return void<br>\n" if ($self->{DEBUG});
    $self->errno ( $OpenCA::DBI::ERROR->{ CANNOT_CREATE_OBJECT } );
    return undef;
  }

  ## who uses DBKEY ?!
  $item->{parsedItem}->{DBKEY} = $arguments{KEY};

  ## We return the object
  print "OpenCA::DBI->getResultItem: return item<br>\n" if ($self->{DEBUG});
  $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );

  return $item;
      
} ## end of getResultItem

## rollback never touch the status because 
## rollback is normally the action if a
## statement fails
sub rollback {
  my $self = shift;

  print "OpenCA::DBI->rollback<br>\n" if ($self->{DEBUG});

  ## if there is no databasehandle then we have not to and cannot roll back
  if (not $self->{DBH} or $self->{DBH}->rollback()) {
    $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
    return 1;
  } else {
    $self->errno ( $OpenCA::DBI::ERROR->{ROLLBACK_FAILED} );
    return undef;
  }
}

## commit sets the status-variable
sub commit {
  my $self = shift;

  print "OpenCA::DBI->commit<br>\n" if ($self->{DEBUG});

  if ($self->{DBH}->commit() ) {
    $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
    return 1;
  } else {
    $self->errno ( $OpenCA::DBI::ERROR->{COMMIT_FAILED} );
    return undef;
  }
}

## disconnect don't set the status-variable because commit
## and rollback called before disconnect so success is not important
sub disconnect {
  
  my $self = shift;

  if ($self->{DBH}->disconnect() ) {
    $self->errno ( $OpenCA::DBI::ERROR->{SUCCESS} );
    return 1;
  } else {
    $self->errno ( $OpenCA::DBI::ERROR->{DISCONNECT_FAILED} );
    return undef;
  }
}

sub DESTROY {
  my $self = shift;

  if ($self->{ERRNO} != $OpenCA::DBI::ERROR->{SUCCESS}) {
    print "OpenCA::DBI automatic rollback by destructor DESTROY<br>\n" if ($self->{DEBUG});
    $self->rollback ();
  } else {
    print "OpenCA::DBI automatic commit by destructor DESTROY<br>\n" if ($self->{DEBUG});
    if (not defined $self->commit ()) {
      print "<FONT COLOR=#FF0000>WARNING commit failed so starting general rollback!</FONT><br>\n";
      $self->rollback ();
    }
  }
  ## finish the statement handles to reduce warnings by DBI
  print "call finish on all statement handles to avoid warnings by DBI<br>\n" if ($self->{DEBUG});
  for my $h (@{$self->{STH}}) {
    $h->finish ();
  }

  $self->{DBH}->disconnect ();
}

############################
## begin of errorhandling ##
############################

sub errno {
  my $self = shift;

  if ( defined $_[0] ) {
    ## set errorcode
    $self->{ERRNO} = $_[0];
    ## this helps us handling crashes during new ()
    $OpenCA::DBI::ERRNO = $self->{ERRNO};

    ## this is the new OpenCA-standard
    if ($errno)
    {
      $errval = $OpenCA::DBI::MESSAGE->{$OpenCA::DBI::ERRNO}." (error $errno: $errval)";
    } else {
      $errval = $OpenCA::DBI::MESSAGE->{$OpenCA::DBI::ERRNO};
    }
    $errno  = $OpenCA::DBI::ERRNO;

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
  
  ## simple error
  return $OpenCA::DBI::MESSAGE->{$code};

}

##########################
## end of errorhandling ##
##########################

sub handleExpiredCert {
  my $self = shift;
  my $arguments = $_[0];
  my $query ="";

  if ($arguments->{NOTAFTER}) {
    $query .= " and (".$OpenCA::DBI::SQL->{VARIABLE}->{NOTAFTER}[0];
    if ($arguments->{STATUS_OLD} =~ /EXPIRED/i) {
      $query .= " < ";
    } else {
      $query .= " > ";
    }
    $query .= $arguments->{NOTAFTER}.")";
  }
}

##########################
## end of new functions ##
##########################

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
