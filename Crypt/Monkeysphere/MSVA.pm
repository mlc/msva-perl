# Monkeysphere Validation Agent, Perl version
# Copyright © 2010 Daniel Kahn Gillmor <dkg@fifthhorseman.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

{ package Crypt::Monkeysphere::MSVA;

  use strict;
  use warnings;

  BEGIN {
    use Exporter   ();
    our (@EXPORT_OK,@ISA);
    @ISA = qw(Exporter);
    @EXPORT_OK = qw( &msvalog );
  }
  our @EXPORT_OK;

  use Crypt::Monkeysphere::MSVA::MarginalUI;
  use parent qw(HTTP::Server::Simple::CGI);
  require Crypt::X509;
  use Regexp::Common qw /net/;
  use Convert::ASN1;
  use MIME::Base64;
  use IO::Socket;
  use IO::File;
  use Socket;
  use File::Spec;
  use File::HomeDir;
  use Config::General;

  use JSON;
  use POSIX qw(strftime);
  # we need the version of GnuPG::Interface that knows about pubkey_data, etc:
  use GnuPG::Interface 0.42.02;

  my $version = '0.1';

  my $gnupg = GnuPG::Interface->new();
  $gnupg->options->quiet(1);
  $gnupg->options->batch(1);

  my %dispatch = (
                  '/' => { handler => \&noop,
                           methods => { 'GET' => 1 },
                         },
                  '/reviewcert' => { handler => \&reviewcert,
                                     methods => { 'POST' => 1 },
                                   },
                  '/extracerts' => { handler => \&extracerts,
                                     methods => { 'POST' => 1 },
                                   },
                 );

  my $default_keyserver = 'hkp://pool.sks-keyservers.net';
  my $default_keyserver_policy = 'unlessvalid';

# Net::Server log_level goes from 0 to 4
# this is scaled to match.
  my %loglevels = (
                   'silent' => 0,
                   'quiet' => 0.25,
                   'fatal' => 0.5,
                   'error' => 1,
                   'info' => 2,
                   'verbose' => 3,
                   'debug' => 4,
                   'debug1' => 4,
                   'debug2' => 5,
                   'debug3' => 6,
                  );

  my $rsa_decoder = Convert::ASN1->new;
  $rsa_decoder->prepare(q<

   SEQUENCE {
        modulus INTEGER,
        exponent INTEGER
   }
          >);

  sub msvalog {
    my $msglevel = shift;

    my $level = $loglevels{lc($ENV{MSVA_LOG_LEVEL})};
    $level = $loglevels{error} if (! defined $level);

    if ($loglevels{lc($msglevel)} <= $level) {
      printf STDERR @_;
    }
  };

  sub get_log_level {
    my $level = $loglevels{lc($ENV{MSVA_LOG_LEVEL})};
    $level = $loglevels{error} if (! defined $level);
    return $level;
  }

  sub net_server {
    return 'Net::Server::MSVA';
  };

  sub new {
    my $class = shift;

    my $port = 0;
    if (exists $ENV{MSVA_PORT}) {
      $port = $ENV{MSVA_PORT} + 0;
      die sprintf("not a reasonable port %d", $port) if (($port >= 65536) || $port <= 0);
    }
    # start the server on requested port
    my $self = $class->SUPER::new($port);
    if (! exists $ENV{MSVA_PORT}) {
      # we can't pass port 0 to the constructor because it evaluates
      # to false, so HTTP::Server::Simple just uses its internal
      # default of 8080.  But if we want to select an arbitrary open
      # port, we *can* set it here.
      $self->port(0);
    }

    $self->{allowed_uids} = {};
    if (exists $ENV{MSVA_ALLOWED_USERS} and $ENV{MSVA_ALLOWED_USERS} ne '') {
      msvalog('verbose', "MSVA_ALLOWED_USERS environment variable is set.\nLimiting access to specified users.\n");
      foreach my $user (split(/ +/, $ENV{MSVA_ALLOWED_USERS})) {
        my ($name, $passwd, $uid);
        if ($user =~ /^[0-9]+$/) {
          $uid = $user + 0; # force to integer
        } else {
          ($name,$passwd,$uid) = getpwnam($user);
        }
        if (defined $uid) {
          msvalog('verbose', "Allowing access from user ID %d\n", $uid);
          $self->{allowed_uids}->{$uid} = $user;
        } else {
          msvalog('error', "Could not find user '%d'; not allowing\n", $user);
        }
      }
    } else {
      # default is to allow access only to the current user
      $self->{allowed_uids}->{POSIX::getuid()} = 'self';
    }

    bless ($self, $class);
    return $self;
  }

  sub noop {
    my $self = shift;
    my $cgi = shift;
    return '200 OK', { available => JSON::true,
                       protoversion => 1,
                       server => "MSVA-Perl ".$version };
  }

  # returns an empty list if bad key found.
  sub parse_openssh_pubkey {
    my $data = shift;
    my ($label, $prop) = split(/ +/, $data);
    $prop = decode_base64($prop) or return ();

    msvalog('debug', "key properties: %s\n", unpack('H*', $prop));
    my @out;
    while (length($prop) > 4) {
      my $size = unpack('N', substr($prop, 0, 4));
      msvalog('debug', "size: 0x%08x\n", $size);
      return () if (length($prop) < $size + 4);
      push(@out, substr($prop, 4, $size));
      $prop = substr($prop, 4 + $size);
    }
    return () if ($label ne $out[0]);
    return @out;
  }


  # return an arrayref of processes which we can detect that have the
  # given socket open (the socket is specified with its inode)
  sub getpidswithsocketinode {
    my $sockid = shift;

    # this appears to be how Linux symlinks open sockets in /proc/*/fd,
    # as of at least 2.6.26:
    my $socktarget = sprintf('socket:[%d]', $sockid);
    my @pids;

    my $procfs;
    if (opendir($procfs, '/proc')) {
      foreach my $pid (grep { /^\d+$/ } readdir($procfs)) {
        my $procdir = sprintf('/proc/%d', $pid);
        if (-d $procdir) {
          my $procfds;
          if (opendir($procfds, sprintf('/proc/%d/fd', $pid))) {
            foreach my $procfd (grep { /^\d+$/ } readdir($procfds)) {
              my $fd = sprintf('/proc/%d/fd/%d', $pid, $procfd);
              if (-l $fd) {
                #my ($dev,$ino,$mode,$nlink,$uid,$gid) = lstat($fd);
                my $targ = readlink($fd);
                push @pids, $pid
                  if ($targ eq $socktarget);
              }
            }
            closedir($procfds);
          }
        }
      }
      closedir($procfs);
    }

    # FIXME: this whole business is very linux-specific, i think.  i
    # wonder how to get this info in other OSes?

    return \@pids;
  }

  # return {uid => X, inode => Y}, meaning the numeric ID of the peer
  # on the other end of $socket, "socket inode" identifying the peer's
  # open network socket.  each value could be undef if unknown.
  sub get_client_info {
    my $socket = shift;

    my $sock = IO::Socket->new_from_fd($socket, 'r');
    # check SO_PEERCRED -- if this was a TCP socket, Linux
    # might not be able to support SO_PEERCRED (even on the loopback),
    # though apparently some kernels (Solaris?) are able to.

    my $clientid;
    my $remotesocketinode;
    my $socktype = $sock->sockopt(SO_TYPE) or die "could not get SO_TYPE info";
    if (defined $socktype) {
      msvalog('debug', "sockopt(SO_TYPE) = %d\n", $socktype);
    } else {
      msvalog('verbose', "sockopt(SO_TYPE) returned undefined.\n");
    }

    my $peercred = $sock->sockopt(SO_PEERCRED) or die "could not get SO_PEERCRED info";
    my $client = $sock->peername();
    my $family = sockaddr_family($client); # should be AF_UNIX (a.k.a. AF_LOCAL) or AF_INET

    msvalog('verbose', "socket family: %d\nsocket type: %d\n", $family, $socktype);

    if ($peercred) {
      # FIXME: on i386 linux, this appears to be three ints, according to
      # /usr/include/linux/socket.h.  What about other platforms?
      my ($pid, $uid, $gid) = unpack('iii', $peercred);

      msvalog('verbose', "SO_PEERCRED: pid: %u, uid: %u, gid: %u\n",
              $pid, $uid, $gid,
             );
      if ($pid != 0 && $uid != 0) { # then we can accept it:
        $clientid = $uid;
      }
      # FIXME: can we get the socket inode as well this way?
    }

    # another option in Linux would be to parse the contents of
    # /proc/net/tcp to find the uid of the peer process based on that
    # information.
    if (! defined $clientid) {
      msvalog('verbose', "SO_PEERCRED failed, digging around in /proc/net/tcp\n");
      my $proto;
      if ($family == AF_INET) {
        $proto = '';
      } elsif ($family == AF_INET6) {
        $proto = '6';
      }
      if (defined $proto) {
        if ($socktype == &SOCK_STREAM) {
          $proto = 'tcp'.$proto;
        } elsif ($socktype == &SOCK_DGRAM) {
          $proto = 'udp'.$proto;
        } else {
          undef $proto;
        }
        if (defined $proto) {
          my ($port, $iaddr) = unpack_sockaddr_in($client);
          my $iaddrstring = unpack("H*", reverse($iaddr));
          msvalog('verbose', "Port: %04x\nAddr: %s\n", $port, $iaddrstring);
          my $remmatch = lc(sprintf("%s:%04x", $iaddrstring, $port));
          my $infofile = '/proc/net/'.$proto;
          my $f = new IO::File;
          if ( $f->open('< '.$infofile)) {
            my @header = split(/ +/, <$f>);
            my ($localaddrix, $uidix, $inodeix);
            my $ix = 0;
            my $skipcount = 0;
            while ($ix <= $#header) {
              $localaddrix = $ix - $skipcount if (lc($header[$ix]) eq 'local_address');
              $uidix = $ix - $skipcount if (lc($header[$ix]) eq 'uid');
              $inodeix = $ix - $skipcount if (lc($header[$ix]) eq 'inode');
              $skipcount++ if (lc($header[$ix]) eq 'tx_queue') or (lc($header[$ix]) eq 'tr'); # these headers don't actually result in a new column during the data rows
              $ix++;
            }
            if (!defined $localaddrix) {
              msvalog('info', "Could not find local_address field in %s; unable to determine peer UID\n",
                      $infofile);
            } elsif (!defined $uidix) {
              msvalog('info', "Could not find uid field in %s; unable to determine peer UID\n",
                      $infofile);
            } elsif (!defined $inodeix) {
              msvalog('info', "Could not find inode field in %s; unable to determine peer network socket inode\n",
                      $infofile);
            } else {
              msvalog('debug', "local_address: %d; uid: %d\n", $localaddrix,$uidix);
              while (my @line = split(/ +/,<$f>)) {
                if (lc($line[$localaddrix]) eq $remmatch) {
                  if (defined $clientid) {
                    msvalog('error', "Warning! found more than one remote uid! (%s and %s\n", $clientid, $line[$uidix]);
                  } else {
                    $clientid = $line[$uidix];
                    $remotesocketinode = $line[$inodeix];
                    msvalog('info', "remote peer is uid %d (inode %d)\n",
                            $clientid, $remotesocketinode);
                  }
                }
              }
            msvalog('error', "Warning! could not find peer information in %s.  Not verifying.\n", $infofile) unless defined $clientid;
            }
          } else { # FIXME: we couldn't read the file.  what should we
                   # do besides warning?
            msvalog('info', "Could not read %s; unable to determine peer UID\n",
                    $infofile);
          }
        }
      }
    }
    return { 'uid' => $clientid,
             'inode' => $remotesocketinode };
  }

  sub handle_request {
    my $self = shift;
    my $cgi  = shift;

    my $clientinfo = get_client_info(select);
    my $clientuid = $clientinfo->{uid};

    if (defined $clientuid) {
      # test that this is an allowed user:
      if (exists $self->{allowed_uids}->{$clientuid}) {
        msvalog('verbose', "Allowing access from uid %d (%s)\n", $clientuid, $self->{allowed_uids}->{$clientuid});
      } else {
        msvalog('error', "MSVA client connection from uid %d, forbidden.\n", $clientuid);
        printf("HTTP/1.0 403 Forbidden -- peer does not match local user ID\r\nContent-Type: text/plain\r\nDate: %s\r\n\r\nHTTP/1.1 403 Not Found -- peer does not match the local user ID.  Are you sure the agent is running as the same user?\r\n",
               strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time())),);
        return;
      }
    }

    my $path = $cgi->path_info();
    my $handler = $dispatch{$path};

    if (ref($handler) eq "HASH") {
      if (! exists $handler->{methods}->{$cgi->request_method()}) {
        printf("HTTP/1.0 405 Method not allowed\r\nAllow: %s\r\nDate: %s\r\n",
               join(', ', keys(%{$handler->{methods}})),
               strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time())));
      } elsif (ref($handler->{handler}) ne "CODE") {
        printf("HTTP/1.0 500 Server Error\r\nDate: %s\r\n",
               strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time())));
      } else {
        my $data = {};
        my $ctype = $cgi->content_type();
        msvalog('verbose', "Got %s %s (Content-Type: %s)\n", $cgi->request_method(), $path, defined $ctype ? $ctype : '**none supplied**');
        if (defined $ctype) {
          my @ctypes = split(/; */, $ctype);
          $ctype = shift @ctypes;
          if ($ctype eq 'application/json') {
            $data = from_json($cgi->param('POSTDATA'));
          }
        };

        my ($status, $object) = $handler->{handler}($data, $clientinfo);
        my $ret = to_json($object);
        msvalog('info', "returning: %s\n", $ret);
        printf("HTTP/1.0 %s\r\nDate: %s\r\nContent-Type: application/json\r\n\r\n%s",
               $status,
               strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time())),
               $ret);
      }
    } else {
      printf("HTTP/1.0 404 Not Found -- not handled by Monkeysphere validation agent\r\nContent-Type: text/plain\r\nDate: %s\r\n\r\nHTTP/1.0 404 Not Found -- the path:\r\n   %s\r\nis not handled by the MonkeySphere validation agent.\r\nPlease try one of the following paths instead:\r\n\r\n%s\r\n",
             strftime("%a, %d %b %Y %H:%M:%S %z", localtime(time())),
             $path, ' * '.join("\r\n * ", keys %dispatch) );
    }
  }

  sub keycomp {
    my $rsakey = shift;
    my $gpgkey = shift;

    if ($gpgkey->algo_num != 1) {
      msvalog('verbose', "Monkeysphere only does RSA keys.  This key is algorithm #%d\n", $gpgkey->algo_num);
    } else {
      if ($rsakey->{exponent}->bcmp($gpgkey->pubkey_data->[1]) == 0 &&
          $rsakey->{modulus}->bcmp($gpgkey->pubkey_data->[0]) == 0) {
        return 1;
      }
    }
    return 0;
  }

  sub getuid {
    my $data = shift;
    if ($data->{context} =~ /^(https|ssh)$/) {
      $data->{context} = $1;
      if ($data->{peer} =~ /^($RE{net}{domain})$/) {
        $data->{peer} = $1;
        return $data->{context}.'://'.$data->{peer};
      }
    }
  }

  sub get_keyserver_policy {
    if (exists $ENV{MSVA_KEYSERVER_POLICY} and $ENV{MSVA_KEYSERVER_POLICY} ne '') {
      if ($ENV{MSVA_KEYSERVER_POLICY} =~ /^(always|never|unlessvalid)$/) {
        return $1;
      }
      msvalog('error', "Not a valid MSVA_KEYSERVER_POLICY):\n  %s\n", $ENV{MSVA_KEYSERVER_POLICY});
    }
    return $default_keyserver_policy;
  }

  sub get_keyserver {
    # We should read from (first hit wins):
    # the environment
    if (exists $ENV{MSVA_KEYSERVER} and $ENV{MSVA_KEYSERVER} ne '') {
      if ($ENV{MSVA_KEYSERVER} =~ /^(((hkps?|finger|ldap):\/\/)?$RE{net}{domain})$/) {
        return $1;
      }
      msvalog('error', "Not a valid keyserver (from MSVA_KEYSERVER):\n  %s\n", $ENV{MSVA_KEYSERVER});
    }

    # FIXME: some msva.conf or monkeysphere.conf file (system and user?)

    # or else read from the relevant gnupg.conf:
    my $gpghome;
    if (exists $ENV{GNUPGHOME} and $ENV{GNUPGHOME} ne '') {
      $gpghome = untaint($ENV{GNUPGHOME});
    } else {
      $gpghome = File::Spec->catfile(File::HomeDir->my_home, '.gnupg');
    }
    my $gpgconf = File::Spec->catfile($gpghome, 'gpg.conf');
    if (-f $gpgconf) {
      if (-r $gpgconf) {
        my %gpgconfig = Config::General::ParseConfig($gpgconf);
        if ($gpgconfig{keyserver} =~ /^(((hkps?|finger|ldap):\/\/)?$RE{net}{domain})$/) {
          msvalog('debug', "Using keyserver %s from the GnuPG configuration file (%s)\n", $1, $gpgconf);
          return $1;
        } else {
          msvalog('error', "Not a valid keyserver (from gpg config %s):\n  %s\n", $gpgconf, $gpgconfig{keyserver});
        }
      } else {
        msvalog('error', "The GnuPG configuration file (%s) is not readable\n", $gpgconf);
      }
    } else {
      msvalog('info', "Did not find GnuPG configuration file while looking for keyserver '%s'\n", $gpgconf);
    }

    # the default_keyserver
    return $default_keyserver;
  }

  sub fetch_uid_from_keyserver {
    my $uid = shift;

    my $cmd = IO::Handle->new();
    my $out = IO::Handle->new();
    my $nul = IO::File->new("< /dev/null");

    my $ks = get_keyserver();
    msvalog('debug', "start ks query to %s for UserID: %s\n", $ks, $uid);
    my $pid = $gnupg->wrap_call
      ( handles => GnuPG::Handles->new( command => $cmd, stdout => $out, stderr => $nul ),
        command_args => [ '='.$uid ],
        commands => [ '--keyserver',
                      $ks,
                      qw( --no-tty --with-colons --search ) ]
      );
    while (my $line = $out->getline()) {
      msvalog('debug', "from ks query: (%d) %s", $cmd->fileno, $line);
      if ($line =~ /^info:(\d+):(\d+)/ ) {
        $cmd->print(join(' ', ($1..$2))."\n");
        msvalog('debug', 'to ks query: '.join(' ', ($1..$2))."\n");
        last;
      }
    }
    # FIXME: can we do something to avoid hanging forever?
    waitpid($pid, 0);
    msvalog('debug', "ks query returns %d\n", POSIX::WEXITSTATUS($?));
  }

  sub reviewcert {
    my $data  = shift;
    my $clientinfo  = shift;
    return if !ref $data;

    my $status = '200 OK';
    my $ret =  { valid => JSON::false,
                 message => 'Unknown failure',
               };

    my $uid = getuid($data);
    if ($uid eq []) {
        msvalog('error', "invalid peer/context: %s/%s\n", $data->{context}, $data->{peer});
        $ret->{message} = sprintf('invalid peer/context');
        return $status, $ret;
    }

    my $rawdata = join('', map(chr, @{$data->{pkc}->{data}}));
    my $cert = Crypt::X509->new(cert => $rawdata);
    msvalog('verbose', "cert subject: %s\n", $cert->subject_cn());
    msvalog('verbose', "cert issuer: %s\n", $cert->issuer_cn());
    msvalog('verbose', "cert pubkey algo: %s\n", $cert->PubKeyAlg());
    msvalog('verbose', "cert pubkey: %s\n", unpack('H*', $cert->pubkey()));

    if ($cert->PubKeyAlg() ne 'RSA') {
      $ret->{message} = sprintf('public key was algo "%s" (OID %s).  MSVA.pl only supports RSA',
                                $cert->PubKeyAlg(), $cert->pubkey_algorithm);
    } else {
      my $key = $rsa_decoder->decode($cert->pubkey());
      if ($key) {
        # make sure that the returned integers are Math::BigInts:
        $key->{exponent} = Math::BigInt->new($key->{exponent}) unless (ref($key->{exponent}));
        $key->{modulus} = Math::BigInt->new($key->{modulus}) unless (ref($key->{modulus}));
        msvalog('debug', "cert info:\nmodulus: %s\nexponent: %s\n",
                $key->{modulus}->as_hex(),
                $key->{exponent}->as_hex(),
               );

        if ($key->{modulus}->copy()->blog(2) < 1000) { # FIXME: this appears to be the full pubkey, including DER overhead
          $ret->{message} = sprintf('public key size is less than 1000 bits (was: %d bits)', $cert->pubkey_size());
        } else {
          $ret->{message} = sprintf('Failed to validate "%s" through the OpenPGP Web of Trust.', $uid);
          my $lastloop = 0;
          msvalog('debug', "keyserver policy: %s\n", get_keyserver_policy);
          # needed because $gnupg spawns child processes
          $ENV{PATH} = '/usr/local/bin:/usr/bin:/bin';
          if (get_keyserver_policy() eq 'always') {
            fetch_uid_from_keyserver($uid);
            $lastloop = 1;
          } elsif (get_keyserver_policy() eq 'never') {
            $lastloop = 1;
          }
          my $foundvalid = 0;

          # fingerprints of keys that are not fully-valid for this User ID, but match
          # the key from the queried certificate:
          my @subvalid_key_fprs;

          while (1) {
            foreach my $gpgkey ($gnupg->get_public_keys('='.$uid)) {
              my $validity = '-';
              foreach my $tryuid ($gpgkey->user_ids) {
                if ($tryuid->as_string eq $uid) {
                  $validity = $tryuid->validity;
                }
              }
              # treat primary keys just like subkeys:
              foreach my $subkey ($gpgkey, @{$gpgkey->subkeys}) {
                my $primarymatch = keycomp($key, $subkey);
                if ($primarymatch) {
                  if ($subkey->usage_flags =~ /a/) {
                    msvalog('verbose', "key matches, and 0x%s is authentication-capable\n", $subkey->hex_id);
                    if ($validity =~ /^[fu]$/) {
                      $foundvalid = 1;
                      msvalog('verbose', "...and it matches!\n");
                      $ret->{valid} = JSON::true;
                      $ret->{message} = sprintf('Successfully validated "%s" through the OpenPGP Web of Trust.', $uid);
                    } else {
                      push(@subvalid_key_fprs, { fpr => $subkey->fingerprint, val => $validity }) if $lastloop;
                    }
                  } else {
                    msvalog('verbose', "key matches, but 0x%s is not authentication-capable\n", $subkey->hex_id);
                  }
                }
              }
            }
            if ($lastloop) {
              last;
            } else {
              fetch_uid_from_keyserver($uid) if (!$foundvalid);
              $lastloop = 1;
            }
          }

          my $resp = Crypt::Monkeysphere::MSVA::MarginalUI->ask_the_user($gnupg,
                                                                         $uid,
                                                                         \@subvalid_key_fprs,
                                                                         getpidswithsocketinode($clientinfo->{inode}));
          msvalog('info', "response: %s\n", $resp);
          if ($resp) {
            $ret->{valid} = JSON::true;
            $ret->{message} = sprintf('Manually validated "%s" through the OpenPGP Web of Trust.', $uid);
          }
        }
      } else {
        msvalog('error', "failed to decode %s\n", unpack('H*', $cert->pubkey()));
        $ret->{message} = sprintf('failed to decode the public key', $uid);
      }
    }

    return $status, $ret;
  }

  sub child_dies {
    my $self = shift;
    my $pid = shift;
    my $server = shift;

    msvalog('debug', "Subprocess %d terminated.\n", $pid);

    if (exists $self->{child_pid} &&
        ($self->{child_pid} == 0 ||
         $self->{child_pid} == $pid)) {
      my $exitstatus = POSIX::WEXITSTATUS($?);
      msvalog('verbose', "Subprocess %d terminated; exiting %d.\n", $pid, $exitstatus);
      $server->set_exit_status($exitstatus);
      $server->server_close();
    }
  }

  # use sparingly!  We want to keep taint mode around for the data we
  # get over the network.  this is only here because we want to treat
  # the command line arguments differently for the subprocess.
  sub untaint {
    my $x = shift;
    $x =~ /^(.*)$/ ;
    return $1;
  }

  sub post_bind_hook {
    my $self = shift;
    my $server = shift;

    my $socketcount = @{ $server->{server}->{sock} };
    if ( $socketcount != 1 ) {
      msvalog('error', "%d sockets open; should have been 1.", $socketcount);
      $server->set_exit_status(10);
      $server->server_close();
    }
    my $port = @{ $server->{server}->{sock} }[0]->sockport();
    if ((! defined $port) || ($port < 1) || ($port >= 65536)) {
      msvalog('error', "got nonsense port: %d.", $port);
      $server->set_exit_status(11);
      $server->server_close();
    }
    if ((exists $ENV{MSVA_PORT}) && (($ENV{MSVA_PORT} + 0) != $port)) {
      msvalog('error', "Explicitly requested port %d, but got port: %d.", ($ENV{MSVA_PORT}+0), $port);
      $server->set_exit_status(13);
      $server->server_close();
    }
    $self->port($port);

    my $argcount = @ARGV;
    if ($argcount) {
      $self->{child_pid} = 0; # indicate that we are planning to fork.
      my $fork = fork();
      if (! defined $fork) {
        msvalog('error', "could not fork\n");
      } else {
        if ($fork) {
          msvalog('debug', "Child process has PID %d\n", $fork);
          $self->{child_pid} = $fork;
        } else {
          msvalog('verbose', "PID %d executing: \n", $$);
          for my $arg (@ARGV) {
            msvalog('verbose', " %s\n", $arg);
          }
          # untaint the environment for the subprocess
          # see: https://labs.riseup.net/code/issues/2461
          foreach my $e (keys %ENV) {
            $ENV{$e} = untaint($ENV{$e});
          }
          my @args;
          foreach (@ARGV) {
            push @args, untaint($_);
          }
          # restore default SIGCHLD handling:
          $SIG{CHLD} = 'DEFAULT';
          $ENV{MONKEYSPHERE_VALIDATION_AGENT_SOCKET} = sprintf('http://localhost:%d', $self->port);
          exec(@args) or exit 111;
        }
      }
    } else {
      printf("MONKEYSPHERE_VALIDATION_AGENT_SOCKET=http://localhost:%d;\nexport MONKEYSPHERE_VALIDATION_AGENT_SOCKET;\n", $self->port);
      # FIXME: consider daemonizing here to behave more like
      # ssh-agent.  maybe avoid backgrounding by setting
      # MSVA_NO_BACKGROUND.
    };
  }

  sub extracerts {
    my $data = shift;

    return '500 not yet implemented', { };
  }

  1;
}
