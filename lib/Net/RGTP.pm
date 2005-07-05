# Net::RGTP                    -*- cperl -*-
#
# This program is free software; you may distribute it under the same
# conditions as Perl itself.
#
# Copyright (c) 2005 Thomas Thurman <marnanel@marnanel.org>

################################################################

package Net::RGTP;

use strict;
use warnings;
use vars qw(@ISA $VERSION);

use Socket 1.3;
use IO::Socket;
use Net::Cmd;
use Digest::MD5 qw(md5_hex);

$VERSION = '0.02';
@ISA     = qw(Exporter Net::Cmd IO::Socket::INET);

use constant GROGGS => 'rgtp-serv.groggs.group.cam.ac.uk';
use constant RGTP => 'rgtp(1431)';

################################################################

sub new
{
  my $package  = shift;
  my %args  = @_;

  my $self = $package->SUPER::new(PeerAddr => $args{Host} || GROGGS, 
				  PeerPort => $args{Port} || RGTP,
				  LocalAddr => $args{'LocalAddr'},
				  Proto    => 'tcp',
				  Timeout  => defined $args{Timeout}? $args{Timeout}: 120
				 ) or return undef;

  $self->debug(1) if $args{'Debug'};

  $self->response() or die "Couldn't get a response from the server";

  ${*$self}{'net_rgtp_groggsbug'} = $self->message =~ /GROGGS system/;
  
  die "Not an RGTP server" if $self->code()<230 || $self->code()>232;

  $self->_set_alvl;

  $self;
}

sub access_level {
  my $self = shift;

  return ${*$self}{'net_rgtp_status'};
}

sub motd {
  my $self = shift;

  $self->command('MOTD');
  $self->_read_item(no_parse_headers=>1,
		    motd=>1);
}

sub item {
  my ($self, $itemid) = @_;

  return $self->motd if $itemid eq 'motd';

  _is_valid_itemid($itemid);

  $self->command('ITEM', $itemid);
  $self->_read_item;
}

sub login {
  my ($self, $userid, $secret) = @_;

  $self->command("USER $userid");
  $self->response;

  # Did they let us in for just saying who we were?
  if ($self->code >= 230 && $self->code <= 233) {
    die 'Unexpected lack of security-- possible man in the middle attack?'
      if defined $secret;
    
    $self->_set_alvl;

    return;
  }

  die "Already logged in" if $self->code eq '500';
  die "Unexpected code" if $self->code ne '130';

  my ($algorithm) = $self->message =~ /^(.*?) /;
  die "Unknown algorithm: $algorithm" unless $algorithm eq 'MD5';

  $self->response;
  die "Unexpected code" if $self->code ne '333';
  my ($server_nonce) = $self->message =~ /([a-zA-Z0-9]{32})/;
  $server_nonce = pack("H*", $server_nonce);

  $secret = pack("H*", $secret);

  my $flipped_secret = '';
  for (my $i=0; $i<length($secret); $i++) {
    $flipped_secret .= chr((~ord(substr($secret,$i,1)) & 0xFF));
  }

  my $munged_userid = substr($userid, 0, 16);
  while (length($munged_userid)<16) {
    $munged_userid .= chr(0);
  }

  my $client_nonce = 'SIXTEEN BYTES...';
  my $client_hash = md5_hex($client_nonce,
			    $server_nonce,
			    $munged_userid,
			    $flipped_secret);
  
  my $server_hash = md5_hex($server_nonce,
			    $client_nonce,
			    $munged_userid,
			    $secret);
  
  # Now we prove to the server that we know the secret...
  
  $self->command('AUTH', $client_hash, unpack('H*',$client_nonce));

  # ...and it proves the same to us.

  $self->response;
    
  die "server failed to authenticate to us"
    unless $server_hash eq substr(lc($self->message), 0, 32);

  $self->response;

  $self->_set_alvl;
}

sub items {
  my $self = shift;
  my $latest_seq = 0;

  if (defined ${*$self}{'net_rgtp_latest'}) {
    $self->command('INDX', sprintf('#%08x', ${*$self}{'net_rgtp_latest'}+1));
  } else {
    $self->command('INDX');
    ${*$self}{'net_rgtp_index'} = {};
  }

  $self->response;

  die "No reading access" if $self->code eq '531';
  die "Unexpected code" unless $self->code eq '250';

  for my $line (@{$self->read_until_dot}) {
    my $seq = hex(substr($line, 0, 8));
    my $timestamp = hex(substr($line, 9, 8));
    my $itemid = substr($line, 18, 8);
    my $from = substr($line, 27, 75);
    my $type = substr($line, 103, 1);
    my $subject = substr($line, 105);
      
    $from =~ s/\s*$//;
    $subject =~ s/\s*$//;

    if ($type eq 'M') {
      $itemid = 'motd';
      $subject = 'Message of the Day';
      $type = 'I';
    }

    if ($type eq 'C') {
      ${*$self}{'net_rgtp_childlink'} = $itemid;
    } elsif ($type eq 'F') {
      if (defined ${*$self}{'net_rgtp_childlink'}) {
	${*$self}{'net_rgtp_index'}{ ${*$self}{'net_rgtp_childlink'} }{'child'} = $itemid;
	${*$self}{'net_rgtp_index'}{ $itemid }{'parent'} = ${*$self}{'net_rgtp_childlink'};
	delete ${*$self}{'net_rgtp_childlink'};
      }
    }
    
    if ($type eq 'R' or $type eq 'I' or $type eq 'C') {
      ${*$self}{'net_rgtp_index'}{ $itemid }{'subject'} = $subject;
      ${*$self}{'net_rgtp_index'}{ $itemid }{'posts'}++;
      ${*$self}{'net_rgtp_index'}{ $itemid }{'timestamp'} = $timestamp;
      ${*$self}{'net_rgtp_index'}{ $itemid }{'seq'} = $seq;
    }

    $latest_seq = $seq if $seq > $latest_seq;
	
  }

  ${*$self}{'net_rgtp_latest'} = $latest_seq;

  ${*$self}{'net_rgtp_index'};

}

sub state {
  my ($self, $setting) = @_;

  if (defined $setting) {
    if (defined $setting->{'latest'}) {
      ${*$self}{'net_rgtp_latest'} = $setting->{'latest'};
      ${*$self}{'net_rgtp_index'}  = $setting->{'index'};
    } else {
      delete ${*$self}{'net_rgtp_latest'};
      delete ${*$self}{'net_rgtp_index'};
    }
  } else {
    if (defined ${*$self}{'net_rgtp_latest'}) {
      return {
	      latest => ${*$self}{'net_rgtp_latest'},
	      index  => ${*$self}{'net_rgtp_index'},
	     };
    } else {
      return {
	      index  => {},
	     };
    }
  }
}

################################################################
# INTERNAL ROUTINES

sub _read_item {
  my $self = shift;
  my %args = @_;
  my %result = ();
  my @responses = ();
  my $current_response = ();
  my ($seq, $timestamp);

  $self->response;
  die "No reading access" if $self->code eq '531';
  return undef            if $self->code eq '410';
  die "Unexpected code"   unless $self->code eq '250';

  my $status = $self->getline;

  if ($args{'motd'}) {	
    ($seq, $timestamp) =
      $status =~ /^([0-9a-fA-F]{8}|\s{8}) ([0-9a-fA-F]{8})/;
    
    if (${*$self}{'net_rgtp_groggsbug'}) {
      # They have it backwards!
      $result{'seq'} = hex($timestamp);
      $result{'timestamp'} = hex($seq);
    } else {
      $result{'seq'} = hex($seq);
      $result{'timestamp'} = hex($timestamp);
    }
  } else {
    my ($parent, $child, $edit, $reply) =
      $status =~ /^([A-Za-z]\d{7}|\s{8}) ([A-Za-z]\d{7}|\s{8}) ([0-9a-fA-F]{8}|\s{8}) ([0-9a-fA-F]{8})/;
    
    $result{'parent'} = $parent    if $parent ne '        ';
    $result{'child' } = $child     if $child  ne '        ';
    $result{'edit'  } = hex($edit) if $edit   ne '        ';
    $result{'reply' } = hex($reply);
  }

  for my $line (@{$self->read_until_dot}) {
    if (($seq, $timestamp) = $line =~ /^\^([0-9a-fA-F]{8}) ([0-9a-fA-F]{8})/) {
      push @responses, $current_response if $current_response;
      $current_response = { seq=>hex($seq), timestamp=>hex($timestamp) };
      
    } else {
      $line =~ s/^\^\^/\^/;
      $current_response->{'text'} .= $line;
    }
  }

  push @responses, $current_response;

  unless ($args{'no_parse_headers'}) {
    for my $response (@responses) {
      my $username;
      if (($username) = $response->{'text'} =~ /^.* from (.*) at .*\n/) {
	
	if ($username =~ /\(.*\)$/) {
	  ($response->{'grogname'}, $response->{'poster'}) =
	    $username =~ /^(.*) \((.*)\)$/;
	} else {
	  $response->{'poster'} = $username;
	  if ($response->{'text'} =~ /From (.*)\n/) {
	    $response->{'grogname'} = $1;
	  }
	}
	
      }
	    
      if ($response->{'text'} =~ /Subject: (.*)\n/) {
	$result{'subject'} = $1;
      }
	    
      $response->{'text'} =~ s/^(.|\r|\n)*?\r?\n\r?\n//;
    }
  }

  $result{'posts'} = \@responses;

  if ($args{'motd'}) {	
    $result{'posts'}[0]->{'seq'} = delete $result{'seq'};
    $result{'posts'}[0]->{'timestamp'} = delete $result{'timestamp'};
  }

  \%result;
}

sub _is_valid_itemid {
  die "Invalid itemid" unless shift =~ /^[A-Za-z]\d{7}$/;
}

sub _set_alvl {
  my $self = shift;

  die "Expected status response"
    if $self->code()<230 || $self->code()>233;

  ${*$self}{'net_rgtp_status'} = $self->code()-230;
}

1;

__END__

=head1 NAME

  Net::RGTP - Reverse Gossip client

=head1 SYNOPSIS

  use Net::RGTP;

  my $rgtp = Net::RGTP->new(Host=>'gossip.example.com')
    or die "Cannot connect to RGTP server!";

  $rgtp->login('spqr1@cam.ac.uk', 'DEADBEEFCAFEF00D');

  for my $itemid (keys %{$rgtp->items}) {
    my $item = $rgtp->item($itemid);

    print $itemid, ' ', $item->{'subject'}, ' has ',
      scalar(@{$item->{'text'}}),
      " posts.\n";
  }

=head1 DESCRIPTION

C<Net::RGTP> is a class implementing the RGTP bulletin board protocol,
as used in the Cambridge University GROGGS system. At present it provides
read-only access only.

Future versions of this package will include posting, editing and
registration capabilities.

=head1 OVERVIEW

RGTP stands for Reverse Gossip Transfer Protocol. An RGTP board, such
as GROGGS, consists essentially of a set of "items", each denoted by
an eight-character itemid such as "A1240111". An item consists of a
sequence of posts on a given subject, identified by a subject string
attached to the item. When an item has reached a certain size,
attempting to post to it will instead generate a new item, known as
a "continuation" or "child" item, with a new itemid and subject string.
RGTP keeps track of which items are children of which parent items,
thus allowing long chains of discussion to be built.

The first character of itemids was "A" in 1986, the first year of
GROGGS's existence, and has been incremented through the alphabet every
year since.

Every user is identified to RGTP by their email address. They are usually
identified to the other users by a string known as their "grogname". (These
are usually fanciful, and regular contests are held as to the best ones.)

Every action which causes a state change on an RGTP server is given a
monotonically increasing sequence number. Most actions are also given
timestamps. These are in seconds since midnight UTC, 1 January 1970.

=head1 CONSTRUCTOR

=over 4

=item new ([ OPTIONS ])

This is the constructor for a new Net::RGTP object. C<OPTIONS> are passed
in a hash-like fashion, using key and value pairs. Possible options are:

B<Host> - the name of the RGTP server to connect to. If this is omitted,
it will default to C<rgtp-serv.groggs.group.cam.ac.uk>.

B<Port> - the port number to connect to. If this is omitted, it will default
to 1471, the IANA standard number for RGTP.

B<Debug> - set this to 1 if you want the traffic between the server and
client to be printed to stderr. This does not print the contents of
files (e.g. the index, or items) as they transfer.

=back

=head1 METHODS

=over 4

=item login (USERID [, SECRET])

Logs in to the RGTP server. SECRET is the shared-secret which is sent out
by mail. It should be undef only if you are expecting not to have to go through
authentication (for example, many RGTP servers have an account called "guest"
which needs no authentication step).

=item access_level

Returns the current access level. 0 means only the message of the day
may be read. 1 means the index and any item may be read, but nothing
may be written. 2 means that items may be posted to. 3 means that the
contents of the items, including posts made by other users, may be
edited.

=item motd

Returns a hashref containing only the key B<posts>, which maps to an
arrayref containing only one element, a hashref which contains three
keys:

B<seq>: the sequence number of the message of the day;

B<text>: the text of the message of the day; and

B<timestamp>: the time the message of the day was last set.

The reason for the baroque formatting is that it matches the format
of the response of the C<item> method.

Returns C<undef> if there is no message of the day.

=item item(ITEMID)

Returns a hashref which may if applicable contain the keys:

B<parent>, which is the itemid of the given item's parent;

B<child>, which is the itemid of the given item's child; 

B<subject>, which is the subject line of the given item;

B<reply>, which is the sequence number of the most recent reply
to the given item; and

B<edit>, which is the sequence number of the most recent edit.
(That is, an edit by an editor, not an ordinary reply.)

The hashref will always contain a key B<posts>. This maps to an
arrayref of hashrefs, each representing a post to this item.
Each hashref may if applicable contain the keys:

B<seq>, which is the sequence number of this post;

B<timestamp>, which is the timestamp of this post;

B<grogname>, which is the grogname of the poster; and

B<poster>, which is the user ID of the poster (that is, their email address).

There will also always be a key B<text>, which contains the text of the post.

C<item> returns C<undef> if the item does not exist.

As a special case, item("motd") is equivalent to calling the C<motd> method.

=item items

Returns a hashref describing every item on the current server.

The keys of the hashref are the itemids of the several items,
except for the key "motd", which describes the message of the day.
Each key maps to a hash describing the item. The keys of this hash are:

B<subject>: the subject line of the item. This may be truncated by
the RGTP server; you may find the exact subject line using the C<item>
method.

B<posts>: a count of posts.

B<timestamp>: the timestamp of the most recent change to this item.

B<seq>: the sequence number of the most recent change to this item.

B<parent>: the itemid of the parent of this item. Exists only for items
which have a parent.

B<child>: the itemid of the child of this item. Exists only for items
which have a child.

This method may take a long time to execute on popular RGTP servers
the first time it is called. This is because it has to download the
entire index. Subsequent calls will use cached data and will be faster.
See also the C<state> method.

=item state([STATE])

This method exists because the C<items> method is slow on first use.
(Over my home connection, for the main GROGGS server, it takes about
forty seconds). When called with no arguments, C<state> returns a
scalar describing the state of C<items>'s cache. When called with
this scalar as argument, it re-fills the cache with this data. This
scalar can be seralised so that the advantages of caching can be
gained between sessions.

=head1 UNIMPLEMENTED

The following aspects of RGTP have not been implemented. This will
be addressed in a later revision:

=over 4

=item Posting

Anything to do with posting items.

=item Registration

Creating new user accounts.

=item Editing

Using superuser powers to modify other people's comments.

=head1 AUTHOR

Thomas Thurman <marnanel@marnanel.org>

=head1 CREDITS

Firinel Taranen - for being there to bounce ideas off, and, well, everything.

John Stark - for inventing GROGGS.

Ian Jackson - for inventing RGTP.

Tony Finch - whose RGTP to Atom converter made the idea of this module click
for me.

=head1 SEE ALSO

The RGTP protocol, at
 http://www.groggs.group.cam.ac.uk/protocol.txt .

The GROGGS home page, at
 http://www.groggs.group.cam.ac.uk/ .

Yarrow, a CGI RGTP client, at
 http://rgtp.thurman.org.uk/gossip/groggs/browse .

GREED, an Emacs RGTP client, at
 http://www.chiark.greenend.org.uk/~owend/free/GREED.html .

=head1 COPYRIGHT

Copyright (c) 2005 Thomas Thurman. All rights reserved.
This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut
