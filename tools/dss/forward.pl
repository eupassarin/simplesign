#!/usr/bin/perl
# Listens on 127.0.0.1:PORT inside the container and forwards every connection to HOST:PORT.
#
# The SimpleSign Sandbox writes http://localhost:5300 (and :5301 for HTTPS, :5302 for LDAP) into
# its certificates, and SimpleSign only lets a request to a private address through when it is
# loopback. Inside the container "localhost" is the container itself, so without this DSS could
# not fetch the Sandbox's CRLs, OCSP responses and certificates. entrypoint.sh starts one per port.
#
#   perl forward.pl 5300 host.docker.internal
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;

my ($port, $host) = @ARGV;
die "usage: forward.pl PORT HOST\n" unless $port && $host;
$SIG{CHLD} = 'IGNORE';

my $listener = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => $port, Listen => 64, ReuseAddr => 1)
    or die "[dss] cannot listen on 127.0.0.1:$port: $!\n";

while (my $client = $listener->accept) {
    my $pid = fork;
    if (!defined $pid || $pid) {
        close $client;
        next;
    }

    close $listener;
    my $upstream = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Timeout => 10) or exit 0;
    my $select = IO::Select->new($client, $upstream);
    COPY: while (1) {
        for my $from ($select->can_read) {
            my $read = sysread($from, my $buffer, 65536);
            last COPY unless $read;
            my $to = $from == $client ? $upstream : $client;
            my $offset = 0;
            while ($offset < $read) {
                my $written = syswrite($to, $buffer, $read - $offset, $offset);
                last COPY unless $written;
                $offset += $written;
            }
        }
    }

    exit 0;
}
