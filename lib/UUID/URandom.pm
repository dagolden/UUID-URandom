use 5.008;
use strict;
use warnings;

package UUID::URandom;
# ABSTRACT: UUIDs based on /dev/urandom or the Windows Crypto API

our $VERSION = '0.002';

use Exporter 5.57 qw/import/;
use Crypt::URandom 0.36 ();

our @EXPORT_OK = qw(
  create_uuid
  create_uuid_hex
  create_uuid_string
);

=func create_uuid

    my $uuid = create_uuid();

    # "\x95\x5a\xe4\x96\x8b\xb2\x45\x0b\x9c\x7e\x99\xf5\x01\xdf\x90\xfe"

This returns a new UUID as a 16 byte 'binary' string.

=cut

sub create_uuid {
    my $uuid = Crypt::URandom::urandom(16);
    vec( $uuid, 13, 4 ) = 0x4; # set UUID version
    vec( $uuid, 35, 2 ) = 0x2; # set UUID variant
    return $uuid;
}

=func create_uuid_hex

    my $uuid = create_uuid_hex();

    # "955ae4968bb2450b9c7e99f501df90fe"

This returns a new UUID as a 32-byte hexadecimal string.

=cut

sub create_uuid_hex {
    return unpack( "H*", create_uuid() );
}

=func create_uuid_string

    my $uuid = create_uuid_string();

    # "955ae496-8bb2-450b-9c7e-99f501df90fe"

This returns a new UUID in the 36-byte RFC-4122 canonical string
representation.  (N.B. The canonical representation is lower-case.)

=cut

sub create_uuid_string {
    return join "-", unpack( "H8H4H4H4H12", create_uuid() );
}

1;

=for Pod::Coverage

=head1 SYNOPSIS

    use UUID::URandom qw/create_uuid/;

    my $uuid = create_uuid();

=head1 DESCRIPTION

This module provides a portable, secure generator of
L<RFC-4122|https://tools.ietf.org/html/rfc4122> version 4
(random) UUIDs.  It is a thin wrapper around L<Crypt::URandom> to set
the UUID version and variant bits required by the RFC.

=head1 USAGE

No functions are exported by default.

=head1 FORK AND THREAD SAFETY

The underlying L<Crypt::URandom> is believed to be fork and thread safe.

=head1 SEE ALSO

There are a number of other modules that provide version 4 UUIDs.  Many
rely on insecure or non-crypto-strength random number generators.

=for :list
* L<Data::GUID::Any>
* L<Data::UUID::LibUUID>
* L<UUID>
* L<UUID::Tiny>
* L<Data::UUID::MT>

=cut

# vim: ts=4 sts=4 sw=4 et tw=75:
