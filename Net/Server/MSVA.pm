#!/usr/bin/perl -wT

# Net::Server implementation for Monkeysphere Validation Agent
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

{ package Net::Server::MSVA;
  use strict;
  use base qw(Net::Server::Fork);

  my $msva;
  # guarantee initial failure -- this will be cleared after we bind
  # successfully.
  my $exit_status = 13;

  sub post_bind_hook {
    my $self = shift;
    # if we got here, then the binding was successful.
    $exit_status = 0;
    $msva->post_bind_hook($self, @_);
  }

  sub set_exit_status {
    my $self = shift;
    $exit_status = shift;
  }

  # FIXME: this is an override of an undocumented interface of
  # Net::Server.  it would be better to use a documented hook, if
  # https://rt.cpan.org/Public/Bug/Display.html?id=55485 was resolved
  sub delete_child {
    my $self = shift;
    my $pid = shift;

    $msva->child_dies($pid, $self);
    $self->SUPER::delete_child($pid, @_);
  }

  sub server_exit {
    my $self = shift;
    exit $exit_status;
  }

  sub run {
    my $self = shift;
    my $options = { @_ };
    if (exists $options->{msva}) {
      $msva = $options->{msva};
    };
    $self->SUPER::run(@_);
  }

  1;
}
