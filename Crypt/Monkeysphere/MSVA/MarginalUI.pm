#----------------------------------------------------------------------
# Monkeysphere Validation Agent, Perl version
# Marginal User Interface for reasonable prompting
# Copyright © 2010 Daniel Kahn Gillmor <dkg@fifthhorseman.net>,
#                  Matthew James Goins <mjgoins@openflows.com>,
#                  Jameson Graef Rollins <jrollins@finestructure.net>,
#                  Elliot Winard <enw@caveteen.com>
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
#
#----------------------------------------------------------------------

{ package Crypt::Monkeysphere::MSVA::MarginalUI;

  use strict;
  use warnings;

  use Gtk2;
  use Crypt::Monkeysphere::MSVA qw( msvalog );

  sub ask_the_user {
    my $self = shift;
    my $gnupg = shift;
    my $uid = shift;
    my $fprs = shift;
    my @subvalid_key_fprs = @{$fprs};

    msvalog('debug', "%d subvalid_key_fprs\n", $#subvalid_key_fprs+1);
    foreach my $keyfpr (@subvalid_key_fprs) {
      my $fprx = sprintf('0x%.40s', $keyfpr->{fpr}->as_hex_string);
      msvalog('debug', "checking on %s\n", $fprx);
      foreach my $gpgkey ($gnupg->get_public_keys_with_sigs($fprx)) {
        msvalog('debug', "found key %.40s\n", $gpgkey->fingerprint->as_hex_string);
        # we're going to prompt the user here if we have any
        # relevant certifiers:
        my @valid_certifiers;
        my @marginal_certifiers;

        # FIXME: if there are multiple keys in the OpenPGP WoT
        # with the same key material and the same User ID
        # attached, we'll be throwing multiple prompts per query
        # (until the user selects one or cancels them all).
        # That's a mess, but i'm not sure what the better thing
        # to do is.
        foreach my $user_id ($gpgkey->user_ids) {
          msvalog('debug', "found EE User ID %s\n", $user_id->as_string);
          if ($user_id->as_string eq $uid) {
            # get a list of the certifiers of the relevant User ID for the key
            foreach my $cert (@{$user_id->signatures}) {
              if ($cert->hex_id =~ /^([A-Fa-f0-9]{16})$/) {
                my $certid = $1;
                msvalog('debug', "found certifier 0x%.16s\n", $certid);
                if ($cert->is_valid()) {
                  foreach my $certifier ($gnupg->get_public_keys(sprintf('0x%.40s!', $certid))) {
                    my $valid_cuid = 0;
                    my $marginal = undef;
                    foreach my $cuid ($certifier->user_ids) {
                      # grab the first full or ultimate user ID on
                      # this certifier's key:
                      if ($cuid->validity =~ /^[fu]$/) {
                        push(@valid_certifiers, { key_id => $cert->hex_id,
                                                  user_id => $cuid->as_string,
                                                } );
                        $valid_cuid = 1;
                        last;
                      } elsif ($cuid->validity =~ /^[m]$/) {
                        $marginal = { key_id => $cert->hex_id,
                                      user_id => $cuid->as_string,
                                    };
                      }
                    }
                    push(@marginal_certifiers, $marginal)
                      if (! $valid_cuid && defined $marginal);
                  }
                }
              } else {
                msvalog('error', "certifier ID does not fit expected pattern '%s'\n", $cert->hex_id);
              }
            }
          }
          # else ## do we care at all about other User IDs on this key?

          # We now know the list of fully/ultimately-valid
          # certifiers, and a separate list of marginally-valid
          # certifiers.
          if ($#valid_certifiers < 0) {
            msvalog('info', "No valid certifiers, so no marginal UI\n");
          } else {
            my $certifier_list = join("\n", map { sprintf("%s [%s]",
                                                          $_->{user_id},
                                                          $_->{key_id},
                                                         ) } @valid_certifiers);
            my $msg = sprintf("The matching key for [%s] is not %svalid.
----------
The certificate is certified by:

%s

Would you like to temporarily accept this certification?",
                              $uid,
                              ('m' == $keyfpr->{val} ? 'fully ' : ''),
                              $certifier_list,
                             );
            my $tip = sprintf("Peer: %s
Key fingerprint: 0x%.40s
GnuPG calculated validity: %s",
			      $uid,
                              $keyfpr->{fpr}->as_hex_string,
			      $keyfpr->{val},
                             );
            # FIXME: what about revoked certifications?
            # FIXME: what about expired certifications?
            # FIXME: what about certifications ostensibly made in the future?
            msvalog('info', "%s\n", $msg);
            msvalog('verbose', "%s\n", $tip);
            my $resp = prompt($uid, $msg, $tip);
            if ($resp) {
              return $resp;
            }
          }
          # FIXME: not doing anything with @marginal_certifiers
          # -- that'd be yet more queries to gpg :(
        }
      }
    }
    return 0;
  }

  sub prompt {
    my $peer = shift;
    my $labeltxt = shift;
    my $tip = shift;

    Gtk2->init();
    # create a new dialog with some buttons - one stock, one not.
    my $dialog = Gtk2::Dialog->new(sprintf('Monkeysphere validation agent [%s]', $peer),
				    undef,
				    [],
				    'gtk-no' => 'cancel',
				    'gtk-yes' => 'ok');



    my $label = Gtk2::Label->new($labeltxt);
    # make the text in the dialog box selectable
    $label->set('selectable', 1);
    $label->show();
    my $button = Gtk2::Button->new_from_stock('gtk-properties');
    $button->show();
    $button->signal_connect('clicked',
                            sub {
                              $button->hide();
 # FIXME: for some reason, $label->set_text($labeltxt."\n\n".$tip) throws this error:
 # Insecure dependency in eval_sv() while running with -T switch at Crypt/Monkeysphere/MSVA/MarginalUI.pm line 180.
 # the workaround here (remove, destroy, re-create) seems to work, though.
                              $dialog->get_content_area()->remove($label);
                              $label->destroy();
                              $label = Gtk2::Label->new($labeltxt."\n\n".$tip);
                              $label->set('selectable', 1);
                              $label->show();
                              $dialog->get_content_area()->add($label);
                            });

    my $tooltips = Gtk2::Tooltips->new();
    $tooltips->set_tip($label, $tip);
    $dialog->get_content_area()->add($label);
    $dialog->get_content_area()->add($button);
    my $resp = 0;

    my $icon_file = '/usr/share/pixmaps/monkeysphere-icon.png';

    $dialog->set_default_icon_from_file($icon_file)
      if (-r $icon_file);
    $dialog->set_default_response('cancel');

    my $response = $dialog->run();
    if ($response eq 'ok') {
      $resp = 1;
    }

    # we'll let the fact that the process is about to terminate
    # destroy the window.  so lazy!

    return $resp;
  }

  1;
}
