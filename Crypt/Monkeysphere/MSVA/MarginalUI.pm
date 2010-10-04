#----------------------------------------------------------------------
# marginalUI
#
# TODO: make the $heredoc a fucntion that takes the following args -
#    end entity uid - string
#    certifiers - list of certifiers
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
                if ($#valid_certifiers == -1) {
                  msvalog('info', "No valid certifiers, so no marginal UI\n");
                } else {
                  my $certifier_list = join("\n", map { sprintf("[%s] %s", $_->{key_id}, $_->{user_id}) } @valid_certifiers);
                  my $msg = sprintf("The matching key we found for [%s] is not %svalid.\n(Key Fingerprint: 0x%.40s)\n----\nBut it was certified by the following folks:\n%s",
                                    $uid,
                                    ('m' == $keyfpr->{val} ? 'fully ' : ''),
                                    $keyfpr->{fpr}->as_hex_string,
                                    $certifier_list,
                                   );
                  # FIXME: what about revoked certifications?
                  # FIXME: what about expired certifications?
                  # FIXME: what about certifications ostensibly made in the future?
                  msvalog('info', "%s\n", $msg);
                  my $resp = prompt($msg);
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
    my $labeltxt = shift;

    Gtk2->init();
    # create a new dialog with some buttons - one stock, one not.
    my $dialog = Gtk2::Dialog->new ('msva-perl prompt!', undef, [],
                                    'gtk-cancel' => 'cancel',
                                    'Lemme at it!' => 'ok');
    my $label = Gtk2::Label->new($labeltxt);
    $label->show();
    $dialog->get_content_area()->add($label);
    my $resp = 0;

    $dialog->set_default_response ('cancel');

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
