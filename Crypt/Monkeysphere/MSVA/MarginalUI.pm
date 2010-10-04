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
  use Gtk2 '-init';

  sub prompt {
    my $labeltxt = shift;

    # create a new dialog with some buttons - one stock, one not.
    my $dialog = Gtk2::Dialog->new ('msva-perl prompt!', undef, qw( modal ),
                                    'gtk-cancel' => 'cancel',
                                    'Lemme at it!' => 'ok');
    my $label = Gtk2::Label->new($labeltxt);
    $label->show();
    $dialog->get_content_area()->add($label);
    my $resp = 0;

    $dialog->set_default_response ('cancel');

    # show and interact modally -- blocks until the user
    # activates a response.
    my $response = $dialog->run();
    if ($response eq 'ok') {
      $resp = 1;
    }

    $dialog->hide();
    # activating a response does not destroy the window,
    # that's up to you.
    $dialog->destroy();

    return $resp;
  }

  1;
}
