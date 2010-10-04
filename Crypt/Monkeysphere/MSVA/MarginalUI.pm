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
