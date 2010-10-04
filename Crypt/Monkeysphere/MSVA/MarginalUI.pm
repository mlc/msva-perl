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

  my $resp = 0;

  sub prompt {
    use Gtk2 '-init'; # auto-initializes Gtk2
    use Gtk2::GladeXML;

    my $glade;
    my $label;

    # populate UI from 
    $glade = Gtk2::GladeXML->new("Crypt/Monkeysphere/MSVA/MarginalUI.glade");

    # Connect the signals
    $glade->signal_autoconnect_from_package('Crypt::Monkeysphere::MSVA::MarginalUI');
    $label = $glade->get_widget('messageLabel');

    my $labeltxt = shift;
    $label->set_text($labeltxt);

    # Start it up
    Gtk2->main;

    return $resp;
  }

  sub on_yesButton_clicked {
    $resp = 1;
    Gtk2->main_quit;
  }
  sub on_noButton_clicked {
    Gtk2->main_quit;
  }

  1;
}
