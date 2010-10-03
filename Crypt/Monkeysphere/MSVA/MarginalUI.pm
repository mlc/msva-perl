#!/usr/bin/perl -w

#----------------------------------------------------------------------
# marginalUI
#
# TODO: make the $heredoc a fucntion that takes the following args -
#    end entity uid - string
#    certifiers - list of certifiers
#
#----------------------------------------------------------------------

{ package MSVA::MarginalUI;

use strict;
use warnings;

use Gtk2 '-init'; # auto-initializes Gtk2
use Gtk2::GladeXML;

my $glade;
my $label;

# populate UI from 
$glade = Gtk2::GladeXML->new("MSVA/MarginalUI.glade");

# Connect the signals
$glade->signal_autoconnect_from_package('main');

$label = $glade->get_widget('messageLabel');
my $labeltxt = <<'END';
pub   4096R/E27BAABC 2007-01-08 [expires: 2012-01-07] 
uid       [  full  ] Jameson Graef Rollins <jrollins@finestructure.net> 
uid       [  full  ] Jameson Graef Rollins <jrollins@phys.columbia.edu>
uid       [  full  ] Jameson Graef Rollins <jrollins@fifthhorseman.net>
uid       [  full  ] Jameson Graef Rollins <jrollins@astro.columbia.edu>
uid       [  full  ] Jameson Rollins <jrollins@fifthhorseman.net>
uid       [  full  ] Jameson Graef Rollins <jameson.rollins@ligo.org>
uid       [  full  ] [jpeg image of size 4097]
uid       [marginal] Jameson Rollins <jrollins@finestructure.net>
sub   4096R/1321E689 2007-01-09 [expires: 2012-01-08]
sub   2048R/4414A10A 2008-06-18 [expires: 2013-06-17]

Do you trust this dude?
END
$label->set_text($labeltxt);

# Start it up
Gtk2->main;

exit 0;

sub on_yesButton_clicked {
    exit 0;
}
sub on_noButton_clicked {
    exit 1;
}

1;

}
