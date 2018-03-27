#!/usr/bin/env perl

use strict;
use warnings;

use File::Basename;

my @languages = glob("../src/*");
chomp @languages;
@languages = map { basename $_ } @languages;
print "languages @languages\n";

my @tcs = glob("generic/*");
chomp @tcs;
@tcs = map { basename $_ } @tcs;
print "tcs @tcs\n";

for my $tc (@tcs) {
  my $cont = &readFile("file"=>"generic/$tc");
  for my $lang (@languages) {
    mkdir $lang;
    my $newCont = $cont;
    $newCont =~ s/LANGUAGE/$lang/;
    &writeToFile("file"=>"$lang/$tc", "contents"=>$newCont);
  }
}

print "I populated languages <@languages>\n";
exit 0;

############

# input: %args: keys: file
# output: $contents
sub readFile {
  my %args = @_;

	open(my $FH, '<', $args{file}) or die "Error, could not read $args{file}: $!";
	my $contents = do { local $/; <$FH> }; # localizing $? wipes the line separator char, so <> gets it all at once.
	close $FH;

  return $contents;
}

# input: %args: keys: file contents
# output: $file
sub writeToFile {
  my %args = @_;

	open(my $fh, '>', $args{file});
	print $fh $args{contents};
	close $fh;

  return $args{file};
}
