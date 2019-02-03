#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Try REDOS attack on Perl

use strict;
use warnings;

use JSON::PP; # I/O
use Carp;

# Arg parsing.
my $queryFile = $ARGV[0];
if (not defined($queryFile)) {
  print "Error, usage: $0 query-file.json\n";
  exit 1;
}

# Load query from file.
&log("Loading query from $queryFile");
# NB This is a possible source of false positives.
# The outer wrapper assumes that the only potentially-slow phase is the actual regex evaluation.
# For very long input files (e.g. 10MB), just parsing the input file can take O(seconds).
my $query = decode_json(&readFile("file"=>$queryFile));

# Check query is valid.
my $validQuery = 1;
my @requiredQueryKeys = ('pattern', 'input');
for my $k (@requiredQueryKeys) {
  if (not defined($query->{$k})) {
    $validQuery = 0;
  }
};
if (not $validQuery) {
  &log("Error, invalid query. Need keys <@requiredQueryKeys>. Got " . encode_json($query));
  exit 1;
}

&log("Query is valid");

# Try to match string against pattern.
my $len = length($query->{input});
&log("matching: pattern /$query->{pattern}/ inputStr: len $len");

my $NO_REDOS_EXCEPT = "NO_REDOS_EXCEPT";
my $RECURSION_EXCEPT = "RECURSION_LIMIT";

my $matched = 0;
my $matchContents = {
  "matchedString" => "",
  "captureGroups" => []
};
my $except = $NO_REDOS_EXCEPT;
eval {

  # Exception handler
  local $SIG{__WARN__} = sub {
    my $recursionSubStr = "Complex regular subexpression recursion limit";
    my $message = shift;
    
    # if we got a recursion limit warning
    if (index($message, $recursionSubStr) != -1) {
      $except = $RECURSION_EXCEPT;
    }
    else {
      &log("warning: $message");
    }
  };

  # Perform the match
  if ($query->{input} =~ m/$query->{pattern}/) {
    $matched = 1;
    $matchContents->{matchedString} = $&; # I love perl

    if (defined $1) { # Were there any capture groups?
      my @matches = ($query->{input} =~ m/$query->{pattern}/);
      @matches = map { if (defined $_) { $_ } else { ""; } } @matches;
      $matchContents->{captureGroups} = \@matches;
    } else {
      $matchContents->{captureGroups} = [];
    }
  }
};

# this just catches all warnings -- can we specify by anything other than string text?
my $result = $query;
if ($@) {
  &log("Caught input exception: $@");
  &log("\$except: $except");
  if ($except eq $NO_REDOS_EXCEPT) {
    # An exception that wasn't ReDoS-related -- invalid pattern
    $result->{validPattern} = 0;
  } else {
    # ReDoS-related exception -- valid pattern
    $result->{validPattern} = 1;
  }
  $except = "INVALID_INPUT";
} else {
  # No exceptions -- valid pattern
  $result->{validPattern} = 1;
}

delete $result->{input}; # Might take a long time to print
$result->{inputLength} = $len;
$result->{matched} = $matched ? 1 : 0;
$result->{matchContents} = $matchContents;
$result->{exceptionString} = $except;

print encode_json($result) . "\n";
exit 0;

##################

sub log {
  my ($msg) = @_;
  my $now = localtime;
  print STDERR "$now: $msg\n";
}

# input: %args: keys: file
# output: $contents
sub readFile {
  my %args = @_;

	open(my $FH, '<', $args{file}) or confess "Error, could not read $args{file}: $!";
	my $contents = do { local $/; <$FH> }; # localizing $? wipes the line separator char, so <> gets it all at once.
	close $FH;

  return $contents;
}
