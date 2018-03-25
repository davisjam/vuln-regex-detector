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
my $query = decode_json(&readFile("file"=>$queryFile));

# Check query is valid.
my $validQuery = 1;
my @requiredQueryKeys = ('pattern', 'evilInput', 'nPumps');
for my $k (@requiredQueryKeys) {
  if (not defined($query->{$k})) {
    $validQuery = 0;
  }
};
if (not $validQuery) {
  &log("Error, invalid query. Need keys <@requiredQueryKeys>. Got " . encode_json($query));
  exit 1;
}

my @requiredEvilInputKeys = ('pumpPairs', 'suffix');
for my $k (@requiredEvilInputKeys) {
  if (not defined($query->{evilInput}->{$k})) {
    $validQuery = 0;
  }
};
if (!$validQuery) {
  &log("Error, invalid query. evilInput needs keys <@requiredEvilInputKeys>. Got " . encode_json($query->{evilInput}));
  exit 1;
}

&log("Query is valid");

# Compose evilInputStr based on query.evilInput.
my $evilInputStr = '';
for my $pair (@{$query->{evilInput}->{pumpPairs}}) {
  $evilInputStr .= $pair->{prefix};
  for (my $i = 0; $i < $query->{nPumps}; $i++) {
    $evilInputStr .= $pair->{pump};
  }
};
$evilInputStr .= $query->{evilInput}->{suffix};

# Try to match string against pattern.
my $len = length($evilInputStr);
&log("matching: pattern /$query->{pattern}/ nPumps $query->{nPumps} evilInputStr: len $len value <$evilInputStr>");

my $matched;
my $except = "NO_EXCEPT";
eval {

  local $SIG{__WARN__} = sub {
    my $recursionSubStr = "Complex regular subexpression recursion limit";
    my $message = shift;
    
    # if we got a recusion limit warning
    if (index($message, $recursionSubStr) != -1) {
      $except = "RECURSION_LIMIT";
    }
    else {
      &log("warning: $message");
    }
  };

  $matched = $evilInputStr =~ m/$query->{pattern}/;
};

# this just catches all warnings -- can we specify by anything other than string text?
if ($@) {
  &log("Caught input exception: $@");
  $except = "INVALID_INPUT";
}

my $result = $query;
$result->{inputLength} = $len;
$result->{matched} = $matched ? 1 : 0;
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
