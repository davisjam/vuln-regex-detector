#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Validate a possible catastrophic backtracking vulnerability.
#
# Requirements:
#   - VULN_REGEX_DETECTOR_ROOT must be defined

use strict;
use warnings;

use JSON::PP;

# Check dependencies.

if (not defined $ENV{VULN_REGEX_DETECTOR_ROOT}) {
  die "Error, VULN_REGEX_DETECTOR_ROOT must be defined\n";
}

# Map extension to validator
my $pref = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/validate/src";
my %language2validator = (
  "javascript" => "$pref/javascript/query-node.js",
  "python"     => "$pref/python/query-python.py",
  "php"        => "$pref/php/query-php.php",
  "ruby"       => "$pref/ruby/query-ruby.rb",
  "perl"       => "$pref/perl/query-perl.pl",
  "rust"       => "$pref/rust/query-rust",
);

for my $ext (keys %language2validator) {
  if (not -x $language2validator{$ext}) {
    die "Error, could not find regexp extractor for extension $ext: not executable <$language2validator{$ext}>\n";
  }
}

# Check usage
if (not @ARGV) {
  die "Usage: $0 desc.json\n";
}

# Parse args
my $jsonFile = $ARGV[0];
if (not -f $jsonFile) {
  die "Error, no such file $jsonFile\n";
}
my $json = decode_json(`cat $jsonFile`);

for my $key ("language", "pattern", "evilInput", "nPumps", "timeLimit") {
  if (not defined($json->{$key})) {
    die "Error, undefined field: <$key>\n";
  }
}
if (not exists $language2validator{$json->{language}}) {
  die "Error, unsupported language $json->{language}\n";
}

# Make sure integer types are correct.
$json->{nPumps} = int($json->{nPumps});
$json->{timeLimit} = int($json->{timeLimit});

my $result = $json;
$result->{timedOut} = 0;

# Compute an attackString from evilInput.
# If the detector recommended a cubic or higher (>= 2 pumpPairs), try all polynomial powers
# by working our way up the list of pumpPairs.
# See https://github.com/NicolaasWeideman/RegexStaticAnalysis/issues/11.
my @pumpPairs = @{$json->{evilInput}->{pumpPairs}};
for my $nPumpPairsToTry (1 .. scalar(@pumpPairs)) {
  my $attackString = "";
  for my $pumpPair (@pumpPairs[0 .. $nPumpPairsToTry-1]) {
    $attackString .= $pumpPair->{prefix};
    $attackString .= ($pumpPair->{pump} x $json->{nPumps});
  }
  $attackString .= $json->{evilInput}->{suffix};

  # Prep an input file.
  my $input = { "pattern" => $json->{pattern},
                "input"   => $attackString,
              };
  my $tmpFile = "/tmp/validate-vuln-$$.json";
  &writeToFile("file"=>$tmpFile, "contents"=>encode_json($input));

  # Invoke the appropriate validator.
  my $validator = $language2validator{$json->{language}};

  # Use KILL because Ruby blocks TERM during regex match (??).
  my ($rc, $deathSignal, $out) = &cmd("timeout --signal=KILL $json->{timeLimit}s $validator $tmpFile");
  #unlink $tmpFile;
  # On timeout, rc is 124 if using TERM and 128+9 if using KILL
  # The right-shift of 8 in &cmd turns 128+9 into 9
  my $timedOut = ($rc eq 124 or $deathSignal eq 9) ? 1 : 0;
  &log("rc $rc timedOut $timedOut");

  if ($timedOut) {
    $result->{timedOut} = 1;
  }
}

print STDOUT encode_json($result) . "\n";
exit 0;

######################

# input: %args: keys: file contents
# output: $file
sub writeToFile {
  my %args = @_;

	open(my $fh, '>', $args{file});
	print $fh $args{contents};
	close $fh;

  return $args{file};
}

# returns ($rc, $deathSignal, $out)
sub cmd {
  my ($cmd) = @_;
  &log($cmd);
  my $out = `$cmd`;

  my $deathSignal = $? & 127;
  my $rc = $? >> 8;

  return ($rc, $deathSignal, $out);
}

sub log {
  my ($msg) = @_;
  print STDERR "$msg\n";
}
