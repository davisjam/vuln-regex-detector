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

# Make sure integer types are correct.
$json->{nPumps} = int($json->{nPumps});
$json->{timeLimit} = int($json->{timeLimit});

# Compute an attackString from evilInput.
my $attackString = "";
for my $pumpPair (@{$json->{evilInput}->{pumpPairs}}) {
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

my ($rc, $out) = &cmd("timeout $json->{timeLimit}s $validator $tmpFile");
unlink $tmpFile;
my $timedOut = ($rc eq 124) ? 1 : 0;

my $result = $json;
$result->{timedOut} = $timedOut;

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

sub cmd {
  my ($cmd) = @_;
  my $out = `$cmd`;
  my $rc = $? >> 8;

  return ($rc, $out);
}
