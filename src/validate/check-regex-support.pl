#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Check if a regex is supported in a language
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
  "go"         => "$pref/go/query-go",
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

for my $key ("language", "pattern") {
  if (not defined($json->{$key})) {
    die "Error, undefined field: <$key>\n";
  }
}
if (not exists $language2validator{$json->{language}}) {
  die "Error, unsupported language $json->{language}\n";
}

my $result = $json;

# Prep an input file.
my $input = { "pattern" => $json->{pattern}, # What matters is whether the pattern works
              "input"   => "a" # We don't care about this, but this is the vrd driver API
            };
my $tmpFile = "/tmp/validate-vuln-$$.json";
&writeToFile("file"=>$tmpFile, "contents"=>encode_json($input));

# Invoke the appropriate validator.
my $validator = $language2validator{$json->{language}};

my ($rc, $deathSignal, $out) = &cmd("$validator $tmpFile");
&log("rc $rc out\n  $out");
unlink $tmpFile;

# Was the regex valid?
my $validatorRes = decode_json($out);
$result->{validPattern} = $validatorRes->{validPattern};

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
