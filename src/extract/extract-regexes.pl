#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Route an 'extract-regexps' request to the appropriate language handler based on file extension
#  Prints to STDOUT a JSON object with keys:
#    regexps[]: an array of objects, each with keys: pattern flags
#               pattern and flags are each either a string or 'DYNAMIC-{PATTERN|FLAGS}' 
#  Additional keys are OK.
#
# Requirements:
#   - VULN_REGEX_DETECTOR_ROOT must be defined

use strict;
use warnings;

use JSON::PP;

# Globals.
my $UNKNOWN_LANGUAGE = "UNKNOWN_LANGUAGE";

# Check dependencies.

if (not defined $ENV{VULN_REGEX_DETECTOR_ROOT}) {
  die "Error, VULN_REGEX_DETECTOR_ROOT must be defined\n";
}

# Map extension to regexp extractor
my $pref = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/extract/src";
my %language2extractor = (
  "javascript" => "$pref/javascript/extract-regexps.js",
  "python"     => "$pref/python/python-extract-regexps-wrapper.pl",
);

for my $lang (keys %language2extractor) {
  if (not -x $language2extractor{$lang}) {
    die "Error, could not find regexp extractor for lang $lang: not executable <$language2extractor{$lang}>\n";
  }
}

# Check usage

if (not @ARGV) {
  die "Usage: $0 desc.json\n";
}

my $jsonFile = $ARGV[0];
if (not -f $jsonFile) {
  die "Error, no such file $jsonFile\n";
}
my $json = decode_json(`cat $jsonFile`);

for my $key ("file") {
  if (not defined($json->{$key})) {
    die "Error, undefined field: <$key>\n";
  }
}

# If no language, try to figure it out.
my $language = $json->{language};
if (not $language) {
  $language = &determineLanguage($json->{file});
  if ($language eq $UNKNOWN_LANGUAGE) {
    die "Error, could not discover language of $json->{file}\n";
  }
}

# Invoke the appropriate extractor.
my $extractor = $language2extractor{$language};
if ($extractor and -x $extractor) {
  print STDERR "$extractor '$json->{file}'\n";
  my $result = decode_json(`$extractor '$json->{file}' 2>/dev/null`);
  # Add the language to the output to simplify pipelining.
  $result->{language} = $language;
  print STDOUT encode_json($result) . "\n";
}
else {
  die "Error, no extractor for $language\n";
}

######################

sub determineLanguage {
  my ($file) = @_;

  my $language = $UNKNOWN_LANGUAGE;

  # File extension.
  if ($file =~ m/\.(\w+)$/) {
    my $extension = $1;
    $language = &extension2language($extension);
  }
  # Did it work?
  if ($language ne $UNKNOWN_LANGUAGE) {
    return $language;
  }

  # Check the 'file' command's guess.
  my ($rc, $out) = &cmd("file $file");
  #print "rc $rc out $out\n";
  if ($rc eq 0) {
    if ($out =~ m/(\s|\/)node(js)?\s/i) {
      $language = "javascript";
    }
    elsif ($out =~ m/\sPython\s/i) {
      $language = "python";
    }
  }
  # Did it work?
  if ($language ne $UNKNOWN_LANGUAGE) {
    return $language;
  }

  return $language;
}

sub extension2language {
  my ($ext) = @_;

  my $language = $UNKNOWN_LANGUAGE;
  if (lc $ext eq "js") {
    $language = "javascript";
  }
  elsif (lc $ext eq "py") {
    $language = "python";
  }

  return $language;
}

sub cmd {
  my ($cmd) = @_;
  my $out = `$cmd`;
  my $rc = $? >> 8;

  return ($rc, $out);
}
