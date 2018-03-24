#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Route an 'extract-regexps' request to the appropriate language handler based on file extension
#  Prints to STDERR a JSON object with keys:
#    regexps[]: an array of objects, each with keys: pattern flags
#               pattern and flags are each either a string or 'DYNAMIC-{PATTERN|FLAGS}' 
#  Additional keys are OK.
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

# Map extension to regexp extractor
my %language2extractor = (
  "javascript" => "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/extract/src/js/extract-regexps.js",

  "python"     => "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/extract/src/python/python-extract-regexps-wrapper.pl",
);

for my $ext (keys %language2extractor) {
  if (not -x $language2extractor{$ext}) {
    die "Error, could not find regexp extractor for extension $ext: not executable <$language2extractor{$ext}>\n";
  }
}

# Check usage

if (not @ARGV) {
  die "Usage: $0 file-json.json\n";
}

my $jsonFile = $ARGV[0];
if (not -f $jsonFile) {
  die "Error, no such file $jsonFile\n";
}
my $json = decode_json(`cat $jsonFile`);

my $file = $json->{file};
my $language = $json->{language};

# If no language, use extension
if (not $language) {
  if ($file =~ m/\.(\w+)$/) {
    my $extension = $1;
    $language = &extension2language($extension);
  }
  else {
    die "File has no extension, and no language was provided.\n";
  }
}

# Invoke the appropriate extractor
my $extractor = $language2extractor{$language};
if ($extractor and -x $extractor) {
  print STDERR "$extractor '$file'\n";
  exec($extractor, $file); # Goodbye
  die "Error, couldn't exec $extractor: $!\n";
}
else {
  die "Error, no extension found on file <$file>\n";
}

######################

sub extension2language {
  my ($ext) = @_;

  if (lc $ext eq "js") {
    return "javascript";
  }
  elsif (lc $ext eq "py") {
    return "python";
  }

  die "Error, unsupported extension $ext\n";
}
