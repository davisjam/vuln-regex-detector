#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Query the rathnayake-rxxr2 detector for pattern safety
#
# Dependencies:
#   - VULN_REGEX_DETECTOR_ROOT must be defined

use strict;
use warnings;

use JSON::PP; # I/O

# Check dependencies.
if (not defined $ENV{VULN_REGEX_DETECTOR_ROOT}) {
  die "Error, VULN_REGEX_DETECTOR_ROOT must be defined\n";
}

my $rxxr2Bin = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/detect/src/detectors/rathnayake-rxxr2/scan.bin";
if (not -x $rxxr2Bin) {
  die "Error, cannot run rxxr2Bin $rxxr2Bin\n";
}

# Check args.
if (scalar(@ARGV) != 1) {
  die "Usage: $0 query-desc.json\n";
}

my $patternFile = $ARGV[0];
if (not -f $patternFile) {
  die "Error, no such patternFile $patternFile\n";
}

# Read.
my $cont = &readFile("file"=>$patternFile);
my $pattern = decode_json($cont);

# Write out to a tmp file for rxxr2 format.
my $tmpFile = "/tmp/query-rathnayake-rxxr2-$$.regex";
unlink $tmpFile;
&writeToFile("file"=>$tmpFile, "contents"=>"/$pattern->{pattern}/\n");
print STDERR "CLEANUP: $tmpFile\n"; # If we time out, the parent can clean up for us.

# Run.
my ($rc, $out) = &cmd("$rxxr2Bin -i $tmpFile 2>&1");
unlink $tmpFile;

# Parse to determine opinion
my $opinion = {};

$opinion->{canAnalyze} = ($out =~ m/PARSE: OK/) ? 1 : 0;
if ($opinion->{canAnalyze}) {
  $opinion->{isSafe} = ($out =~ m/VULNERABLE: YES/) ? 0 : 1;
}
else {
  $opinion->{isSafe} = 'UNKNOWN';
}

if (not $opinion->{isSafe}) {
  # Find the evil input suggested by rxxr2.
  my ($prefix) = ($out =~ m/PREFIX: (.*)/); # . won't cross \n
  my ($pump)   = ($out =~ m/PUMPABLE[\s\S]*?PUMPABLE: (.*)/); # The first PUMPABLE is boolean, the second is an attack string. There is a third, so use non-greedy match. . won't cross \n.
  my ($suffix) = ($out =~ m/SUFFIX: (.*)/); # . won't cross \n

  if (defined($prefix) and defined($pump) and defined($suffix)) {
    my $details = { "pumpPairs" => [ { "prefix" => $prefix,
                                       "pump" => $pump,
                                     },
                                   ],
                    "suffix"   => $suffix,
                  };
    $opinion->{evilInput} = [$details];
  }
  else {
    &log("Although detector said it was unsafe, I could not identify evilInput in output\n$out");
    $opinion->{evilInput} = ["COULD-NOT-PARSE"];
  }
}

# Update $pattern.
$pattern->{opinion} = $opinion;
# Emit.
print STDOUT encode_json($pattern) . "\n";

exit 0;

#####################

# input: ($cmd)
# output: ($rc, $out)
sub cmd {
  my ($cmd) = @_;
  &log("CMD: $cmd");
  my $out = `$cmd`;
  return ($? >> 8, $out);
}

sub log {
  my ($msg) = @_;
  print STDERR "$msg\n";
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

# input: %args: keys: file
# output: $contents
sub readFile {
  my %args = @_;

	open(my $FH, '<', $args{file}) or die "Error, could not read $args{file}: $!";
	my $contents = do { local $/; <$FH> }; # localizing $? wipes the line separator char, so <> gets it all at once.
	close $FH;

  return $contents;
}
