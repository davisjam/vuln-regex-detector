#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Query the wuestholz-RegexCheck detector for pattern safety
#
# Dependencies:
#   - VULN_REGEX_DETECTOR_ROOT must be defined

use strict;
use warnings;

use IPC::Cmd qw[can_run]; # Check PATH
use JSON::PP; # I/O
use Carp;

# Check dependencies.
if (not defined $ENV{VULN_REGEX_DETECTOR_ROOT}) {
  die "Error, VULN_REGEX_DETECTOR_ROOT must be defined\n";
}

my $regexCheckDir = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/detect/src/detectors/wuestholz-RegexCheck";
if (not -d $regexCheckDir) {
  die "Error, could not find regexCheckDir <$regexCheckDir>\n";
}

if (not can_run("java")) {
  die "Error, cannot find 'java'\n";
}

# Check args.
if (scalar(@ARGV) != 1) {
  die "Usage: $0 pattern.json\n";
}

my $patternFile = $ARGV[0];
if (not -f $patternFile) {
  die "Error, no such patternFile $patternFile\n";
}

# Read.
my $cont = &readFile("file"=>$patternFile);
my $pattern = decode_json($cont);

# Write out to a tmp file for RegexCheck format.
my $tmpFile = "/tmp/query-wuestholz-RegexCheck-$$.regex";
unlink $tmpFile;
&writeToFile("file"=>$tmpFile, "contents"=>"\"$pattern->{pattern}\"\n");
print STDERR "CLEANUP: $tmpFile\n"; # If we time out, the parent can clean up for us.

# Run.
my $jvmNoDumpFlags = ""; # TODO Is there a portable way to do this? "-XXnoJrDump -XXdumpSize:none"; # Disable crash files (generated if ulimit on memory exceeded).
my $cmdString = "java $jvmNoDumpFlags -Xss64M -Xmx1024M -jar $regexCheckDir/regexcheck.jar -f $tmpFile -e false -v 1";
my ($rc, $out) = &cmd("$cmdString 2>&1");
unlink $tmpFile;

&log("rc $rc out\n$out");

# Parse to determine opinion
my $opinion = {};

$opinion->{canAnalyze} = ($out =~ m/Failed:\s+1/) ? 0 : 1;
if ($opinion->{canAnalyze}) {
  $opinion->{isSafe} = ($out =~ m/Exponential:\s+1/ or $out =~ m/Super-linear:\s+1/) ? 0 : 1;
}
else {
  $opinion->{isSafe} = 'UNKNOWN';
}

if (not $opinion->{isSafe}) {
  # Find the evil input suggested by RegexCheck.

  # NB
  # On the regex /\s*#?\s*$/, Wuestholz produces the following:
  #   Found pumpable: "s"
  #   Found prefix: "s"
  #   Found suffix: "" <-- ed.: this is the null byte \0
  #   Attack regex: "s(s)*\u0000" (SUPER_LINEAR)
  #
  # This is the same output it produces on the regex /s*#?s*$/ (note those are 's', not 'whitespace').
  #   Found pumpable: "s"
  #   Found prefix: "s"
  #   Found suffix: ""
  #   Attack regex: "s(s)*\u0000" (SUPER_LINEAR)
  #
  # For those following along at home, in the first regex the pump should be whitespace, not the letter 's'.
  # Can't tell the difference in the output, though, and neither resembles the output we get from the pattern /(a+)+$/.
  #   Found pumpable string: "aa"
  #   Found prefix: "aaa"
  #   Found suffix: ""
  #   Attack regex: "aaa(aa)*\u0000" (EXPONENTIAL)
  #
  # Since Wuestholz's tool is closed-source we can't investigate and improve the output.   
  # So, we just look for 'Found pumpable string' and if we can't find it we declare it unparseable.

  my ($prefix) = ($out =~ m/Found prefix:\s+"(.*)"$/m); # . won't cross \n; might be an empty string or might contain a "
  my ($pump)   = ($out =~ m/Found pumpable string:\s+"(.*)"$/m); # . won't cross \n; might be an empty string or might contain a "
  my ($suffix) = ($out =~ m/Found suffix:\s+"(.*)"$/m); # . won't cross \n; might be an empty string or might contain a "

  if (defined($prefix) and defined($pump) and defined($suffix)) {
    my $details = { "pumpPairs" => [ { "prefix" => $prefix,
                                         "pump" => $pump
                                     }
                                   ],
                    "suffix"   => $suffix
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

	open(my $FH, '<', $args{file}) or confess "Error, could not read $args{file}: $!";
	my $contents = do { local $/; <$FH> }; # localizing $? wipes the line separator char, so <> gets it all at once.
	close $FH;

  return $contents;
}
