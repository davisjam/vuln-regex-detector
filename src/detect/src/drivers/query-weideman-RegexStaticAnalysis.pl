#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Query the weideman-RegexStaticAnalysis detector for pattern safety
#
# Dependencies:
#   - VULN_REGEX_DETECTOR_ROOT must be defined

use strict;
use warnings;

use IPC::Cmd qw[can_run]; # Check PATH
use JSON::PP; # I/O
use Data::Dumper;
use Carp;

my $DELETE_TMP_FILES = 1;

# If considered unsafe, set to one of these
my %PREDICTED_COMPLEXITY = (
  "exponential" => "exponential",
  "polynomial" => "polynomial",
  "unknown" => "unknown"
);

# Check dependencies.
if (not defined $ENV{VULN_REGEX_DETECTOR_ROOT}) {
  die "Error, VULN_REGEX_DETECTOR_ROOT must be defined\n";
}

my $regexStaticAnalysisDir = "$ENV{VULN_REGEX_DETECTOR_ROOT}/src/detect/src/detectors/weideman-RegexStaticAnalysis";
if (not -d $regexStaticAnalysisDir) {
  die "Error, could not find regexStaticAnalysisDir <$regexStaticAnalysisDir>\n";
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

# Write out to a tmp file for RegexStaticAnalysis format.
my $tmpFile = "/tmp/query-weideman-RegexStaticAnalysis-$$.regex";
unlink $tmpFile;
&writeToFile("file"=>$tmpFile, "contents"=>"$pattern->{pattern}\n");
print STDERR "CLEANUP: $tmpFile\n"; # If we time out, the parent can clean up for us.

# Run.
#
# Explanation of arguments:
#
#   --if=$tmpFile                     Regex is in this file
#   --test-eda-exploit-string=false   We will validate simple mode ourselves dynamically.
#   --ida=true                        We're currently open to any kind of vulnerabilities. EDA is exp-time, IDA is poly-time. 
#   --timeout=0                       We enforce the timeout ourselves.
#   --simple                          Full is exponential in the size of the regexp. Too pricey.
#                                       --simple: reports an imprecise upper bound.
#                                       --full: strengthens the upper bound, possibly identifying false positives.
my $classpath = "'$regexStaticAnalysisDir/bin:$regexStaticAnalysisDir/lib/gson-2.8.2.jar'";
my $jvmNoDumpFlags = ""; # TODO Is there a portable way to do this? "-XXnoJrDump -XXdumpSize:none"; # Disable crash files (generated if ulimit on memory exceeded).
my $cmdString = "java $jvmNoDumpFlags -cp $classpath driver.Main --if=$tmpFile --test-eda-exploit-string=false --ida=true --timeout=0 --simple";
my ($rc, $out) = &cmd("$cmdString 2>&1");
if ($DELETE_TMP_FILES) {
  unlink $tmpFile;
}

# Parse to determine opinion
my $opinion = {};

$opinion->{canAnalyze} = ($out =~ m/SKIPPED/) ? 0 : 1;
if ($opinion->{canAnalyze}) {
  $opinion->{isSafe} = ($out =~ m/Analysed:.*1\/1[\s\S]*?Safe:.*1\/1/) ? 1 : 0;
}
else {
  $opinion->{isSafe} = 'UNKNOWN';
}

if (not $opinion->{isSafe}) {
  my ($edaExploitString) = ($out =~ m/EDA exploit string as JSON:\s+({.*})/); # Greedy will grab the whole JSON string.
  my ($idaExploitString) = ($out =~ m/IDA exploit string as JSON:\s+({.*})/); # Greedy will grab the whole JSON string.
  my $predictedComplexity = $PREDICTED_COMPLEXITY{"unknown"};

  my @evilInput;

  if (defined($edaExploitString)) {
    $predictedComplexity = $PREDICTED_COMPLEXITY{"exponential"};
    my $es = &translateExploitString(decode_json($edaExploitString));
    push @evilInput, $es;
  }
  
  if (defined($idaExploitString)) {
    # If for some reason it produces both E and I predictions, keep the stronger prediction
    if ($predictedComplexity eq $PREDICTED_COMPLEXITY{"unknown"}) {
      $predictedComplexity = $PREDICTED_COMPLEXITY{"polynomial"};
    }

    # But keep the proposed input just in case the stronger prediction is incorrect
    my $es = &translateExploitString(decode_json($idaExploitString));
    push @evilInput, $es;
  }

  if (@evilInput) {
    $opinion->{predictedComplexity} = $predictedComplexity;
    $opinion->{evilInput} = \@evilInput;
  }
  else {
    &log("Although detector said it was unsafe, I could not identify evilInput in output\n$out");
    $opinion->{predictedComplexity} = $predictedComplexity;
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

# input: ($exploitString) JSON object
#   fields: separators[] pumps[] suffix
#     separators and pumps have the same length
# output: ($translatedExploitString) hashref
#   fields: pumpPairs[] suffix
#     Each pumpPair is an object with keys: prefix pump
sub translateExploitString {
  my ($es) = @_;

  if (defined($es->{separators}) and defined($es->{pumps}) and defined($es->{suffix})) {
    &log("exploitString looks valid");
  }
  else {
    croak("Invalid exploitString: " . Dumper($es));
  }

  # Convert Weideman's format to something more sensible:
  #   pumpPairs[]
  #   suffix

  my @separators = @{$es->{separators}};
  my @pumps = @{$es->{pumps}};
  if (scalar(@separators) ne scalar(@pumps)) {
    croak("Invalid exploitString: " . Dumper($es));
  }

  my @pumpPairs;
  for (my $i = 0; $i < scalar(@separators); $i++) {
    push @pumpPairs, { "prefix" => $separators[$i],
                       "pump"   => $pumps[$i]
                     };
  }

  my $suffix = $es->{suffix};

  return { "pumpPairs" => \@pumpPairs,
           "suffix"    => $suffix
         };
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
