#!/usr/bin/env perl
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Test all files in a tree to see if any have vulnerable regexes.
#
# Dependencies:
#   - VULN_REGEX_DETECTOR_ROOT must be defined

use strict;
use warnings;

use JSON::PP;

# Check dependencies.
if (not defined $ENV{VULN_REGEX_DETECTOR_ROOT}) {
  die "Error, VULN_REGEX_DETECTOR_ROOT must be defined\n";
}

my $checkFile = "$ENV{VULN_REGEX_DETECTOR_ROOT}/bin/check-file.pl";

for my $script ($checkFile) {
  if (not -x $script) {
    die "Error, could not find script $script\n";
  }
}

# Args.
if (scalar(@ARGV) != 1) {
  die "Usage: $0 tree.json\n";
}

my $queryFile = $ARGV[0];
if (not -f $queryFile) {
  die "Error, no such queryFile $queryFile\n";
}

my $query = decode_json(`cat $queryFile`);
for my $key ("root") {
  if (not defined $query->{$key}) {
    die "Error, must provide key $key\n";
  }
}

my $tmpFile = "/tmp/check-tree-$$.json";
my $progressFile = "/tmp/check-tree-$$-progress.log";
unlink($tmpFile, $progressFile);

my $result = {};

### Identify files

# Any file might contain regexes, can't rely on file extension alone.
my @filesToCheck = `find $query->{root} -type f`; # Ignore symlinks. If they point inside the tree we'll find them anyway.
chomp @filesToCheck;
&log("Found " . scalar(@filesToCheck) . " files");

# Did they want to exclude directories?
if (defined $query->{excludeDirs}) {
  for my $excludeDir (@{$query->{excludeDirs}}) {
    @filesToCheck = grep { not m/(^|\/)$excludeDir\// } @filesToCheck;
  }
}
&log("excludeDirs left me with " . scalar(@filesToCheck) . " files");

### check-file

my $i = 1;
my $n = scalar(@filesToCheck);

my @checkFileReports;
my @vulnFiles;
for my $file (@filesToCheck) {
  &log("Checking file $i/$n: $file");
  $i++;

  # Prep a query to $checkFile.
  my $checkFileQuery = decode_json(encode_json($query));
  $checkFileQuery->{file} = $file;
  &writeToFile("file"=>$tmpFile, "contents"=>encode_json($checkFileQuery));

  # Might fail if it's not a supported file type.
  my $checkFileReport = decode_json(&chkcmd("$checkFile $tmpFile 2>>$progressFile"));
  push @checkFileReports, $checkFileReport;

  next if (not $checkFileReport->{couldExtractRegexes});

  if ($checkFileReport->{anyVulnRegexes}) {
    push @vulnFiles, $file;
  }
}

# Update result.
$result->{checkFileReports} = \@checkFileReports;
$result->{vulnFiles} = \@vulnFiles;

if (scalar(@{$result->{vulnFiles}})) {
  $result->{anyVulnFiles} = 1;
}
else {
  $result->{anyVulnFiles} = 0;
}

# Summary.
&log("Root $query->{root} contained " . scalar(@vulnFiles) . " vulnerable file(s)");

# Cleanup.
unlink($tmpFile, $progressFile);

# Report results.
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
  &log("$cmd");
  my $out = `$cmd`;
  my $rc = $? >> 8;

  return ($rc, $out);
}

sub chkcmd {
  my ($cmd) = @_;
  my ($rc, $out) = &cmd($cmd);
  if ($rc) {
    die "Error, cmd <$cmd> gave rc $rc:\n$out\n";
  }

  return $out;
}

sub log {
  my ($msg) = @_;
  print STDERR "$msg\n";
}
