#!/usr/bin/env perl

use strict;
use warnings;

use File::Basename;
use File::Spec;

# The dirname() thing will only work if this script is invoked directly, not via symlink
my $jar = File::Spec->catfile(dirname($0), "target", "query-java-1.0-shaded.jar");

# java -jar JARFILE ...
exec("java", "-jar", $jar, @ARGV);
