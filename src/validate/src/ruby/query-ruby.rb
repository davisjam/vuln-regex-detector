#!/usr/bin/env ruby
# Author: Jamie Davis <davisjam@vt.edu>
# Description: Try REDOS attack on Ruby

require 'json'

def my_log(msg)
  STDERR.puts msg + "\n"
end

def main()
  # Assume args are correct.
  file = ARGV[0];
  my_log(file);

  cont = File.read(file)
  obj = JSON.parse(cont)

  # Compose evil input.
  queryString = "";
  for pumpPair in obj['evilInput']['pumpPairs'] 
    queryString += pumpPair['prefix'];
    1.upto(obj['nPumps']) do |i|
      queryString += pumpPair['pump'];
    end
  end
  queryString += obj['evilInput']['suffix']

  # Query regexp.
  my_log("matching: pattern /" + obj['pattern'] + "/ nPumps #{obj['nPumps']} queryString " + queryString); 
  if (/#{obj['pattern']}/ =~ queryString)
    matched = 1
  else
    matched = 0
  end

  # Compose output.
  obj['matched'] = matched
  obj['inputLength'] = queryString.length
  str = JSON.generate(obj)
  STDOUT.puts str + "\n"

  # Whew.
  exit(0);
end

############

main()
