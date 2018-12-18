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

  cont = File.read(file)
  obj = JSON.parse(cont)

  # Query regexp.
  my_log("matching: pattern /" + obj['pattern'] + "/ input: length " + obj['input'].length.to_s)
  obj['validPattern'] = 1
  matched = 0
  begin
    if (/#{obj['pattern']}/ =~ obj['input'])
      matched = 1
    else
      matched = 0
    end
  rescue
    obj['validPattern'] = 0
  end

  # Compose output.
  obj['matched'] = matched
  obj['inputLength'] = obj['input'].length
  str = JSON.generate(obj)
  STDOUT.puts str + "\n"

  # Whew.
  exit(0);
end

############

main()
