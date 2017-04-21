#!/usr/bin/env ruby
# nessus-merge.rb fileout *.nessus

require "bundler/setup"
require "offrep"

out=ARGV.shift
ot=Offrep::Translation.new
oc=Offrep::CommonXML.new
on=Offrep::NessusXML.new
on.readxml(File.open(ARGV.shift))
while opt = ARGV.shift do
        puts opt
        on.mergexml(opt)
end
File.write(out+".nessusxml",on.xmldoc.to_s)
File.write(out+".commonxml",on.to_common.to_s)

