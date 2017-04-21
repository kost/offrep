# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'offrep/version'

Gem::Specification.new do |spec|
  spec.name          = "offrep"
  spec.version       = Offrep::VERSION
  spec.authors       = ["Vlatko Kosturjak"]
  spec.email         = ["kost@linux.hr"]

  spec.summary       = %q{Offensive reporting.}
  spec.description   = %q{Offensive reporting.}
  spec.homepage      = "https://github.com/kost/offrep"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", ">= 1.3"
  spec.add_development_dependency "rake", ">= 1.0"
  spec.add_development_dependency "rspec", ">= 1.0"
  spec.add_development_dependency "pry", ">= 0"

  spec.add_runtime_dependency 'nokogiri', '>= 0'
end
