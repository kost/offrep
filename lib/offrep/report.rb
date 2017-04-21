require 'nokogiri'
require 'logger'

require 'erb'

module Offrep
  class Reportvuln
	  def initialize (vulns)
		  @vulns=vulns
	  end

	  def get_binding
		  binding
	  end
  end # of class 

  class Report
    attr_accessor :xml, :log, :template

    def initialize
      @log = Logger.new
      @template="<% @vulns.each do |v| %>\n"+
                "<%= lineitem=v['pid']+';'+v['title']+';'+v['hosts'] %>"+
	        "<% end %>"
    end

    def output (allvulns)
      rhtml = ERB.new(@template)
      # Set up template data.
      gvuln = Reportvuln.new( allvulns )
      # vulns=allvulns
      # rhtml.result
      rhtml.run(gvuln.get_binding)
    end

    def readxml(trxml)
      f=File.open(fn)
      @xml=Nokogiri::XML(trxml)
      f.close
    end

  end # class
end # module
