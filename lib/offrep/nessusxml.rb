require 'nokogiri'
require 'logger'

module Offrep
  class NessusXML
    attr_accessor :xmldoc, :log

    def initialize
      @log=Logger.new(STDERR)
      @log.level = Logger::WARN
    end

    def readxml(trxml)
      # f=File.open(trxml)
      @xmldoc=Nokogiri::XML(trxml)
      #f.close
    end

    def importxml(trxml)
	if @xmldoc.nil? then
          readxml(trxml)
        else
          mergexml(trxml)
        end
    end

    def mergexml(trxml)
	f = File.open(trxml)
	doc = Nokogiri::XML(f)

        reportnode=@xmldoc.at_xpath("/NessusClientData_v2/Report")
	doc.xpath("/NessusClientData_v2/Report/ReportHost").each { |host|
	  hostname=host.attribute("name").to_s
	  result=@xmldoc.xpath('/NessusClientData_v2/Report/ReportHost[@name="'+hostname+'"]')
	  if result.empty?
	    reportnode.add_child(host)
	    @log.debug("host "+hostname+": not found, added")
	  else
	    @log.debug("host "+hostname+": found, not added new")
	    rhnode=@xmldoc.at_xpath('/NessusClientData_v2/Report/ReportHost[@name="'+hostname+'"]')
	    host.xpath("./ReportItem").each { |ri|
	      port=ri.attribute("port").to_s
	      pluginid=ri.attribute("pluginID").to_s
	      protocol=ri.attribute("protocol").to_s

	      resultri=@xmldoc.xpath('/NessusClientData_v2/Report/ReportHost[@name="'+hostname+'"]/ReportItem[@pluginID="'+pluginid+
	      '" and @port="'+port+
	      '" and @protocol="'+protocol+'"]')
	      if resultri.empty?
		rhnode.add_child(ri)
		@log.debug(port+";"+protocol+";"+pluginid+": not found, added")
	      else
		@log.debug(port+";"+protocol+";"+pluginid+": found, not added new")
	      end
	    } # host.xpath
	  end
	} # xpath.each host

	f.close
    end

    def getcontent(cont,defvalue)
      if cont.nil? then
        return defvalue
      else
        return cont.content
      end
    end

    def to_common
builder = Nokogiri::XML::Builder.new do |xml|
    xml.vulnerabilities {
      @xmldoc.xpath("/NessusClientData_v2/Report/ReportHost").each do |host|
      host.xpath("./ReportItem").each do |ri|
      xml.vulnerability_ {
        xml.target_ {
          xml.ip_ host.attribute("name").to_s || '0'
          xml.port_ ri.attribute("port").to_s || '0'
          xml.protocol_ ri.attribute("protocol").to_s || 'ip'
          xml.service_ ri.attribute("svc_name").to_s || 'general'
	}
        xml.id_ {
          xml.nessusPluginId_ ri.attribute("pluginID").to_s || '0'
        }
        xml.data_ {
          xml.common {
            xml.severity_ ri.attribute("severity").to_s || '0'
            xml.score_ getcontent(ri.at_xpath('./cvss_base_score'),'')
            xml.title_ ri.attribute("pluginName").to_s || ''
	    xml.synopsis_ getcontent(ri.at_xpath('./synopsis'),'')
	    xml.description_ getcontent(ri.at_xpath('./description'),'')
	    xml.solution_ getcontent(ri.at_xpath('./solution'),'')
	    xml.output_ getcontent(ri.at_xpath('./plugin_output'),'')
	    xml.references_ getcontent(ri.at_xpath('./see_also'),'')
          }
        }
      }
      end # host.xpath
      end # @xmldoc.xpath
    }
end
return builder.to_xml

    end

  end
end
