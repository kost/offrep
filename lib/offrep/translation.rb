require 'nokogiri'

module Offrep
  class Translation
    attr_accessor :xml

    def readxml(xmlparm)
      @xml = Nokogiri::XML(xmlparm)
    end

    def nessusid(pluginid)
      @xml.xpath("/vulnerabilities/vulnerability[./id/nessusPluginId='#{pluginid}']")
    end

    # getelement('nessusPluginId',10072)
    def getvulnele(pluginelement,pluginid)
      @xml.at_xpath("/vulnerabilities/vulnerability[./id/#{pluginelement}='#{pluginid}']")
    end

    # getvulncommon('nessusPluginId',10072,'title')
    def getvulncommon(pluginelement,pluginid,commonelement)
      getvulnele(pluginelement,pluginid).at_xpath("./data/common/#{commonelement}").content
    end

  end # class
end # module
