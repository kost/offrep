require 'nokogiri'
require 'logger'

require 'pry'

module Offrep
  class CommonXML
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

    def sevnum2text(sev)
      str="NOT"
      nsev=0
      if sev.is_a? Integer
	nsev=sev
      else
        nsev=sev.to_i
      end

      case nsev
        when 4
          str="CRITICAL"
        when 3
          str="HIGH"
        when 2
          str="MEDIUM"
        when 1
          str="LOW"
        when 0
          str="INFO"
        else
          str="UNKNOWN"
        end
      return str
    end

    def sev2i(sev)
      sevnum=0
      if sev.is_a? Integer
        sevnum=sev
      else
        sevnum=sev.to_i
      end
      return sevnum
    end

    def cvss2f(score)
      scorenum=0.to_f
      if score.is_a? Float
        scorenum=score
      else
        scorenum=score.to_f
      end
      return scorenum
    end

    def removesev(sev)
      @xmldoc.xpath("/vulnerabilities/vulnerability[./data/common/severity='#{sev}']").each do |vuln|
        vuln.remove
      end
      @xmldoc
    end

    def anonymize(xmln) 
      xmln.xpath('/vulnerabilities/vulnerability/target').each do |target|
        target.remove
      end
      xmln.xpath('/vulnerabilities/vulnerability/data/common/output').each do |output|
        output.remove
      end 
      return xmln   
    end

    def emptyxml
      misvulns = Nokogiri::XML::Builder.new do |xml|
	  xml.vulnerabilities {
	  }
      end # misvulns
      misxml = Nokogiri::XML(misvulns.to_xml)
      return misxml
    end

    def removebydef(defxml)
      defxml.xpath("/vulnerabilities/vulnerability").each do |vulndef|
        vulndef.element_children.each do |vulnele|
          vulnele.element_children.each do |vulnele|
          end
        end
      end
    end

    def swapvuln(vuln1,vuln2)
      tempvuln=vuln1.dup
      vuln1=vuln2
      vuln2=tempvuln
    end

    def cmpvuln(vuln1,vuln2)
      sev1=sev2i(getcontent(vuln1.at_xpath('./data/common/severity'),'0'))
      cvss1=cvss2f(getcontent(vuln1.at_xpath('./data/common/score'),'0.0'))
      sev2=sev2i(getcontent(vuln2.at_xpath('./data/common/severity'),'0'))
      cvss2=cvss2f(getcontent(vuln2.at_xpath('./data/common/score'),'0.0'))
      ret=0
      case
	when sev1>sev2
          ret=1
	when sev1<sev2
	  ret=-1
	when sev1==sev2
          case
	    when cvss1>cvss2
              ret=1
	    when cvss1<cvss2
	      ret=-1
            when cvss1==cvss2
              ret=0
	  end
      end
      return ret
    end

    def isortbysev!
      vulnxml=sortbysev
      @xmldoc=vulnxml
    end

    def isortbysevrev!
      vulnxml=sortbysevrev
      @xmldoc=vulnxml
    end

    def sortbysevrev
      sorted=xsortbysev.reverse
      sorted.each do |vuln|
	@xmldoc.at_xpath('/vulnerabilities').add_child(vuln)
      end
    end

    def sortbysev
      sorted=xsortbysev
      sorted.each do |vuln|
        @xmldoc.at_xpath('/vulnerabilities').add_child(vuln)
      end
    end

    def xsortbysev
      vulnsnode=@xmldoc.at_xpath('/vulnerabilities')
      vulns=vulnsnode.xpath('./vulnerability')
      sorted=vulns.sort {|a,b| cmpvuln(a,b) }
      return sorted
    end

    def osortbysev!
      vulns=@xmldoc.xpath('/vulnerabilities/vulnerability')
      sorted=vulns.sort{|a,b| cmpvuln(a,b) }
      vulns=sorted
    end

    def osortbysev
      vulns=@xmldoc.xpath('/vulnerabilities/vulnerability')
      sorted=vulns.sort{|a,b| cmpvuln(a,b) }
      return sorted
    end

    def sortbyvuln
      vulnxml=emptyxml()
      xmldoc=@xmldoc
      xmldoc.xpath("/vulnerabilities/vulnerability").each do |vuln|
        foundid=false
        vuln.at_xpath('./id').element_children.each do |ids|
          if foundid then
            next
          end
	  foundvuln=vulnxml.at_xpath("/vulnerabilities/vulnerability[./id/#{ids.name}='#{ids.content}']")
          if foundvuln.nil?
            # if not found add complete vulnerability
	    vulnxml.at_xpath('/vulnerabilities').add_child(vuln.dup)
          else
            # if found, add only target part
            foundvuln.add_child(vuln.at_xpath('./target').dup)
            # TODO: add output as well
            foundid=true
          end
        end
      end
      return vulnxml
    end

    def translate(trxml)
      misxml = emptyxml()
      @xmldoc.xpath('/vulnerabilities/vulnerability').each do |vuln| 
        foundit=false
        # binding.pry
        vuln.at_xpath('./id').element_children.each do |ids|
          if ids.name=='cve' then
            next 
          end
	  # binding.pry
	  trid=trxml.at_xpath("/vulnerabilities/vulnerability[./id/#{ids.name}='#{ids.content}']")
          if not trid.nil? then
            foundit=true
            # replace all XML elements inside /data/common to translated ones
            trid.at_xpath('./data/common').element_children.each do |ele| 
              # puts ele.name
              foundele=vuln.at_xpath("./data/common/#{ele.name}")
              # if element not found, add as a child in common
              # binding.pry
              if foundele.nil?
                vuln.at_xpath("./data/common").add_child(trid.at_xpath("./data/common").dup)
              else
                foundele.content = ele.content
              end
            end # trid.at_xpath
          end # if not trid
        end # vuln.at_xpath .. ids

        # trxml.xpath('/vulnerabilities/vulnerability').each do |trvuln|
        # vuln.at_xpath('./data/common').element_children.each { |e| puts e.name }

        if foundit then
          # puts "Found for #{vuln.to_s[0..60]}"
        else
          # puts "Not found for #{vuln.to_s[0..60]}"
          # binding.pry
          misxml.at_xpath('/vulnerabilities').add_child(vuln.dup)
        end
      end # @xmldoc ... vuln
      # puts misxml
      return misxml
    end

    def mergexml(trxml)
      doc = Nokogiri::XML(trxml)
      doc.xpath("/vulnerabilities/vulnerability").each do |vuln|
      end
    end

    def getcontent(cont,defvalue)
      if cont.nil? then
        return defvalue
      else
        return cont.content
      end
    end

    def to_common
      return @xmldoc
    end

    def to_com
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
