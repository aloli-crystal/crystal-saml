module CrystalSaml
  class LogoutResponse
    getter settings : Settings
    getter document : XML::Node
    getter errors : Array(String)

    def initialize(@settings : Settings, raw_base64 : String)
      @errors = [] of String
      raw = Utils.base64_decode(raw_base64)
      @document = XML.parse(raw)
    end

    # Validate the logout response.
    def valid? : Bool
      @errors.clear
      validate_status
      validate_issuer
      @errors.empty?
    end

    # Get the status code.
    def status_code : String?
      status = find_node_recursive(@document, "Status")
      return nil unless status
      sc = status.children.find { |c| c.type.element_node? && local_name(c) == "StatusCode" }
      sc.try(&.["Value"]?)
    end

    # Get InResponseTo attribute.
    def in_response_to : String?
      resp = find_node_recursive(@document, "LogoutResponse")
      resp.try(&.["InResponseTo"]?)
    end

    # Get the issuer.
    def issuer : String?
      resp = find_node_recursive(@document, "LogoutResponse")
      return nil unless resp
      resp.children.each do |child|
        if child.type.element_node? && local_name(child) == "Issuer"
          return child.content
        end
      end
      nil
    end

    # Build a LogoutResponse XML to send back to IdP.
    def self.build(settings : Settings, in_response_to : String, status : String = "urn:oasis:names:tc:SAML:2.0:status:Success") : String
      id = Utils.uuid
      issue_instant = Utils.timestamp

      xml = String.build do |s|
        s << %(<samlp:LogoutResponse)
        s << %( xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol")
        s << %( xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion")
        s << %( ID="#{id}")
        s << %( Version="2.0")
        s << %( IssueInstant="#{issue_instant}")
        s << %( Destination="#{settings.idp_slo_service_url}")
        s << %( InResponseTo="#{in_response_to}")
        s << %(>)
        s << %(<saml:Issuer>#{settings.sp_entity_id}</saml:Issuer>)
        s << %(<samlp:Status><samlp:StatusCode Value="#{status}"/></samlp:Status>)
        s << %(</samlp:LogoutResponse>)
      end

      Utils.base64_encode(xml)
    end

    private def validate_status
      code = status_code
      unless code && code.includes?("Success")
        @errors << "LogoutResponse status is not Success: #{code || "missing"}"
      end
    end

    private def validate_issuer
      resp_issuer = issuer
      if resp_issuer && !@settings.idp_entity_id.empty?
        unless resp_issuer == @settings.idp_entity_id
          @errors << "Issuer mismatch: expected #{@settings.idp_entity_id}, got #{resp_issuer}"
        end
      end
    end

    private def find_node_recursive(node : XML::Node, target : String) : XML::Node?
      if node.type.element_node? && local_name(node) == target
        return node
      end
      node.children.each do |child|
        result = find_node_recursive(child, target)
        return result if result
      end
      nil
    end

    private def local_name(node : XML::Node) : String
      name = node.name
      idx = name.index(':')
      idx ? name[(idx + 1)..] : name
    end
  end
end
