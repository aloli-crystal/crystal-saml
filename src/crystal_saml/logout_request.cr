module CrystalSaml
  class LogoutRequest
    getter id : String
    getter issue_instant : String
    getter settings : Settings

    def initialize(@settings : Settings, @name_id : String = "", @session_index : String? = nil)
      @id = Utils.uuid
      @issue_instant = Utils.timestamp
    end

    # Build the SAML LogoutRequest XML.
    def to_xml : String
      String.build do |xml|
        xml << %(<samlp:LogoutRequest)
        xml << %( xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol")
        xml << %( xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion")
        xml << %( ID="#{@id}")
        xml << %( Version="2.0")
        xml << %( IssueInstant="#{@issue_instant}")
        xml << %( Destination="#{@settings.idp_slo_service_url}")
        xml << %(>)

        # Issuer
        xml << %(<saml:Issuer>#{@settings.sp_entity_id}</saml:Issuer>)

        # NameID
        xml << %(<saml:NameID)
        xml << %( Format="#{@settings.name_identifier_format}")
        unless @settings.sp_name_qualifier.empty?
          xml << %( SPNameQualifier="#{@settings.sp_name_qualifier}")
        end
        xml << %(>#{@name_id}</saml:NameID>)

        # SessionIndex
        if si = @session_index
          xml << %(<samlp:SessionIndex>#{si}</samlp:SessionIndex>)
        end

        xml << %(</samlp:LogoutRequest>)
      end
    end

    # Build redirect URL for HTTP-Redirect binding.
    def redirect_url(relay_state : String? = nil) : String
      encoded = Utils.deflate_and_encode(to_xml)
      params = {"SAMLRequest" => encoded}
      params["RelayState"] = relay_state if relay_state
      Utils.build_redirect_url(@settings.idp_slo_service_url, params)
    end
  end
end
