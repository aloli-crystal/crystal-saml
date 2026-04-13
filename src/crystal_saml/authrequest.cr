require "xml"

module CrystalSaml
  class AuthRequest
    getter id : String
    getter issue_instant : String
    getter settings : Settings

    def initialize(@settings : Settings)
      @id = Utils.uuid
      @issue_instant = Utils.timestamp
    end

    # Build the SAML AuthnRequest XML.
    def to_xml : String
      String.build do |xml|
        xml << %(<samlp:AuthnRequest)
        xml << %( xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol")
        xml << %( xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion")
        xml << %( ID="#{@id}")
        xml << %( Version="2.0")
        xml << %( IssueInstant="#{@issue_instant}")
        xml << %( Destination="#{@settings.idp_sso_service_url}")
        xml << %( AssertionConsumerServiceURL="#{@settings.assertion_consumer_service_url}")
        xml << %( ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
        xml << %(>)

        # Issuer
        xml << %(<saml:Issuer>#{@settings.sp_entity_id}</saml:Issuer>)

        # NameIDPolicy
        xml << %(<samlp:NameIDPolicy)
        xml << %( Format="#{@settings.name_identifier_format}")
        xml << %( AllowCreate="true")
        xml << %(/>)

        # RequestedAuthnContext
        unless @settings.authn_context.empty?
          xml << %(<samlp:RequestedAuthnContext Comparison="exact">)
          @settings.authn_context.each do |ctx|
            xml << %(<saml:AuthnContextClassRef>#{ctx}</saml:AuthnContextClassRef>)
          end
          xml << %(</samlp:RequestedAuthnContext>)
        end

        xml << %(</samlp:AuthnRequest>)
      end
    end

    # Build redirect URL for HTTP-Redirect binding (GET).
    def redirect_url(relay_state : String? = nil) : String
      encoded = Utils.deflate_and_encode(to_xml)
      params = {"SAMLRequest" => encoded}
      params["RelayState"] = relay_state if relay_state
      Utils.build_redirect_url(@settings.idp_sso_service_url, params)
    end

    # Build the encoded request for HTTP-POST binding.
    def post_data(relay_state : String? = nil) : Hash(String, String)
      encoded = Utils.base64_encode(to_xml)
      data = {"SAMLRequest" => encoded}
      data["RelayState"] = relay_state if relay_state
      data
    end

    # Generate an HTML auto-submit form for HTTP-POST binding.
    def post_form(relay_state : String? = nil) : String
      data = post_data(relay_state)
      String.build do |html|
        html << %(<!DOCTYPE html><html><head><meta charset="utf-8"></head><body onload="document.forms[0].submit();">)
        html << %(<form method="post" action="#{@settings.idp_sso_service_url}">)
        data.each do |name, value|
          html << %(<input type="hidden" name="#{name}" value="#{value}"/>)
        end
        html << %(<noscript><input type="submit" value="Submit"/></noscript>)
        html << %(</form></body></html>)
      end
    end
  end
end
