module CrystalSaml
  class Metadata
    def initialize(@settings : Settings)
    end

    # Generate SP metadata XML.
    def generate : String
      String.build do |xml|
        xml << %(<?xml version="1.0" encoding="UTF-8"?>)
        xml << %(<md:EntityDescriptor)
        xml << %( xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata")
        xml << %( xmlns:ds="http://www.w3.org/2000/09/xmldsig#")
        xml << %( entityID="#{@settings.sp_entity_id}")
        xml << %(>)

        xml << %(<md:SPSSODescriptor)
        xml << %( AuthnRequestsSigned="#{@settings.security_authn_requests_signed}")
        xml << %( WantAssertionsSigned="#{@settings.security_want_assertions_signed}")
        xml << %( protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol")
        xml << %(>)

        # Signing certificate
        unless @settings.certificate.empty?
          xml << %(<md:KeyDescriptor use="signing">)
          xml << %(<ds:KeyInfo>)
          xml << %(<ds:X509Data>)
          xml << %(<ds:X509Certificate>)
          cert_clean = @settings.certificate
            .gsub("-----BEGIN CERTIFICATE-----", "")
            .gsub("-----END CERTIFICATE-----", "")
            .gsub(/\s+/, "")
          xml << cert_clean
          xml << %(</ds:X509Certificate>)
          xml << %(</ds:X509Data>)
          xml << %(</ds:KeyInfo>)
          xml << %(</md:KeyDescriptor>)
        end

        # SingleLogoutService
        unless @settings.single_logout_service_url.empty?
          xml << %(<md:SingleLogoutService)
          xml << %( Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
          xml << %( Location="#{@settings.single_logout_service_url}")
          xml << %(/>)
        end

        # NameIDFormat
        xml << %(<md:NameIDFormat>#{@settings.name_identifier_format}</md:NameIDFormat>)

        # AssertionConsumerService
        xml << %(<md:AssertionConsumerService)
        xml << %( Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
        xml << %( Location="#{@settings.assertion_consumer_service_url}")
        xml << %( index="0")
        xml << %( isDefault="true")
        xml << %(/>)

        xml << %(</md:SPSSODescriptor>)
        xml << %(</md:EntityDescriptor>)
      end
    end
  end
end
