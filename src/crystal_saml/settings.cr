module CrystalSaml
  class Settings
    # Identity Provider (IdP) settings
    property idp_entity_id : String = ""
    property idp_sso_service_url : String = ""
    property idp_slo_service_url : String = ""
    property idp_cert : String = ""
    property idp_cert_fingerprint : String = ""
    property idp_cert_fingerprint_algorithm : String = "sha256"

    # Service Provider (SP) settings
    property sp_entity_id : String = ""
    property assertion_consumer_service_url : String = ""
    property single_logout_service_url : String = ""
    property sp_name_qualifier : String = ""
    property name_identifier_format : String = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    # Security settings
    property authn_context : Array(String) = ["urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"]
    property security_authn_requests_signed : Bool = false
    property security_want_assertions_signed : Bool = true
    property security_want_assertions_encrypted : Bool = false
    property security_signature_method : String = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    property security_digest_method : String = "http://www.w3.org/2001/04/xmlenc#sha256"

    # SP certificate/key for signing (optional)
    property certificate : String = ""
    property private_key : String = ""

    # Generate SP metadata XML.
    def sp_metadata : String
      Metadata.new(self).generate
    end
  end
end
