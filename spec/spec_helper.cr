require "spec"
require "../src/crystal_saml"

module TestHelper
  # Generate a self-signed test certificate and private key using openssl CLI.
  def self.generate_test_cert : {String, String}
    tmp_key = File.tempfile("test_key", ".pem")
    tmp_cert = File.tempfile("test_cert", ".pem")

    begin
      # Generate RSA private key
      Process.run(
        "openssl",
        ["genrsa", "-out", tmp_key.path, "2048"],
        error: Process::Redirect::Close
      )

      # Generate self-signed certificate
      Process.run(
        "openssl",
        ["req", "-new", "-x509", "-key", tmp_key.path,
         "-out", tmp_cert.path, "-days", "365",
         "-subj", "/CN=test.example.com/O=Test/C=US"],
        error: Process::Redirect::Close
      )

      cert_pem = File.read(tmp_cert.path)
      key_pem = File.read(tmp_key.path)
      {cert_pem, key_pem}
    ensure
      tmp_key.delete
      tmp_cert.delete
    end
  end

  @@test_cert : String?
  @@test_key : String?

  def self.test_cert : String
    ensure_cert_generated
    @@test_cert.not_nil!
  end

  def self.test_key : String
    ensure_cert_generated
    @@test_key.not_nil!
  end

  private def self.ensure_cert_generated
    return if @@test_cert
    cert, key = generate_test_cert
    @@test_cert = cert
    @@test_key = key
  end

  def self.test_settings : CrystalSaml::Settings
    settings = CrystalSaml::Settings.new
    settings.idp_entity_id = "https://idp.example.com"
    settings.idp_sso_service_url = "https://idp.example.com/sso"
    settings.idp_slo_service_url = "https://idp.example.com/slo"
    settings.idp_cert = test_cert
    settings.sp_entity_id = "https://sp.example.com"
    settings.assertion_consumer_service_url = "https://sp.example.com/saml/callback"
    settings.single_logout_service_url = "https://sp.example.com/saml/logout"
    settings.certificate = test_cert
    settings.private_key = test_key
    settings
  end

  # Build a minimal valid SAML Response XML.
  def self.build_saml_response(
    issuer : String = "https://idp.example.com",
    name_id : String = "user@example.com",
    audience : String = "https://sp.example.com",
    destination : String = "https://sp.example.com/saml/callback",
    in_response_to : String = "_request123",
    session_index : String = "_session456",
    not_before : Time = Time.utc - 5.minutes,
    not_on_or_after : Time = Time.utc + 55.minutes,
    status : String = "urn:oasis:names:tc:SAML:2.0:status:Success",
    attributes : Hash(String, String) = {"email" => "user@example.com", "name" => "Test User"},
  ) : String
    response_id = CrystalSaml::Utils.uuid
    assertion_id = CrystalSaml::Utils.uuid
    issue_instant = CrystalSaml::Utils.timestamp

    nb = CrystalSaml::Utils.timestamp(not_before)
    noa = CrystalSaml::Utils.timestamp(not_on_or_after)

    attrs_xml = String.build do |s|
      attributes.each do |k, v|
        s << %(<saml:Attribute Name="#{k}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">)
        s << %(<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">#{v}</saml:AttributeValue>)
        s << %(</saml:Attribute>)
      end
    end

    <<-XML
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="#{response_id}"
                    Version="2.0"
                    IssueInstant="#{issue_instant}"
                    Destination="#{destination}"
                    InResponseTo="#{in_response_to}">
      <saml:Issuer>#{issuer}</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="#{status}"/>
      </samlp:Status>
      <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                      ID="#{assertion_id}"
                      Version="2.0"
                      IssueInstant="#{issue_instant}">
        <saml:Issuer>#{issuer}</saml:Issuer>
        <saml:Subject>
          <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">#{name_id}</saml:NameID>
          <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData InResponseTo="#{in_response_to}"
                                          NotOnOrAfter="#{noa}"
                                          Recipient="#{destination}"/>
          </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="#{nb}" NotOnOrAfter="#{noa}">
          <saml:AudienceRestriction>
            <saml:Audience>#{audience}</saml:Audience>
          </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="#{issue_instant}" SessionIndex="#{session_index}">
          <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
          </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
          #{attrs_xml}
        </saml:AttributeStatement>
      </saml:Assertion>
    </samlp:Response>
    XML
  end

  # Build and encode a SAML response as Base64.
  def self.build_encoded_response(**kwargs) : String
    xml = build_saml_response(**kwargs)
    CrystalSaml::Utils.base64_encode(xml)
  end
end
