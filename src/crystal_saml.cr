require "./crystal_saml/openssl_ext"
require "./crystal_saml/utils"
require "./crystal_saml/settings"
require "./crystal_saml/xml_security"
require "./crystal_saml/authrequest"
require "./crystal_saml/response"
require "./crystal_saml/logout_request"
require "./crystal_saml/logout_response"
require "./crystal_saml/metadata"

module CrystalSaml
  VERSION          = "1.18.1"
  UPSTREAM_VERSION = "1.18.1"

  NAMESPACES = {
    "samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml"  => "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds"    => "http://www.w3.org/2000/09/xmldsig#",
    "xenc"  => "http://www.w3.org/2001/04/xmlenc#",
    "md"    => "urn:oasis:names:tc:SAML:2.0:metadata",
  }
end
