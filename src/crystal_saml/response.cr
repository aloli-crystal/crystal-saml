require "xml"
require "base64"

module CrystalSaml
  class Response
    getter settings : Settings
    getter document : XML::Node
    getter errors : Array(String)

    @raw_response : String

    def initialize(@settings : Settings, raw_base64 : String)
      @errors = [] of String
      @raw_response = Utils.base64_decode(raw_base64)
      @document = XML.parse(@raw_response)
    end

    # Validate the entire SAML response.
    def valid?(skip_conditions : Bool = false, skip_signature : Bool = false) : Bool
      @errors.clear

      validate_status
      validate_issuer
      validate_conditions unless skip_conditions
      validate_signature unless skip_signature

      @errors.empty?
    end

    # Extract the NameID (authenticated user identifier).
    def name_id : String?
      node = find_node_recursive(@document, "NameID")
      node.try(&.content)
    end

    # Extract the NameID Format.
    def name_id_format : String?
      node = find_node_recursive(@document, "NameID")
      node.try(&.["Format"]?)
    end

    # Extract the SessionIndex from AuthnStatement.
    def session_index : String?
      node = find_node_recursive(@document, "AuthnStatement")
      node.try(&.["SessionIndex"]?)
    end

    # Extract attributes from the AttributeStatement.
    def attributes : Hash(String, Array(String))
      result = {} of String => Array(String)

      attr_statement = find_node_recursive(@document, "AttributeStatement")
      return result unless attr_statement

      attr_statement.children.each do |attr_node|
        next unless attr_node.type.element_node? && local_name(attr_node) == "Attribute"

        name = attr_node["Name"]? || next
        values = [] of String
        attr_node.children.each do |val_node|
          next unless val_node.type.element_node? && local_name(val_node) == "AttributeValue"
          values << (val_node.content || "")
        end
        result[name] = values
      end

      result
    end

    # Get the status code from the response.
    def status_code : String?
      status = find_node_recursive(@document, "Status")
      return nil unless status
      status_code_node = status.children.find { |c| c.type.element_node? && local_name(c) == "StatusCode" }
      status_code_node.try(&.["Value"]?)
    end

    # Get the InResponseTo attribute.
    def in_response_to : String?
      root = response_node
      root.try(&.["InResponseTo"]?)
    end

    # Get the Destination attribute.
    def destination : String?
      root = response_node
      root.try(&.["Destination"]?)
    end

    # Get the Issuer.
    def issuer : String?
      # Look for issuer in the Response element first
      resp = response_node
      return nil unless resp

      resp.children.each do |child|
        if child.type.element_node? && local_name(child) == "Issuer"
          return child.content
        end
      end
      nil
    end

    # Get the assertion issuer.
    def assertion_issuer : String?
      assertion = find_node_recursive(@document, "Assertion")
      return nil unless assertion

      assertion.children.each do |child|
        if child.type.element_node? && local_name(child) == "Issuer"
          return child.content
        end
      end
      nil
    end

    # Get the NotBefore condition.
    def not_before : Time?
      conditions = find_node_recursive(@document, "Conditions")
      return nil unless conditions
      val = conditions["NotBefore"]?
      val ? Utils.parse_timestamp(val) : nil
    end

    # Get the NotOnOrAfter condition.
    def not_on_or_after : Time?
      conditions = find_node_recursive(@document, "Conditions")
      return nil unless conditions
      val = conditions["NotOnOrAfter"]?
      val ? Utils.parse_timestamp(val) : nil
    end

    # Get the Audience from AudienceRestriction.
    def audiences : Array(String)
      result = [] of String
      restriction = find_node_recursive(@document, "AudienceRestriction")
      return result unless restriction

      restriction.children.each do |child|
        if child.type.element_node? && local_name(child) == "Audience"
          content = child.content
          result << content if content && !content.empty?
        end
      end
      result
    end

    private def response_node : XML::Node?
      find_node_recursive(@document, "Response")
    end

    private def validate_status
      code = status_code
      unless code && code.includes?("Success")
        @errors << "Invalid SAML status code: #{code || "missing"}"
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

    private def validate_conditions
      now = Time.utc

      nb = not_before
      if nb && now < nb - 60.seconds
        @errors << "Response is not yet valid (NotBefore: #{nb})"
      end

      noa = not_on_or_after
      if noa && now >= noa + 60.seconds
        @errors << "Response has expired (NotOnOrAfter: #{noa})"
      end

      # Validate audience
      auds = audiences
      if !auds.empty? && !@settings.sp_entity_id.empty?
        unless auds.includes?(@settings.sp_entity_id)
          @errors << "Audience mismatch: expected #{@settings.sp_entity_id}, got #{auds.join(", ")}"
        end
      end
    end

    private def validate_signature
      return if @settings.idp_cert.empty? && @settings.idp_cert_fingerprint.empty?

      # If we have a fingerprint but no cert, try to extract cert from response
      if @settings.idp_cert.empty? && !@settings.idp_cert_fingerprint.empty?
        embedded_cert = extract_embedded_cert
        if embedded_cert
          fp = Utils.fingerprint(embedded_cert, @settings.idp_cert_fingerprint_algorithm)
          expected = @settings.idp_cert_fingerprint.upcase.gsub(/[^A-F0-9]/, ":")
          actual = fp.upcase.gsub(/[^A-F0-9]/, ":")
          unless actual == expected
            @errors << "Certificate fingerprint mismatch"
            return
          end
          # Fingerprint matches, use embedded cert for signature verification
          temp_settings = Settings.new
          temp_settings.idp_entity_id = @settings.idp_entity_id
          temp_settings.idp_cert = Utils.format_cert(embedded_cert)
          validator = XmlSecurity::SignatureValidator.new(temp_settings)
          unless validator.validate(@document)
            @errors.concat(validator.errors)
          end
          return
        else
          @errors << "No embedded certificate found and no IdP certificate configured"
          return
        end
      end

      validator = XmlSecurity::SignatureValidator.new(@settings)
      unless validator.validate(@document)
        @errors.concat(validator.errors)
      end
    end

    private def extract_embedded_cert : String?
      cert_node = find_node_recursive(@document, "X509Certificate")
      cert_node.try(&.content)
    end

    private def find_node_recursive(node : XML::Node, target_local_name : String) : XML::Node?
      if node.type.element_node? && local_name(node) == target_local_name
        return node
      end
      node.children.each do |child|
        result = find_node_recursive(child, target_local_name)
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
