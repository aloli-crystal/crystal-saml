require "xml"
require "base64"

module CrystalSaml
  module XmlSecurity
    # Exclusive XML Canonicalization (C14N) -- simplified implementation covering
    # the common cases found in SAML responses.
    #
    # Implements a subset of https://www.w3.org/TR/xml-exc-c14n/
    # sufficient for SAML signature verification.
    class C14N
      # Canonicalize an XML node to its exclusive canonical form.
      def self.canonicalize(node : XML::Node, inclusive_namespaces : Array(String) = [] of String) : String
        io = IO::Memory.new
        write_canonical(node, io, inclusive_namespaces, collected_ns: {} of String => String)
        io.to_s
      end

      private def self.write_canonical(
        node : XML::Node,
        io : IO,
        inclusive_namespaces : Array(String),
        collected_ns : Hash(String, String),
      )
        case node.type
        when .element_node?
          write_element(node, io, inclusive_namespaces, collected_ns)
        when .text_node?
          io << escape_text(node.content || "")
        when .cdata_section_node?
          io << escape_text(node.content || "")
        when .comment_node?
          # Comments are omitted in canonical form
        when .document_node?
          node.children.each { |child| write_canonical(child, io, inclusive_namespaces, collected_ns) }
        end
      end

      private def self.write_element(
        node : XML::Node,
        io : IO,
        inclusive_namespaces : Array(String),
        parent_ns : Hash(String, String),
      )
        name = node.name
        ns_decls = {} of String => String
        attrs = [] of {String, String}

        # Collect namespace declarations that are visibly utilized
        collect_visible_namespaces(node, ns_decls, parent_ns, inclusive_namespaces)

        # Collect attributes (non-namespace)
        node.attributes.each do |attr|
          next if attr.name.starts_with?("xmlns")
          ns_prefix = attr.namespace.try(&.prefix) || ""
          attr_name = ns_prefix.empty? ? attr.name : "#{ns_prefix}:#{attr.name}"
          attrs << {attr_name, attr.content}
        end

        # Sort namespace declarations
        sorted_ns = ns_decls.to_a.sort_by do |prefix, _uri|
          prefix.empty? ? "" : prefix
        end

        # Sort attributes: by name
        sorted_attrs = attrs.sort_by { |attr_name, _| attr_name }

        io << "<" << name

        # Write namespace declarations
        sorted_ns.each do |prefix, uri|
          if prefix.empty?
            io << " xmlns=\"" << escape_attr(uri) << "\""
          else
            io << " xmlns:" << prefix << "=\"" << escape_attr(uri) << "\""
          end
        end

        # Write attributes
        sorted_attrs.each do |attr_name, attr_value|
          io << " " << attr_name << "=\"" << escape_attr(attr_value) << "\""
        end

        io << ">"

        # Merge namespaces for children
        merged_ns = parent_ns.merge(ns_decls)
        node.children.each { |child| write_canonical(child, io, inclusive_namespaces, merged_ns) }

        io << "</" << name << ">"
      end

      private def self.collect_visible_namespaces(
        node : XML::Node,
        ns_decls : Hash(String, String),
        parent_ns : Hash(String, String),
        inclusive_namespaces : Array(String),
      )
        # Check the element's own namespace
        if ns = node.namespace
          prefix = ns.prefix || ""
          uri = ns.href || ""
          unless parent_ns[prefix]? == uri
            ns_decls[prefix] = uri
          end
        end

        # Check attribute namespaces
        node.attributes.each do |attr|
          next if attr.name.starts_with?("xmlns")
          if ans = attr.namespace
            prefix = ans.prefix || ""
            uri = ans.href || ""
            unless prefix.empty? || parent_ns[prefix]? == uri
              ns_decls[prefix] = uri
            end
          end
        end

        # Include inclusive namespaces
        inclusive_namespaces.each do |inc_prefix|
          next if ns_decls.has_key?(inc_prefix)
          current = node
          while current
            if current.type.element_node?
              current.namespaces.each do |ns_name, ns_uri|
                p = ns_name.starts_with?("xmlns:") ? ns_name[6..] : ""
                if p == inc_prefix && ns_uri && parent_ns[inc_prefix]? != ns_uri
                  ns_decls[inc_prefix] = ns_uri
                end
              end
            end
            break if ns_decls.has_key?(inc_prefix)
            current = current.parent
          end
        end
      end

      private def self.escape_text(text : String) : String
        text
          .gsub("&", "&amp;")
          .gsub("<", "&lt;")
          .gsub(">", "&gt;")
          .gsub("\r", "&#xD;")
      end

      private def self.escape_attr(text : String) : String
        text
          .gsub("&", "&amp;")
          .gsub("<", "&lt;")
          .gsub("\"", "&quot;")
          .gsub("\t", "&#x9;")
          .gsub("\n", "&#xA;")
          .gsub("\r", "&#xD;")
      end
    end

    # Verify an XML digital signature against a certificate.
    class SignatureValidator
      getter errors : Array(String)

      def initialize(@settings : Settings)
        @errors = [] of String
      end

      # Validate the signature in the given XML document.
      def validate(document : XML::Node) : Bool
        @errors.clear

        sig_node = find_signature_node(document)
        unless sig_node
          @errors << "No Signature element found"
          return false
        end

        signed_info = find_child(sig_node, "SignedInfo")
        unless signed_info
          @errors << "No SignedInfo element found"
          return false
        end

        sig_value_node = find_child(sig_node, "SignatureValue")
        unless sig_value_node
          @errors << "No SignatureValue element found"
          return false
        end

        signature_value = Base64.decode(sig_value_node.content.gsub(/\s+/, ""))

        # Get the certificate to verify against
        cert_pem = resolve_certificate_pem(sig_node)
        unless cert_pem
          @errors << "No certificate available for signature verification"
          return false
        end

        # Verify reference digests
        unless verify_digests(signed_info, document)
          return false
        end

        # Canonicalize SignedInfo
        canon_signed_info = C14N.canonicalize(signed_info)

        # Determine signature algorithm
        sig_method_node = find_child(signed_info, "SignatureMethod")
        algorithm = sig_method_node.try(&.["Algorithm"]?) || "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

        digest_name = algorithm_to_digest(algorithm)

        # Verify signature
        begin
          valid = OpenSSLExt.verify(cert_pem, signature_value, canon_signed_info, digest_name)
          unless valid
            @errors << "Signature verification failed"
          end
          valid
        rescue ex
          @errors << "Signature verification error: #{ex.message}"
          false
        end
      end

      private def find_signature_node(doc : XML::Node) : XML::Node?
        find_node_recursive(doc, "Signature")
      end

      private def find_child(node : XML::Node, local_name : String) : XML::Node?
        node.children.each do |child|
          return child if child.type.element_node? && self.class.local_name(child) == local_name
        end
        nil
      end

      private def find_node_recursive(node : XML::Node, local_name : String) : XML::Node?
        if node.type.element_node? && self.class.local_name(node) == local_name
          return node
        end
        node.children.each do |child|
          result = find_node_recursive(child, local_name)
          return result if result
        end
        nil
      end

      protected def self.local_name(node : XML::Node) : String
        name = node.name
        idx = name.index(':')
        idx ? name[(idx + 1)..] : name
      end

      private def resolve_certificate_pem(sig_node : XML::Node) : String?
        # Try embedded certificate first
        cert_node = find_node_recursive(sig_node, "X509Certificate")
        if cert_node
          cert_text = cert_node.content.gsub(/\s+/, "")
          return Utils.format_cert(cert_text)
        end

        # Fall back to settings
        return nil if @settings.idp_cert.empty?
        Utils.format_cert(@settings.idp_cert)
      end

      private def verify_digests(signed_info : XML::Node, document : XML::Node) : Bool
        signed_info.children.each do |child|
          next unless child.type.element_node? && self.class.local_name(child) == "Reference"

          uri = child["URI"]?
          next unless uri

          ref_id = uri.lstrip('#')
          referenced = find_element_by_id(document, ref_id)
          unless referenced
            @errors << "Referenced element not found: #{uri}"
            return false
          end

          digest_value_node = find_child(child, "DigestValue")
          unless digest_value_node
            @errors << "No DigestValue found for reference #{uri}"
            return false
          end
          expected_digest = Base64.decode(digest_value_node.content.gsub(/\s+/, ""))

          digest_method_node = find_child(child, "DigestMethod")
          digest_algorithm = digest_method_node.try(&.["Algorithm"]?) || "http://www.w3.org/2001/04/xmlenc#sha256"

          canonical = C14N.canonicalize(referenced)
          computed = compute_digest(canonical, digest_algorithm)

          unless computed == expected_digest
            @errors << "Digest mismatch for reference #{uri}"
            return false
          end
        end

        true
      end

      private def find_element_by_id(node : XML::Node, id : String) : XML::Node?
        if node.type.element_node?
          node_id = node["ID"]? || node["Id"]? || node["id"]?
          return node if node_id == id
        end
        node.children.each do |child|
          result = find_element_by_id(child, id)
          return result if result
        end
        nil
      end

      private def compute_digest(data : String, algorithm : String) : Bytes
        digest_name = algorithm_to_digest(algorithm)
        OpenSSL::Digest.new(digest_name).update(data).final
      end

      private def algorithm_to_digest(algorithm : String) : String
        case algorithm
        when /sha512/i then "SHA512"
        when /sha384/i then "SHA384"
        when /sha256/i then "SHA256"
        when /sha1/i   then "SHA1"
        else                "SHA256"
        end
      end
    end
  end
end
