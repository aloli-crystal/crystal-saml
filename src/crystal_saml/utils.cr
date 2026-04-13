require "uuid"
require "base64"
require "compress/zlib"
require "openssl"
require "uri"
require "xml"

module CrystalSaml
  module Utils
    extend self

    # Generate a unique ID for SAML requests (prefixed with underscore per spec).
    def uuid : String
      "_#{UUID.random}"
    end

    # ISO 8601 timestamp for SAML (UTC, no fractional seconds).
    def timestamp(time : Time = Time.utc) : String
      time.to_s("%Y-%m-%dT%H:%M:%SZ")
    end

    # Parse an ISO 8601 timestamp.
    def parse_timestamp(str : String) : Time
      Time.parse_utc(str, "%Y-%m-%dT%H:%M:%SZ")
    rescue
      Time.parse_utc(str, "%Y-%m-%dT%H:%M:%S.%LZ")
    end

    # Deflate + Base64 encode (for HTTP-Redirect binding).
    def deflate_and_encode(xml : String) : String
      io = IO::Memory.new
      Compress::Zlib::Writer.open(io, level: Compress::Zlib::BEST_COMPRESSION) do |deflate|
        deflate.print(xml)
      end
      Base64.strict_encode(io.to_slice)
    end

    # Base64 decode + inflate (for HTTP-Redirect binding).
    def decode_and_inflate(encoded : String) : String
      decoded = Base64.decode(encoded)
      io = IO::Memory.new(decoded)
      Compress::Zlib::Reader.open(io) do |inflate|
        inflate.gets_to_end
      end
    end

    # Base64 decode (for HTTP-POST binding -- no deflation).
    def base64_decode(encoded : String) : String
      String.new(Base64.decode(encoded))
    end

    # Base64 encode (for HTTP-POST binding -- no deflation).
    def base64_encode(data : String) : String
      Base64.strict_encode(data)
    end

    # Ensure PEM formatting with proper headers.
    def format_cert(cert : String) : String
      cert = cert.strip
      return cert if cert.starts_with?("-----BEGIN CERTIFICATE-----")

      clean = cert
        .gsub("-----BEGIN CERTIFICATE-----", "")
        .gsub("-----END CERTIFICATE-----", "")
        .gsub(/\s+/, "")

      lines = clean.chars.each_slice(64).map(&.join).to_a
      "-----BEGIN CERTIFICATE-----\n#{lines.join("\n")}\n-----END CERTIFICATE-----\n"
    end

    # Ensure PEM formatting for private key.
    def format_private_key(key : String) : String
      key = key.strip
      return key if key.starts_with?("-----BEGIN")

      clean = key
        .gsub(/-----BEGIN.*?-----/, "")
        .gsub(/-----END.*?-----/, "")
        .gsub(/\s+/, "")

      lines = clean.chars.each_slice(64).map(&.join).to_a
      "-----BEGIN RSA PRIVATE KEY-----\n#{lines.join("\n")}\n-----END RSA PRIVATE KEY-----\n"
    end

    # Compute certificate fingerprint.
    def fingerprint(cert_pem : String, algorithm : String = "sha256") : String
      OpenSSLExt.cert_fingerprint(cert_pem, algorithm)
    end

    # Build redirect URL with query parameters.
    def build_redirect_url(base_url : String, params : Hash(String, String)) : String
      uri = URI.parse(base_url)
      existing = uri.query ? URI::Params.parse(uri.query.not_nil!) : URI::Params.new
      params.each { |k, v| existing[k] = v }
      uri.query = existing.to_s
      uri.to_s
    end

    # URL-encode a string.
    def url_encode(str : String) : String
      URI.encode_www_form(str)
    end

    # URL-decode a string.
    def url_decode(str : String) : String
      URI.decode_www_form(str)
    end
  end
end
