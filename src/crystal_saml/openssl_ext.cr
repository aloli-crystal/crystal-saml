require "openssl/lib_crypto"

# Extended LibCrypto bindings for SAML signature operations.
lib LibCrypto
  type EVP_PKEY = Void*
  type BIO_METHOD = Void*

  fun bio_new_mem_buf = BIO_new_mem_buf(buf : Void*, len : LibC::Int) : Bio*
  fun pem_read_bio_x509 = PEM_read_bio_X509(bp : Bio*, x : X509*, cb : Void*, u : Void*) : X509
  fun pem_read_bio_private_key = PEM_read_bio_PrivateKey(bp : Bio*, x : EVP_PKEY*, cb : Void*, u : Void*) : EVP_PKEY
  fun x509_get_pubkey = X509_get_pubkey(x : X509) : EVP_PKEY
  fun evp_pkey_free = EVP_PKEY_free(pkey : EVP_PKEY)

  fun i2d_x509 = i2d_X509(x : X509, out : UInt8**) : LibC::Int

  fun evp_digestsigninit = EVP_DigestSignInit(ctx : EVP_MD_CTX, pctx : Void*, type : EVP_MD, e : Void*, pkey : EVP_PKEY) : LibC::Int
  fun evp_digestsignupdate = EVP_DigestSignUpdate(ctx : EVP_MD_CTX, data : UInt8*, len : LibC::SizeT) : LibC::Int
  fun evp_digestsignfinal = EVP_DigestSignFinal(ctx : EVP_MD_CTX, sig : UInt8*, siglen : LibC::SizeT*) : LibC::Int

  fun evp_digestverifyinit = EVP_DigestVerifyInit(ctx : EVP_MD_CTX, pctx : Void*, type : EVP_MD, e : Void*, pkey : EVP_PKEY) : LibC::Int
  fun evp_digestverifyupdate = EVP_DigestVerifyUpdate(ctx : EVP_MD_CTX, data : UInt8*, len : LibC::SizeT) : LibC::Int
  fun evp_digestverifyfinal = EVP_DigestVerifyFinal(ctx : EVP_MD_CTX, sig : UInt8*, siglen : LibC::SizeT) : LibC::Int
end

module CrystalSaml
  # Helper module for OpenSSL operations not covered by Crystal stdlib.
  module OpenSSLExt
    extend self

    # Parse a PEM certificate string into a LibCrypto X509 pointer.
    def parse_cert_pem(pem : String) : LibCrypto::X509
      bio = LibCrypto.bio_new_mem_buf(pem.to_unsafe.as(Void*), pem.bytesize)
      raise "BIO_new_mem_buf failed" if bio.null?

      x509 = LibCrypto.pem_read_bio_x509(bio, nil, nil, nil)
      LibCrypto.BIO_free(bio)
      raise "PEM_read_bio_X509 failed" if x509.null?
      x509
    end

    # Get DER encoding of a certificate.
    def cert_to_der(x509 : LibCrypto::X509) : Bytes
      ptr = Pointer(UInt8).null
      len = LibCrypto.i2d_x509(x509, pointerof(ptr))
      raise "i2d_X509 failed" if len <= 0
      bytes = Bytes.new(ptr, len)
      result = bytes.dup
      LibCrypto.crypto_free(ptr) if LibCrypto.responds_to?(:crypto_free)
      result
    end

    # Compute fingerprint of a PEM certificate.
    def cert_fingerprint(pem : String, algorithm : String = "sha256") : String
      pem = CrystalSaml::Utils.format_cert(pem)
      x509 = parse_cert_pem(pem)

      algo_name = case algorithm.downcase.gsub("-", "")
                  when "sha1"   then "SHA1"
                  when "sha256" then "SHA256"
                  when "sha384" then "SHA384"
                  when "sha512" then "SHA512"
                  else               "SHA256"
                  end

      evp_md = LibCrypto.evp_get_digestbyname(algo_name.to_unsafe)
      raise "Unknown digest: #{algo_name}" if evp_md.null?

      hash = Bytes.new(64)
      len = 0_i32
      result = LibCrypto.x509_digest(x509, evp_md, hash, pointerof(len))
      raise "X509_digest failed" unless result == 1

      hash[0, len].hexstring.scan(/../).map(&.[0]).join(":").upcase
    end

    # Parse a PEM private key.
    def parse_private_key_pem(pem : String) : LibCrypto::EVP_PKEY
      bio = LibCrypto.bio_new_mem_buf(pem.to_unsafe.as(Void*), pem.bytesize)
      raise "BIO_new_mem_buf failed" if bio.null?

      pkey = LibCrypto.pem_read_bio_private_key(bio, nil, nil, nil)
      LibCrypto.BIO_free(bio)
      raise "PEM_read_bio_PrivateKey failed" if pkey.null?
      pkey
    end

    # Get the public key from a PEM certificate.
    def cert_public_key(pem : String) : LibCrypto::EVP_PKEY
      formatted = CrystalSaml::Utils.format_cert(pem)
      x509 = parse_cert_pem(formatted)
      pkey = LibCrypto.x509_get_pubkey(x509)
      raise "X509_get_pubkey failed" if pkey.null?
      pkey
    end

    # Sign data using a private key with the given digest algorithm.
    def sign(private_key_pem : String, data : String, algorithm : String = "SHA256") : Bytes
      pkey = parse_private_key_pem(private_key_pem)
      evp_md = LibCrypto.evp_get_digestbyname(algorithm.to_unsafe)
      raise "Unknown digest: #{algorithm}" if evp_md.null?

      ctx = LibCrypto.evp_md_ctx_new
      raise "EVP_MD_CTX_new failed" if ctx.null?

      ret = LibCrypto.evp_digestsigninit(ctx, nil, evp_md, nil, pkey)
      raise "EVP_DigestSignInit failed" unless ret == 1

      ret = LibCrypto.evp_digestsignupdate(ctx, data.to_unsafe, data.bytesize)
      raise "EVP_DigestSignUpdate failed" unless ret == 1

      # Get required signature length
      sig_len = LibC::SizeT.new(0)
      ret = LibCrypto.evp_digestsignfinal(ctx, nil, pointerof(sig_len))
      raise "EVP_DigestSignFinal (length) failed" unless ret == 1

      # Get actual signature
      sig = Bytes.new(sig_len)
      ret = LibCrypto.evp_digestsignfinal(ctx, sig, pointerof(sig_len))
      raise "EVP_DigestSignFinal failed" unless ret == 1

      LibCrypto.evp_md_ctx_free(ctx)
      LibCrypto.evp_pkey_free(pkey)

      sig[0, sig_len]
    end

    # Verify a signature using a certificate's public key.
    def verify(cert_pem : String, signature : Bytes, data : String, algorithm : String = "SHA256") : Bool
      pkey = cert_public_key(cert_pem)
      evp_md = LibCrypto.evp_get_digestbyname(algorithm.to_unsafe)
      raise "Unknown digest: #{algorithm}" if evp_md.null?

      ctx = LibCrypto.evp_md_ctx_new
      raise "EVP_MD_CTX_new failed" if ctx.null?

      ret = LibCrypto.evp_digestverifyinit(ctx, nil, evp_md, nil, pkey)
      raise "EVP_DigestVerifyInit failed" unless ret == 1

      ret = LibCrypto.evp_digestverifyupdate(ctx, data.to_unsafe, data.bytesize)
      raise "EVP_DigestVerifyUpdate failed" unless ret == 1

      ret = LibCrypto.evp_digestverifyfinal(ctx, signature, signature.size)

      LibCrypto.evp_md_ctx_free(ctx)
      LibCrypto.evp_pkey_free(pkey)

      ret == 1
    end
  end
end
