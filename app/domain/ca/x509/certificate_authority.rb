# frozen_string_literal: true

require 'securerandom'

module CA
  # CertificateAuthority implements the signing capabilities
  # for a Conjur configure CA service
  class X509CertificateAuthority

    attr_reader :service

    # Creates a Certificate Authority from a configured Conjur webservice
    # 
    # Params:
    # - service: Conjur `Resource` representing the configured CA
    #               webservice.
    def initialize(service)
      @service = service
    end

    # Verifies and formats the inputs for certificate signing
    def prepare_inputs(role, params)
      verify_role(role)

      raise "Signing parameter 'csr' is missing." unless params.key?(:csr)
      csr = OpenSSL::X509::Request.new(params[:csr])
      verify_csr(csr)

      #TODO: Is there any verification we should perform here? For example, that the TTL is not negative or 0?
      ttl = ISO8601::Duration.new(params[:ttl]).to_seconds 

      return {
        role: role,
        csr: csr,
        ttl: ttl
      }
    end

    # Signs a certificate signing request (CSR) returning the X.509
    # certificate
    #
    # inputs hash should contain:
    #   role: Conjur Role for the requestor
    #   csr:  OpenSSL::X509::Request. Certificate signing request to sign
    #   ttl:  Integer. The desired lifetime, in seconds, for the 
    #               certificate 
    def sign(inputs)

      csr_cert = OpenSSL::X509::Certificate.new

      # Generate a random 20 byte (160 bit) serial number for the certificate
      csr_cert.serial = SecureRandom.random_number(1<<160)

      # This value is zero-based. This is a version 3 certificate.
      csr_cert.version = 2

      now = Time.now
      csr_cert.not_before = now
      csr_cert.not_after = now + [inputs[:ttl], max_ttl].min 
      csr_cert.subject = subject(inputs[:role])
      csr_cert.public_key = inputs[:csr].public_key
      csr_cert.issuer = certificate.subject
  
      extension_factory = OpenSSL::X509::ExtensionFactory.new
      extension_factory.subject_certificate = csr_cert
      extension_factory.issuer_certificate = certificate
  
      csr_cert.add_extension(
        extension_factory.create_extension('basicConstraints', 'CA:FALSE')
      )
      csr_cert.add_extension(
        extension_factory.create_extension('keyUsage', 'keyEncipherment,dataEncipherment,digitalSignature')
      )
      csr_cert.add_extension(
        extension_factory.create_extension('subjectKeyIdentifier', 'hash')
      )

      csr_cert.add_extension(
        extension_factory.create_extension("subjectAltName", subject_alt_name(inputs[:role]))
      )

      csr_cert.sign private_key, OpenSSL::Digest::SHA256.new
      csr_cert.to_pem
    end

    protected

    def subject(role)
      common_name = [
        role.account,
        service_id,
        role.kind,
        role.identifier
      ].join(':')
      OpenSSL::X509::Name.new [['CN', common_name]]
    end

    def service_id
      # CA services have ids like 'conjur/<service_id>/ca'
      @service_id ||= service.identifier.split('/')[1]
    end

    def subject_alt_name(role)
      [
        "DNS:#{leaf_domain_name(role)}",
        "URI:#{spiffe_id(role)}"
      ].join(', ')
    end

    def leaf_domain_name(role)
      role.identifier.split('/').last
    end

    def spiffe_id(role)
      [
        'spiffe://conjur',
        role.account,
        service_id,
        role.kind,
        role.identifier
      ].join('/')
    end

    def private_key
      @private_key ||= load_private_key
    end

    def load_private_key
      if private_key_password?
        OpenSSL::PKey::RSA.new(secret(private_key_var), private_key_password)
      else
        OpenSSL::PKey::RSA.new(secret(private_key_var))
      end
    end

    def private_key_password?
      private_key_password.present?
    end

    def private_key_password
      @private_key_password ||= secret(private_key_password_var)
    end

    def certificate
      # Parse the first certificate in the chain, which should be the
      # intermediate CA certificate
      @certificate ||= OpenSSL::X509::Certificate.new secret(certificate_chain_var)
    end
  
    def max_ttl
      ISO8601::Duration.new(@service.annotation('ca/max_ttl')).to_seconds
    end

    private

    def verify_role(role)
      raise "Requestor is not a host" unless role.kind == 'host'
      raise "Host is not authorized to sign." unless role.allowed_to?('sign', @service)
    end

    def verify_csr(csr)
      raise 'CSR cannot be verified' unless csr.verify(csr.public_key)
    end
        
    def certificate_chain_var
      @service.annotation('ca/certificate-chain')
    end

    def private_key_var
      @service.annotation('ca/private-key')
    end

    def private_key_password_var
      @service.annotation('ca/private-key-password')
    end

    def secret(name)
      Resource[secret_id(name)]&.secret&.value
    end

    def secret_id(name)
      [service.account, 'variable', name].join(':')
    end
  end
end
