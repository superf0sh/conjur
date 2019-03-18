# frozen_string_literal: true

require 'securerandom'

module CA
  # CertificateAuthority implements the signing capabilities
  # for a Conjur configure CA service
  class SshCertificateAuthority

    attr_reader :service

    # Creates a Certificate Authority from a configured Conjur webservice
    # 
    # Params:
    # - service: Conjur `Resource` representing the configured CA
    #               webservice.
    def initialize(service)
      @service = service
    end

    def prepare_inputs(role, params)

      verify_permissions(role)

      raise "Signing parameter 'public_key' is missing." unless params.key?(:public_key)
      public_key = OpenSSL::PKey::RSA.new(params[:public_key])
      #verify_public_key

      raise "Signing parameter 'principals' is missing." unless params.key?(:principals)
      principals = Array(params[:principals])
      # verify_principals

      ttl = ISO8601::Duration.new(params[:ttl]).to_seconds 

      {
        role: role,
        public_key: public_key,
        principals: principals,
        ttl: ttl
      }
    end

            # def verify_principals
        #   return unless is_ssh?
        # end

    def sign(inputs)
      cert = Net::SSH::Authentication::Certificate.new

      # Generate a random 20 byte (160 bit) serial number for the certificate
      cert.serial = SecureRandom.random_number(1<<160)

      now = Time.now
      cert.valid_after = now
      cert.valid_before = now + [inputs[:ttl], max_ttl].min 
      cert.valid_principals = inputs[:principals]

      # TODO: Infer type from requester
      cert.type = :user


      # TODO: Figure out what these are
      cert.extensions = {}
      cert.critical_options = {}

      cert.key_id = inputs[:role].id
      cert.key = inputs[:public_key]

      cert.sign!(private_key)

      "#{cert.ssh_type} #{Base64.strict_encode64(cert.to_blob)}"
    end

    protected

    def service_id
      # CA services have ids like 'conjur/<service_id>/ca'
      @service_id ||= service.identifier.split('/')[1]
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
    
    def verify_permissions(role)
      raise "Role is not authorized to sign." unless role.allowed_to?('sign', @service)
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
