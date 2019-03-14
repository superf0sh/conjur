# frozen_string_literal: true

require 'securerandom'

module CA

  class CertificateAuthorityFactory
    
    CA_KIND_ANNOTATION = 'ca/kind'

    class << self
      def create(ca_resource)
        type = ca_type(ca_resource)
        case type
        when :x509
          ::CA::x509CertificateAuthority.new(ca_resource)
        when :ssh
          ::CA::SshCertificateAuthority.new(ca_resource)
        else
          raise CertificateAuthorityTypeUndefined, type
        end
      end

      private

      def ca_type(ca_resource)
        kind = ca_resource.annotations[CA_KIND_ANNOTATION]
        kind.present? ? kind.to_sym : :x509
      end
    end
  end
end