# frozen_string_literal: true

require "base64"

# Responsible for API calls to interact with a Conjur-configured
# certificate authority (CA) service
class CertificateAuthorityController < RestController
  include ActionController::MimeResponds
  include BodyParser

  before_action :verify_ca
  
  def sign    
    certificate = certificate_authority.sign(signing_params)
    render_certificate(certificate)
  end

  protected

  def verify_ca
    raise RecordNotFound, "There is no CA with ID: #{service_id}" unless ca_resource
  end

  # def verify_host
  #   return unless is_x509?

  #   raise Forbidden unless current_user.allowed_to?('sign', ca_resource)
  #   raise Forbidden, 'Requestor is not a host' unless requestor_is_host?
  # end

  # def verify_csr
  #   return unless is_x509?

  #   raise Forbidden, 'CSR cannot be verified' unless csr.verify(csr.public_key)
  # end

  # def verify_principals
  #   return unless is_ssh?
  # end

  def render_certificate(certificate)
    respond_to do |format|
      format.json do
        render json: {
          certificate: certificate
        },
               status: :created
      end

      format.text do
        render body: certificate, content_type: 'text/plain', status: :created
      end
    end
  end

  def openssh(certificate) 
    "#{certificate.ssh_type} #{Base64.encode64(certificate.to_blob)}"
  end

  def certificate_authority
    ::CA::CertificateAuthorityFactory.create(ca_resource)
  end

  def signing_params
    certificate_authority.prepare_inputs(current_user, params)
  rescue => error
    raise Forbidden, "Invalid signing parameters: #{error}"
  end

  def ca_resource
    identifier = Sequel.function(:identifier, :resource_id)
    kind = Sequel.function(:kind, :resource_id)
    account = Sequel.function(:account, :resource_id)

    @ca_resource ||= Resource
                     .where(
                       identifier => "conjur/#{service_id}/ca", 
                       kind => 'webservice',
                       account => account
                     )
                     .first
  end

  def service_id
    params[:service_id]
  end

  def account
    params[:account]
  end
end
