require 'util/error_class'

module CA
  CertificateAuthorityTypeUndefined = ::Util::ErrorClass.new(
    "'{0}' wasn't in the available certificate authority types"
  )
end