# frozen_string_literal: true

# Register MIME types for certificate responses
Mime::Type.register 'application/x-pem-file', :pem
Mime::Type.register 'application/x-openssh-file', :openssh
