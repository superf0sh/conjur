# frozen_string_literal: true

# This is an API app - we don't need cookies nor shared secrets
Possum::Application.config.secret_key_base = SecureRandom.alphanumeric(128)
