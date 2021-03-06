require 'uri'
require 'command_class'

module Authentication
  module AuthnOidc

    # TODO:
    # dependencies: get key for decryption
    # input: request_body type: raw text,  contains jwt_signed {id_token_encrypted + expiration_time + user_name }
    # actions:
    # - decode body
    # - Validate input
    # - Validate JWT signing token
    # - Decrypt ID token
    GetOidcConjurToken = CommandClass.new(
      dependencies: { },
      inputs: %i(request_body)
    ) do

      def call
        # validate_signing
        oidc_conjur_token
        # decrypt_token
      end

      private


      def oidc_conjur_token
        ConjurToken.new(
          id_token_encrypted: id_token_encrypted,
          user_name: user_name,
          expiration_time: expiration_time
          )
      end

      def decoded_body
        @decoded_body ||= URI.decode_www_form(@request_body)
      end

      def id_token_encrypted
        @id_token_encrypted ||= decoded_body.assoc('id_token_encrypted').last
      end

      def user_name
        @user_name ||= decoded_body.assoc('user_name').last
      end

      def expiration_time
        @expiration_time ||= decoded_body.assoc('expiration_time').last
      end

    end
  end
end
