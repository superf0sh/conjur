# frozen_string_literal: true

# See:
#   https://docs.cucumber.io/cucumber/configuration/#type-registry
# for an explanation of this cucumber feature.

# Replaces:
#   @response_api_key@ with the actual @response_api_key
#
ParameterType(
  name: 'response_api_key',
  regexp: /@response_api_key@/,
  transformer: -> (item) {
    @response_api_key ? item.gsub("@response_api_key@", @response_api_key) : item
  }
)

# Replaces:
#   @host_factory_token_expiration@ with an actual expiration time
#   @host_factory_token_token@ with an actual token
#
DummyToken = Struct.new(:token, :expiration)

ParameterType(
  name: 'host_factory',
  regexp: /@host_factory.+@/,
  transformer: -> (item) {
    token = @host_factory_token || DummyToken.new(
      @result[0]['token'], Time.parse(@result[0]['expiration'])
    )
    
    item.gsub("@host_factory_token_expiration@", token.expiration.utc.iso8601)
        .gsub("@host_factory_token_token@", token.token)
  }
)