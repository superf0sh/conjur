Feature: Conjur signs certificates using a configured CA

  Background:
    Given I am the super-user
    And I successfully PUT "/policies/cucumber/policy/root" with body:
    """
    - !policy
      id: conjur/petstore/ca
      body:
        - !variable private-key
        - !variable public-key

        - !webservice
          annotations:
            ca/private-key: conjur/kitchen/ca/private-key
            ca/certificate-chain: conjur/kitchen/ca/public-key
            ca/max_ttl: P1D
            ca/kind: ssh

        - !group clients

        - !permit
          role: !group clients
          privilege: [ sign ]
          resource: !webservice

    - !host web
    - !host db
    - !user alice

    - !grant
      role: !group conjur/petstore/ca/clients
      members:
      - !host web
      - !user alice
    """
    And I have an ssh CA "petstore"
    And I add the "petstore" ssh CA private key to the resource "cucumber:variable:conjur/kitchen/ca/private-key"
    And I add the "petstore" ssh CA public key to the resource "cucumber:variable:conjur/kitchen/ca/public-key"

  Scenario: The service returns 403 Forbidden if the host doesn't have sign privileges
    Given I login as "cucumber:host:db"
    When I send a public key for "db" to the "petstore" CA with a ttl of "P1D"
    Then the HTTP response status code is 403

  Scenario: I can sign an SSH public key with a configured Conjur SSH CA
    Given I login as "cucumber:host:web"
    When I send a public key for "web" to the "petstore" CA with a ttl of "P1D"
    Then the HTTP response status code is 201
    And the HTTP response content type is "application/json"
    And the resulting json certificate is valid according to the "petstore" ssh CA

  Scenario: I can receive the result directly as a PEM formatted certificate
    Given I login as "cucumber:host:web"
    When I send a public key for "web" to the "petstore" CA with a ttl of "P1D"
    Then the HTTP response status code is 201
    And the HTTP response content type is "application/x-pem-file"
    And the resulting pem certificate is valid according to the "petstore" ssh CA

  Scenario: I can receive the result directly as a OpenSSH formatted certificate
    Given I login as "cucumber:host:web"
    When I send a public key for "web" to the "petstore" CA with a ttl of "P1D"
    Then the HTTP response status code is 201
    And the HTTP response content type is "application/x-openssh-file"
    And the resulting openssh certificate is valid according to the "petstore" ssh CA

  # Scenario: I can sign a CSR using an encrypted CA private key
  #   Given I login as "cucumber:host:table"
  #   When I send a CSR for "table" to the "dining-room" CA with a ttl of "P6M" and CN of "table"
  #   Then the HTTP response status code is 201
  #   And the resulting json certificate is valid according to the "dining-room" intermediate CA
