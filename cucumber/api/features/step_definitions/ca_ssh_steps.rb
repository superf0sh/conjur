Given(/^I have an ssh CA "([^"]*)"$/) do |ca_name|
  ssh_ca[ca_name] ||= generate_ssh_ca(ca_name)
end

Given(/^I add the "([^"]*)" ssh CA private key to the resource "([^"]*)"$/) do |ca_name, resource_id|
  Secret.create resource_id: resource_id, value: ssh_ca[ca_name].private_key
end

Given(/^I add the "([^"]*)" ssh CA public key to the resource "([^"]*)"$/) do |ca_name, resource_id|
  Secret.create resource_id: resource_id, value: ssh_ca[ca_name].public_key
end

When(/^I send a public key for "([^"]*)" to the "([^"]*)" CA with a ttl of "([^"]*)"$/) do |id_name, service_name, ttl|
  host = create_ssh_key(id_name)
  path = "/ca/cucumber/#{service_name}/sign"

  body = <<~BODY
    ttl=#{ttl}&public_key=#{CGI.escape(host.public_key)}
  BODY
  try_request false do
    post_json path, body
  end
end

Then(/^the resulting (pem|json|openssh) certificate is valid according to the "([^"]*)" ssh CA$/) do |type, ca_name|
  pending # Write code here that turns the phrase above into concrete actions
end