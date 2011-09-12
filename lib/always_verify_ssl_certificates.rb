require 'resolv'
require 'resolv-replace'
require "net/http"
require "net/https"

module AlwaysVerifySSLCertificates
end

if /^1\.9/ =~ RUBY_VERSION
  require 'always_verify_ssl_certificates/1.9'
else
  require 'always_verify_ssl_certificates/1.8'
end
