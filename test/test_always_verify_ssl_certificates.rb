require 'helper'

class TestAlwaysVerifySslCertificates < Test::Unit::TestCase

  def test_retrieve_https_encrypted_google_com
    uri = URI.parse('https://encrypted.google.com/')
    https = Net::HTTP.new(uri.host, uri.port)

    https.use_ssl = true
    https.ca_file = AlwaysVerifySSLCertificates::CA_FILE

    https.start do
      https.request_get(uri.path) do |result|
        assert_instance_of(Net::HTTPOK, result)
      end
    end
  end

end
