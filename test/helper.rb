require 'test/unit'
require 'net/https'
require 'uri'

$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
$LOAD_PATH.unshift(File.dirname(__FILE__))
require 'always_verify_ssl_certificates'

class Test::Unit::TestCase
end
