require "net/http"
require "net/https"

class AlwaysVerifySSLCertificates
  class << self
    KNOWN_CA_FILES = %w{ /etc/pki/tls/certs/ca-bundle.crt }
    KNOWN_CA_PATHS = %w{ /etc/ssl/certs /System/Library/OpenSSL/certs/ } # Unsure about last directory (OS X)

    attr_accessor :ca_file, :ca_path

    def discover_ca_file_or_path
      KNOWN_CA_FILES.each do |f|
        if File.exists?(f)
          self.ca_file = f
          return f
        end
      end

      KNOWN_CA_PATHS.each do |p|
        if File.directory?(p)
          self.ca_path = p
          return p
        end
      end

      nil
    end

  end
end

module Net
  class HTTP
    private
      def connect
        D "opening connection to #{conn_address()}..."
        s = timeout(@open_timeout) { TCPSocket.open(conn_address(), conn_port()) }
        D "opened"
        if use_ssl?
          if !AlwaysVerifySSLCertificates.ca_file && !AlwaysVerifySSLCertificates.ca_path
            raise "You must set AlwaysVerifySSLCertificates.ca_file or AlwaysVerifySSLCertificates.ca_path to use SSL." unless AlwaysVerifySSLCertificates.discover_ca_file_or_path
          end

          @ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
          @ssl_context.ca_file     = AlwaysVerifySSLCertificates.ca_file if AlwaysVerifySSLCertificates.ca_file
          @ssl_context.ca_path     = AlwaysVerifySSLCertificates.ca_path if AlwaysVerifySSLCertificates.ca_path
          s = OpenSSL::SSL::SSLSocket.new(s, @ssl_context)
          s.sync_close = true
        end
        @socket = BufferedIO.new(s)
        @socket.read_timeout = @read_timeout
        @socket.debug_output = @debug_output
        if use_ssl?
          if proxy?
            @socket.writeline sprintf('CONNECT %s:%s HTTP/%s',
                                      @address, @port, HTTPVersion)
            @socket.writeline "Host: #{@address}:#{@port}"
            if proxy_user
              credential = ["#{proxy_user}:#{proxy_pass}"].pack('m')
              credential.delete!("\r\n")
              @socket.writeline "Proxy-Authorization: Basic #{credential}"
            end
            @socket.writeline ''
            HTTPResponse.read_new(@socket).value
          end
          s.connect
          if @ssl_context.verify_mode != OpenSSL::SSL::VERIFY_NONE
            s.post_connection_check(@address)
          end
        end
        on_connect
      end
  end
end
