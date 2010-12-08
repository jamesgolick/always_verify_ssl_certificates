require "net/http"
require "net/https"

class AlwaysVerifySSLCertificates
  class << self
    attr_accessor :ca_file
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
          if !AlwaysVerifySSLCertificates.ca_file
            raise "You must set AlwaysVerifySSLCertificates.ca_file to use SSL."
          end

          @ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
          @ssl_context.ca_file     = AlwaysVerifySSLCertificates.ca_file
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
