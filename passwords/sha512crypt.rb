require 'securerandom'
module SHA512crypt
  class Password < String
    attr_reader :salt
    attr_reader :rounds

    class << self
      #   @password = SHA512(word + salt)+salt
      def create(p, options = {})
        @salt = options[:salt] || ''
        Password.new p.crypt("$6$#{@salt}")
      end

      def valid_hash?(h)
        h =~ /^\$6\$[A-Za-z0-9\.\/]{0,16}\$[A-Za-z0-9\.\/]+$/
      end
    end

    # Initializes a SHA512Crypt::Password instance with the data from a stored hash.
    def initialize(raw_hash)
      if true # valid_hash?(raw_hash)
        self.replace(raw_hash)
        @salt, @rounds = split_hash(self)
      else
        raise StandardError, "Invalid SHA512Crypt hash"
      end
      self
    end

    def schema
      'SHA512-CRYPT'
    end

    alias_method :is_password?, :==

  private

    # Returns true if +h+ is a valid hash.
    def valid_hash?(h)
      self.class.valid_hash?(h)
    end

    # call-seq:
    #   split_hash(raw_hash) -> version, cost, salt, hash
    #
    # Splits +h+ into version, cost, salt, and hash and returns them in that order.
    def split_hash(h)
      _, v, c, mash = h.split('$')
      return v, c.to_i, h #[0, 29].to_str, mash[-31, 31].to_str
    end
  end

end
