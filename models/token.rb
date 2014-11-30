require 'securerandom'
require 'openssl'
require 'base64'


class Token < ActiveRecord::Base
  self.table_name = "service.tokens"

  TTL = 2.months
  NONCE_LENGTH = 12

  before_create :refresh

  belongs_to :user

  def self.get_user(service, token)
    t = includes(:user).where("expired_at < ?", Time.now).
        where(service: service, token: token).first
    return t.nil? ? t : t.user
  end

  def refresh
    self.expired_at = (self.expired_at||Time.now) + TTL
    if self.expired_at < Time.now
       self.expired_at = Time.now + TTL
    end
    self.expired_at
  end

  def self.build_cipher(service, email, password)
    cipher = OpenSSL::Cipher::Cipher.new($config['CIPHER'])
    cipher.encrypt
    cipher.key = $config["#{service.upcase}_KEY"]
    cipher.iv  = iv = cipher.random_iv

    nonce = SecureRandom.random_number(36**12).to_s(36).rjust(NONCE_LENGTH, "0")
    result = cipher.update "#{email}|.|#{password}|.|#{nonce}"
    result << cipher.final
    token = Base64.urlsafe_encode64(result) + '|' + Base64.urlsafe_encode64(iv)

    build(service: service, token: token)
  end

private

  def make_token # TODO
    time = Time.now
    text = "#{user.id} #{time} #{rand(time.to_i)}"
    text += "#{XXhash.xxh32(text, $config['TOKEN_SEED'])}"
    self.token = Digest::SHA256.hexdigest(text+$config["#{service.upcase}_SEED"])
  end

end
