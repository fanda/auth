require 'openssl'
require 'base64'

class AccessToken < ActiveRecord::Base
  self.primary_key = :token

  TTL = 2.months

  before_create :make_token, :refresh

  belongs_to :user

  def refresh
    self.expired_at = (self.expired_at||Time.now) + TTL
  end

private

  def make_token
    time = Time.now
    try = 0
    begin
      text = "#{user.id} #{time} #{rand(time.to_i)} #{try += 1}"
      text += "#{XXhash.xxh32(text, $config['TOKEN_SEED'])}"
      self.token = Base64.urlsafe_encode64(
        OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), $config['ACCESS_TOKEN_SEED'], text)
      ).strip
    end while AccessToken.find_by_token(self.token)
  end

end
