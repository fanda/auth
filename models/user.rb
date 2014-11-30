require 'xxhash'
require 'digest'
require_relative '../passwords/sha512crypt'
require 'openssl'

class User < ActiveRecord::Base
  include SHA512crypt

  before_create :make_symbol
  after_create :create_default_permission

  has_one :access_token
  has_one :permission
  has_many :service_tokens, class_name: "Token", :autosave => true

  def self.get(name, domain)
    where(name: name, domain: domain).first
  end

  def as_json(opt={})
    {
      id: id,
      email: email,
      at: access_token.token
    }
  end

  def email=(e)
    self.name, self.domain = e.split('@')
  end

  def email
    "#{self.name}@#{self.domain}"
  end

  def password=(p)
    self.password_hash = Password.create(p, {salt: (self.salt=make_salt)})
    self.password_schema = self.password_hash.schema
    generate_cipher_tokens(p)
  end

  def password_match?(passphrase)
    Password.new(self.password_hash) == Password.create(passphrase, {salt: self.salt})
  end

  def make_reset_password_token
    # TODO
  end

  def destroy_session
    service_tokens.destroy_all and access_token.destroy # XXX check return values
  end

  def create_session
    destroy_session if access_token and access_token.token
    create_access_token
  end

private

  SALT_SIZE = 16

  def make_salt
    now = Time.now
    # salt max size is 16
    self.salt = Digest::SHA256.hexdigest("#{self.name}#{now}#{rand(now.to_i)}")[0...SALT_SIZE]
  end

  # unique numeric string of length 10, but not primary key
  def make_symbol
    try = 0
    begin
      text = "#{self.email} #{self.salt} #{try += 1}"
      self.symbol = XXhash.xxh32(text, $config['SYMBOL_SEED']).to_s[-9..-1]
    end while User.find_by_symbol(symbol)
    self.symbol
  end

  def create_default_permission
    Permission.create(user_id: id, services: '{'+$config['DEFAULT_SERVICES'].join(',')+'}')
  end


  def generate_cipher_tokens(plain_password)
    $config['CIPHERED_SERVICES'].each do |service|
      service_tokens.build_cipher(service, email, plain_password)
    end
  end


end
