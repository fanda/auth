require 'sinatra/base'
require 'active_record'
require 'active_support'

$config = YAML::load(File.open('./config/apps/jabba.yml'))[ENV["RACK_ENV"]||'development']

# rewrite $config with ENV variables
$config.keys.each do |key|
  $config[key] = ENV[key] if ENV[key]
end

Dir["./lib/*.rb"].each {|file| require file }
Dir["./models/*.rb"].each {|file| require file }

if ENV['DATABASE_URL']
  ActiveRecord::Base.establish_connection(ENV['DATABASE_URL'])
else
  dbconf = YAML::load(File.open($config['ROOT']+'config/database.yml'))[ENV["RACK_ENV"]||'development']
  ActiveRecord::Base.establish_connection(dbconf)
  ActiveRecord::Base.logger = Logger.new(File.open($config['ROOT']+'log/auth.log', 'a'))
end


class Auth < Sinatra::Base

  register Sinatra::JsonBodyParams

  set :logging, true
  #set :protection, :origin_whitelist => ['https://limitless-tundra-3728.herokuapp.com']

  before do
    content_type :json
    params.slice!(:user, :domain, :token)
  end

  get '*' do
    logger.info "returning error code"
    status 410
  end


  post '/login' do
    # nginx's X-Original-URI (from nginx.conf) is mapped to 'HTTP_X_ORIGINAL_URI' in Sinatra
    # puts request.env['HTTP_X_ORIGINAL_URI']

    if params[:user][:name].include?('@')
      name, domain = params[:user][:name].split('@')
    end
    unless @user = User.get(name||params[:user][:name], domain||params[:domain])
      logger.info "failed authentication"
      status 401
      return
    end

    if @user.password_match?(params[:user][:password])
      logger.info "successful authentication"
      @user.create_session
      status 200
      { token: @user.access_token.token }.to_json
    else
      logger.info "failed authentication"
      status 401
    end
  end


  post '/passwd' do # TODO
    if params[:user][:name].include?('@')
      name, domain = params[:user][:name].split('@')
    end
    @user = User.get(name||params[:user][:name], domain||params[:domain])
    @user.make_reset_password_token
    #Mailer.passwd_user(@user) # TODO
    logger.info "successful authentication"
    status 201
  end


  post '/register' do
    @user = User.new(params[:user].merge(domain: params[:domain]))
    if @user.save
      logger.info "successful registration"
      @user.create_session
      #Mailer.passwd_user(@user) # TODO
      status 201
      { token: @user.access_token.token }.to_json
    else
      logger.info "failed registration"
      if params[:user][:name].include?('@')
        name, domain = params[:user][:name].split('@')
      end
      if User.get(name||params[:user][:name], domain||params[:domain]) # user exists?
        status 405 # Method Not Allowed -  should login
      else
        status 412 # Precondition Failed
      end
    end
  end

  delete '/logout' do
    if @user = Token.get_user('auth', params[:token])
      if @user.destroy_session
        status 200
      else
        status 500
      end
    else
      status 401
    end
  end

  run! if app_file == $0

end
