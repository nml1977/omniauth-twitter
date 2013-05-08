require 'omniauth-oauth'
require 'multi_json'

module OmniAuth
  module Strategies
    class Twitter < OmniAuth::Strategies::OAuth
      option :name, 'twitter'
      option :client_options, {:authorize_path => '/oauth/authenticate',
                               :site => 'https://api.twitter.com',
                               :proxy => ENV['http_proxy'] ? URI(ENV['http_proxy']) : nil}

      uid { access_token.params[:user_id] }

      info do
        {
          :nickname => raw_info['screen_name'],
          :name => raw_info['name'],
          :location => raw_info['location'],
          :image => options[:secure_image_url] ? raw_info['profile_image_url_https'] : raw_info['profile_image_url'],
          :description => raw_info['description'],
          :urls => {
            'Website' => raw_info['url'],
            'Twitter' => "https://twitter.com/#{raw_info['screen_name']}",
          }
        }
      end

      extra do
        { :raw_info => raw_info }
      end

      def raw_info
        @raw_info ||= MultiJson.load(access_token.get('/1.1/account/verify_credentials.json?include_entities=false&skip_status=true').body)
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end

      # alias :old_request_phase :request_phase

      def request_phase
        provider_timestamp_cache_key = request.env["rack.session"]["omniauth.params"]["pts"]
        RAILS_DEFAULT_LOGGER.error "provider_timestamp_cache_key = #{provider_timestamp_cache_key}"
        
        request_token = consumer.get_request_token({:oauth_callback => callback_url}, options.request_params)
        oauth = {'callback_confirmed' => request_token.callback_confirmed?, 'request_token' => request_token.token, 'request_secret' => request_token.secret}
        Rails.cache.write(provider_timestamp_cache_key, oauth)
      
        if request_token.callback_confirmed?
          redirect request_token.authorize_url(options[:authorize_params])
        else
          redirect request_token.authorize_url(options[:authorize_params].merge(:oauth_callback => callback_url))
        end

      rescue ::Timeout::Error => e
        fail!(:timeout, e)
      rescue ::Net::HTTPFatalError, ::OpenSSL::SSL::SSLError => e
        fail!(:service_unavailable, e)
      end

      def callback_phase
        provider_timestamp_cache_key = request.env["omniauth.params"]["pts"]
        RAILS_DEFAULT_LOGGER.error "provider_timestamp_cache_key = #{provider_timestamp_cache_key}"

        raise OmniAuth::NoSessionError.new("Session Expired") if provider_timestamp_cache_key.nil?
        
        oauth = Rails.cache.read(provider_timestamp_cache_key)
        request_token = ::OAuth::RequestToken.new(consumer, oauth.delete('request_token'), oauth.delete('request_secret'))

        opts = {}
        if oauth['callback_confirmed']
          opts[:oauth_verifier] = request['oauth_verifier']
        else
          opts[:oauth_callback] = callback_url
        end

        @access_token = request_token.get_access_token(opts)
        super
      rescue ::Timeout::Error => e
        fail!(:timeout, e)
      rescue ::Net::HTTPFatalError, ::OpenSSL::SSL::SSLError => e
        fail!(:service_unavailable, e)
      rescue ::OAuth::Unauthorized => e
        fail!(:invalid_credentials, e)
      rescue ::MultiJson::DecodeError => e
        fail!(:invalid_response, e)
      rescue ::OmniAuth::NoSessionError => e
        fail!(:session_expired, e)
      end

      # def request_phase
        # RAILS_DEFAULT_LOGGER.error "session['omniauth.params'] = #{session['omniauth.params'].inspect}"
#         
        # force_login = session['omniauth.params'] ? session['omniauth.params']['force_login'] : nil
#         
        # RAILS_DEFAULT_LOGGER.error "force_login = #{force_login}"
#         
        # screen_name = session['omniauth.params'] ? session['omniauth.params']['screen_name'] : nil
#         
        # RAILS_DEFAULT_LOGGER.error "screen_name = #{screen_name}"
#         
        # x_auth_access_type = session['omniauth.params'] ? session['omniauth.params']['x_auth_access_type'] : nil
#         
        # RAILS_DEFAULT_LOGGER.error "x_auth_access_type = #{x_auth_access_type}"
#         
        # if force_login && !force_login.empty?
          # options[:authorize_params] ||= {}
          # options[:authorize_params].merge!(:force_login => 'true')
        # end
        # if screen_name && !screen_name.empty?
          # options[:authorize_params] ||= {}
          # options[:authorize_params].merge!(:force_login => 'true', :screen_name => screen_name)
        # end
        # if x_auth_access_type
          # options[:request_params] ||= {}
          # options[:request_params].merge!(:x_auth_access_type => x_auth_access_type)
        # end
# 
        # if session['omniauth.params'] && session['omniauth.params']["use_authorize"] == "true"
          # options.client_options.authorize_path = '/oauth/authorize'
        # else
          # options.client_options.authorize_path = '/oauth/authenticate'
        # end
# 
        # old_request_phase
      # end

    end
  end
end
