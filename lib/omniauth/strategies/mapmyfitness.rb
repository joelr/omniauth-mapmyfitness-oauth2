require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class MapMyFitness < OmniAuth::Strategies::OAuth2
      option :name, "mapmyfitness"

      option :client_options, {
        :site => "https://oauth2-api.mapmyapi.com/v7.0",
        :authorize_url => "https://www.mapmyfitness.com/v7.0/oauth2/authorize/",
        :token_url => "https://www.mapmyfitness.com/v7.0/oauth2/uacf/access_token",
        :connection_opts => {
          :headers => {'Api-Key' => ENV['MMF_API_KEY']}
        }
      }

      option :token_options, { :grant_type => 'authorization_code' }

      uid{ raw_info['id'] }

      info{ raw_info }

      info do
        {
          :email => raw_info['email'],
          :name  => raw_info['name'],
          :birthday => raw_info['birthdate']
        }.merge(raw_info)
      end

      def raw_info
        custom_headers = {:"api-key" => ENV['MMF_API_KEY']}
        @raw_info ||= JSON.parse(access_token.get("/v7.0/user/self", {headers: custom_headers}).body)
      end

      def build_access_token
        verifier = request.params['code']
        custom_headers = {:"api-key" => ENV['MMF_API_KEY']}
        client.auth_code.get_token(verifier, {:redirect_uri => callback_url}.merge(token_params.to_hash(:symbolize_keys => true)).merge(headers: custom_headers), {})
      end
    end
  end
end

OmniAuth.config.add_camelization 'mapmyfitness', 'MapMyFitness'
