module DeviseTwoFactor
  module TwoStepConcern
    extend ActiveSupport::Concern

    included do
      before_action :two_factor_auth,
                            if: :otp_enabled?,
                            only: [:create]
    end

    private

    def two_factor_auth
      devise_parameter_sanitizer.permit(:sign_in,
                                        keys: %i[
                                          otp_attempt
                                        ])

      two_factor_inject_params_from_token! if params[resource_name][:_2fa_token]

      # return if there's an otp_attempt or if authentication succeeds (which..
      # admittedly will run it twice, but I think that might be ok?)
      return if params[:otp_attempt]
      return if warden.authenticate(auth_options)

      show_otp_form
    end

    def two_factor_inject_params_from_token!
      # decode the hash, inject the params
      auth_hash_from_token = token_decoder
                               .decode(params[resource_name][:_2fa_token])

      params[resource_name].merge!(auth_hash_from_token)
      request.params[resource_name].merge!(auth_hash_from_token)
      auth_hash_from_token.each do |k, v|
        request.update_param("#{resource_name}[#{k}]", v)
      end
    end

    def token_decoder
      @token_decoder ||= DeviseTwoFactor::TokenCodec
                         .new(params[resource_name][:_2fa_nonce])
    end


    def show_otp_form
      self.resource = resource_class.new(sign_in_params)
      @devise_two_factor_nonce = token_coder.nonce
      @devise_two_factor_token = token_coder.encode(sign_in_params)
      render 'two_factor/confirm'
    end

    def token_coder
      @token_coder ||= DeviseTwoFactor::TokenCodec.new
    end

    def resource_needs_otp?
      otp_enabled? && (resource.nil? || resource.otp_required_for_login)
    end

    def otp_enabled?
      SecurityConfig.otp_required?
    end
  end
end
