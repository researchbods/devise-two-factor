require "devise_two_factor/token_codec"

module DeviseTwoFactor
  module ViewHelpers
    def devise_two_factor_second_step_fields(scope)
      hidden_field_tag("#{scope}[_2fa_nonce]",
                       @devise_two_factor_nonce) +
      hidden_field_tag("#{scope}[_2fa_token]",
                       @devise_two_factor_token)
    end
  end
end
