module DeviseTwoFactor
  module StrategyMixin
    def second_step?
      authentication_hash.eql?(authentication_hash_from_token)
    end

    def authentication_hash_from_token
      token_codec.decode(params[scope][:_2fa_token])
    end

    def token_codec
      DeviseTwoFactor::TokenCodec.new(params[scope][:_2fa_nonce])
    end
  end
end
