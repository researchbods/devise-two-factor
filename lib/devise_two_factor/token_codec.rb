module DeviseTwoFactor
  class TokenCodec
    def initialize(nonce = nil)
      @nonce = nonce.nil? ? generate_nonce : Base64.decode64(nonce)
    end

    def encode(sign_in_params)
      message_encryptor.encrypt_and_sign(sign_in_params)
    end

    def decode(token)
      message_encryptor.decrypt_and_verify(token)
    end

    def nonce
      Base64.encode64(@nonce)
    end

    private

    def message_encryptor
      key = ActiveSupport::KeyGenerator.new(Devise.secret_key)
                                       .generate_key(@nonce, key_len)
      ActiveSupport::MessageEncryptor.new(key,
                                          purpose: :login,
                                          expires_in: 1.minute)
    end

    def generate_nonce
      SecureRandom.random_bytes(key_len)
    end

    def key_len
      ActiveSupport::MessageEncryptor.key_len
    end
  end
end
