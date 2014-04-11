require "openssl"
require "securerandom"
require "rsa"
require "faraday"
require "rotp"

# Test Data
# secret: [0x7B, 0x0B, 0xFA, 0x82, 0x30, 0xE5, 0x44, 0x24, 0xAB, 0x51, 0x77, 0x7D, 0xAD, 0xBF, 0xD5, 0x37, 0x41, 0x43, 0xE3, 0xB0]
# serial: US-1306-2525-4376
# restore: CR24KPKF51

class BattleNet

  MODEL_SIZE = 16
  MODEL_CHARS = " ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890"

  ENROLL_MODULUS =
    "955e4bd989f3917d2f15544a7e0504eb9d7bb66b6f8a2fe470e453c779200e5e" +
    "3ad2e43a02d06c4adbd8d328f1a426b83658e88bfd949b2af4eaf30054673a14" +
    "19a250fa4cc1278d12855b5b25818d162c6e6ee2ab4a350d401d78f6ddb99711" +
    "e72626b48bd8b5b0b7f3acf9ea3c9e0005fee59e19136cdb7c83f2ab8b0a2a99"

  ENROLL_EXPONENT = "0101"

  ENROLL_PATH = "/enrollment/enroll2.htm"

  ENROLL_DOMAIN = {
    "US" => "http://mobile-service.blizzard.com",
    "EU" => "http://mobile-service.blizzard.com",
    "KR" => "http://mobile-service.blizzard.com",
    "CN" => "http://mobile-service.battlenet.com.cn"
  }

  attr_reader :secret
  attr_reader :serial
  attr_reader :time_offset

  def self.enroll(options = {})
    new.enroll(options = {})
  end

  def initialize(options = {})
    @region = "US"
    @country = "US"
    @verbose = true
  end

  def enroll
    # Generate enrollment data:
    #   00 byte[20] one-time key used to decrypt data when returned
    #   20 byte[2] country code, e.g. US, GB, FR, KR, etc
    #   22 byte[16] model string for this device
    #   38 END
    data = Array.new

    # One-time-pad
    pad = one_time_pad(20)
    data.concat(pad)

    # Country
    data.concat(@country.bytes.to_a)

    # Model
    data.concat(random_model.bytes.to_a)

    # Encrypt with BMA public key
    key_pair = RSA::KeyPair.new(nil, RSA::Key.new(ENROLL_MODULUS.hex, ENROLL_EXPONENT.hex))
    encrypted = key_pair.encrypt(data.pack("C*").force_encoding("UTF-8"))

    conn = Faraday.new(:url => enroll_domain) do |faraday|
      faraday.response :logger if @verbose
      faraday.request :url_encoded
      faraday.adapter Faraday.default_adapter
    end

    response = conn.post do |req|
      req.url ENROLL_PATH
      req.headers["Content-Type"] = "application/octet-stream"
      req.body = encrypted
    end

    # Response data:
    #   00-07 server time (Big Endian)
    #   08-24 serial number (17)
    #   25-44 secret key encrpyted with our pad
    #   45 END
    response_data = response.body.bytes.to_a

    # Get server time offset
    current_time = (Time.now.to_f * 1000).to_i
    server_time = integer_from_8_bytes(response_data[0, 8])
    @time_offset = server_time - current_time

    # Get serial
    @serial = response_data[8, 17].pack("C*")

    # Get secret key
    @secret = response_data[25, 20]
    pad.each_index do |i|
      @secret[i] ^= pad[i]
    end
  end

  def secret_code
    return nil unless has_secret?
    base32_encode(@secret.pack("C*"))
  end

  def restore_code
    return nil unless has_secret? && has_serial?
    OpenSSL::Digest.digest("SHA1", "#{@serial.gsub("-", "")}#{@secret.pack("C*")}").bytes.to_a[-10, 10].map do |byte|
      restore_code_byte_to_char(byte)
    end.join
  end

  def provisioning_url(name = nil)
    return nil unless has_secret?
    name ||= "bnet-account"
    "otpauth://totp/#{name}?secret=#{secret_code}&issuer=Battle.net&digits=8"
  end

  private

  def has_serial?
    !@serial.nil? && !@serial.empty?
  end

  def has_secret?
    !@secret.nil? && !@secret.empty?
  end

  def one_time_pad(length)
    block = Array.new
    while true do
      block.concat OpenSSL::Digest.digest("SHA1", SecureRandom.random_bytes(128)).bytes.to_a
      break if block.length >= length
    end
    block
  end

  def random_model
    MODEL_SIZE.times.map { MODEL_CHARS[SecureRandom.random_number(MODEL_CHARS.length)] }.join
  end

  def enroll_domain
    ENROLL_DOMAIN[@region]
  end

  def integer_from_8_bytes(buf)
    (buf[0]<<56) | (buf[1]<<48) | (buf[2]<<40) | (buf[3]<<32) | (buf[4]<<24) | (buf[5]<<16) | (buf[6]<<8) | buf[7]
  end

  def restore_code_byte_to_char(byte)
    index = byte & 0x1f
    return (index + 48).chr if index <= 9
    index = (index + 65) - 10
    index += 1 if index >= 73
    index += 1 if index >= 76
    index += 1 if index >= 79
    index += 1 if index >= 83
    index.chr
  end

  def base32_encode(str)
    cDIGITS = ('A'..'Z').to_a + ('2'..'7').to_a
    dMASK = 0x1f
    cSHIFT = 5

    bytes = str.unpack('C*')

    paddedLen = 8 * ((bytes.length + 4)/5)

    bits = 0
    haveBits = 0

    b32 = []
    bytes.each do |byte|
      bits = (bits << 8) | byte
      haveBits += 8

      while haveBits >= cSHIFT
        b32 << cDIGITS[dMASK & (bits >> (haveBits - cSHIFT))]
        haveBits -= cSHIFT
      end
      bits &= dMASK
    end

    if haveBits > 0
      b32 << cDIGITS[dMASK & (bits << (cSHIFT - haveBits))]
    end

    b32.join + "=" * (paddedLen - b32.length)
  end

end
