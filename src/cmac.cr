require "openssl"

class CMAC
  class Error < Exception; end

  ZERO_BLOCK     = Bytes.new(16)
  CONSTANT_BLOCK = Bytes[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87]

  @key : Bytes
  @key1 : Bytes
  @key2 : Bytes

  def initialize(key)
    @key = _derive_key(key.to_slice)
    @key1, @key2 = _generate_subkeys(@key)
  end

  def sign(message, truncate = 16) : Bytes
    raise Error.new("Tag cannot be greater than maximum (16 bytes)") if truncate > 16
    raise Error.new("Tag cannot be less than minimum (8 bytes)") if truncate < 8

    message = message.to_slice

    if _needs_padding?(message)
      message = _pad_message(message)
      final_block = @key2
    else
      final_block = @key1
    end

    last_ciphertext = ZERO_BLOCK
    count = message.size // 16
    range = Range.new(0, count - 1)

    blocks = range.map do |i|
      starting = 16 * i
      ending = starting + 16
      message[starting...ending]
    end

    blocks.each_with_index do |block, i|
      block = _xor(final_block, block) if i == range.end
      block = _xor(block, last_ciphertext)
      last_ciphertext = _encrypt_block(@key, block)
    end

    last_ciphertext[0...truncate]
  end

  def valid_message?(tag, message) : Bool
    other_tag = sign(message)
    _secure_compare?(tag, other_tag)
  end

  def _derive_key(key : Bytes) : Bytes
    if key.size == 16
      key
    else
      cmac = CMAC.new(ZERO_BLOCK)
      cmac.sign(key)
    end
  end

  def _encrypt_block(key : Bytes, block : Bytes) : Bytes
    cipher = OpenSSL::Cipher.new("AES-128-ECB")
    cipher.encrypt
    cipher.padding = false
    cipher.key = key

    encrypted_data = IO::Memory.new
    encrypted_data.write(cipher.update(block))
    encrypted_data.write(cipher.final)
    encrypted_data.to_slice
  end

  def _generate_subkeys(key : Bytes)
    key0 = _encrypt_block(key, ZERO_BLOCK)
    key1 = _next_key(key0)
    key2 = _next_key(key1.clone)
    {key1, key2}
  end

  def _needs_padding?(message : Bytes) : Bool
    (message.size == 0) || (message.size % 16 != 0)
  end

  def _next_key(key : Bytes) : Bytes
    if key[0] < 0x80
      _leftshift(key)
    else
      _xor(_leftshift(key), CONSTANT_BLOCK)
    end
  end

  def _leftshift(input : Bytes) : Bytes
    io = IO::Memory.new(input)

    words = Slice(UInt32).new(4)
    4.times { |i| words[i] = io.read_bytes(UInt32, IO::ByteFormat::BigEndian) }
    words.reverse!

    overflow = 0_u32
    words.map! do |word|
      new_word = word << 1
      new_word |= overflow
      overflow = (word & 0x80000000_u32) >= 0x80000000_u32 ? 1_u32 : 0_u32
      new_word
    end

    io.rewind
    words.reverse!
    words.each { |word| io.write_bytes(word, IO::ByteFormat::BigEndian) }
    io.to_slice
  end

  def _pad_message(message : Bytes) : Bytes
    padded_length = message.size + 16 - (message.size % 16)
    ljust = padded_length - (message.size + 1)

    io = IO::Memory.new
    io.write message
    io.write_byte 0x80_u8
    io.write(Bytes.new(ljust)) if ljust > 0
    io.to_slice
  end

  def _secure_compare?(a : Bytes, b : Bytes) : Bool
    return false unless a.size == b.size

    result = 0
    b.each_with_index do |byte, i|
      result |= byte ^ a[i]
    end
    result == 0
  end

  def _xor(a : Bytes, b : Bytes) : Bytes
    io = IO::Memory.new
    length = {a.size, b.size}.min
    length.times do |i|
      io.write_byte(a[i] ^ b[i])
    end
    io.to_slice
  end
end
