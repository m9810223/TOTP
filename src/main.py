def cast_to_bytes(message) -> bytes:
    if isinstance(message, str):
        message = message.encode()
    elif isinstance(message, int):
        """
        ref: https://docs.python.org/3/library/stdtypes.html#int.to_bytes
        """
        message = message.to_bytes((message.bit_length() + 7) // 8, 'big')
    elif not isinstance(message, bytes):
        raise TypeError
    return message


def truncate(x, length):
    return x & ((2**length) - 1)


def leftrotate(x, shift_size=1, length=32):
    return ((x << shift_size) | (x >> (length - shift_size))) & ((2**length) - 1)


def sha1(message=b''):
    # print('sha1-message', [x for x in message])
    """
    ref: https://zh.wikipedia.org/wiki/SHA-1
    """

    message = cast_to_bytes(message)

    block_size = 512
    word_size = 32
    size = int(block_size / word_size)
    rounds = 80

    # Initial variables
    hash_value = [
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    ]

    buffer = int.from_bytes(message, 'big')

    # append the bit '1' to the message
    buffer <<= 1
    buffer |= 1

    # append k bits '0', where k is the minimum number >= 0 such that the resulting message length ( in bits) is congruent to 448(mod 512)
    # k = block_size - (message_bit_length + 1 + block_size - 448) % block_size
    message_bit_length = len(message) * 8
    k = (448 - (message_bit_length + 1) + block_size) % block_size
    buffer <<= k

    # append length of message
    buffer <<= 64
    buffer |= truncate(message_bit_length, 64)

    chunks = []
    while buffer:
        words = truncate(buffer, block_size)
        chunk = []
        while len(chunk) < size:
            new = truncate(words, word_size)
            chunk.append(new)
            words >>= word_size
        chunks.append(chunk[::-1])
        buffer >>= block_size
    chunks = chunks[::-1]

    # Process the message in successive 512-bit chunks
    for words in chunks:
        for i in range(size, rounds):
            new_word = leftrotate(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16])
            words.append(new_word)

        # Initialize hash value for this chunk:
        a, b, c, d, e = hash_value

        # Main loop
        for i in range(rounds):
            if i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = truncate(leftrotate(a, 5) + f + e + k + words[i], word_size)
            e = d
            d = c
            c = leftrotate(b, 30)
            b = a
            a = temp

        # Add this chunk's hash to result so far:
        chunk_hash = (a, b, c, d, e)
        for i in range(len(chunk_hash)):
            hash_value[i] += chunk_hash[i]
            hash_value[i] = truncate(hash_value[i], word_size)

    # Produce the final hash value (big-endian):
    result = ''.join(hex(x)[2:].zfill(8) for x in hash_value)

    result = bytes.fromhex(result)
    # print('hash_value', [x for x in result])
    return result


def hmac(key, msg, digestmod, blocksize=64):
    """
    ref:
        https://zh.wikipedia.org/wiki/HMAC
        https://csrc.nist.gov/csrc/media/publications/fips/198/archive/2002-03-06/documents/fips-198a.pdf
    """

    key = cast_to_bytes(key)
    msg = cast_to_bytes(msg)

    def bytes_xor(x, y):
        # byteorder = 'big'
        # x = int.from_bytes(x, byteorder)
        # y = int.from_bytes(y, byteorder)
        # result = x ^ y
        # result = result.to_bytes((result.bit_length() + 7) // 8, byteorder)
        # return result
        return bytes(x[i] ^ y[i] for i in range(min(len(x), len(y))))

    # 若 key 長度超過 blocksize 就先 hash
    if len(key) > blocksize:
        key = digestmod(key)

    # 若現在 key 長度小於 blocksize 就用 0x00 填滿
    if len(key) < blocksize:
        key = key + b'\x00' * (blocksize - len(key))

    o_key_pad = bytes_xor(key, b'\x5c' * blocksize)
    i_key_pad = bytes_xor(key, b'\x36' * blocksize)

    result = digestmod(o_key_pad + digestmod(i_key_pad + msg))

    return result


def b32d(message):
    """
    ref: https://en.wikipedia.org/wiki/Base32
    """

    message = cast_to_bytes(message)

    def baseXdecoder(base_size):
        alphabet = {5: b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'}[base_size]
        decoder = {alphabet[i]: i for i in range(2**base_size)}
        return decoder

    base_size = 5
    decoder = baseXdecoder(base_size)

    buffer = 0
    buffer_len = 0

    result = []
    for c in message:
        if c not in decoder:
            continue
        buffer <<= base_size
        buffer |= decoder[c]
        buffer_len += base_size
        if buffer_len >= 8:
            new = buffer >> (buffer_len - 8)
            buffer_len -= 8
            buffer = truncate(buffer, buffer_len)
            result.append(new)

    result = bytes(result)
    return result


def otp(hasher, length):
    hasher = bytearray(hasher)

    # 取最右邊的 4 bit 作為 offset
    offset = hasher[-1] & 0xF
    hmac_hash = bytes(hasher[offset : offset + 4])
    code = int.from_bytes(hmac_hash, 'big') & 0x7FFFFFFF

    result = str(code)[-length:]
    return result


def totp_pyotp(message):
    if isinstance(message, bytes):
        message = message.decode()
    from pyotp import TOTP

    result = TOTP(message).now()
    print(result, '(use pyotp)')
    return result


def totp_builtin_lib(key, msg, length):
    key = cast_to_bytes(key)
    msg = cast_to_bytes(msg)
    missing = len(key) % 8
    if missing != 0:
        key += b'=' * (8 - missing)
    from base64 import b32decode

    key = b32decode(key)
    import hmac
    from hashlib import sha1

    hasher = hmac.new(key, msg, sha1).digest()

    hmac_hash = bytearray(hasher)

    # 取最右邊的 4 bit 作為 offset
    offset = hmac_hash[-1] & 0xF

    code = (
        (hmac_hash[offset] & 0b01111111) << 24
        | (hmac_hash[offset + 1] & 0b11111111) << 16
        | (hmac_hash[offset + 2] & 0b11111111) << 8
        | (hmac_hash[offset + 3] & 0b11111111)
    )  # ref: pyotp

    result = str(code % (10**length)).zfill(length)
    print(result, '(use only builtin lib)')
    return result


def main(key, msg, length, b32d_func, digestmod, hmac_func, otp_func):
    """
    use:
        1. python `time` library
        1. self-made functions:
            - base32 decode
            - SHA-1
            - HMAC
            - TOTP
    """
    key = b32d_func(key)
    hasher = hmac_func(key=key, msg=msg, digestmod=digestmod)

    result = otp_func(hasher, length)
    print(result, '(my)')
    return result


if __name__ == '__main__':
    DIGITS = 6
    INTERVAL = 30
    from time import time

    TIMECODE = (int(time()) // INTERVAL).to_bytes(8, 'big')
    SECRET = 'H' * 32

    # self-made
    main(SECRET, TIMECODE, DIGITS, b32d, sha1, hmac, otp)

    # use pyotp
    totp_pyotp(SECRET)

    # use python built-in library
    totp_builtin_lib(SECRET, TIMECODE, DIGITS)


"""
(notes) 

str bytes int bytearray hex_str 互換


str_.encode() -> bytes
bytes_.decode() -> str

int_.to_bytes(length,byteorder) -> bytes
int.from_bytes(bytes_,byteorder) -> int

byteorder='big' 表示 bytes 的左邊對應高位數

bytearray(bytes_) -> bytearray
bytes(bytearray_) -> bytes

bytes(int_) -> b'\x00' * int_

bytes_.hex() -> hex_str
bytes.fromhex(hex_str_) -> bytes

"""
