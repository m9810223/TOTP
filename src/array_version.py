"""
    使用 array 取代 byte array 操作以便翻譯
    同時避免 leftshift & xor 時 overflow/underflow
"""


def from_int(num, length, divisor):
    result = [0] * length
    for i in range(length):
        result[~i] = num % divisor
        num //= divisor
    return result


def int_to_bits(num, length):
    """
    int_to_bits(7, 4) -> [0, 1, 1, 1]
    """
    return from_int(num, length, divisor=2)


def bits_to_bytes(arr):
    while len(arr) % 8:
        arr.append(0)
    result = []
    buffer = 0
    for i in range(len(arr)):
        buffer *= 2
        buffer += arr[i]
        if not (i + 1) % 8:
            result.append(buffer)
            buffer = 0
    # print('bits_to_bytes', result)
    return result


def b32d(message):
    """
    input:
        message: all(str) in `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`
    output:
        List[ int in range(128) ]
    """
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    decoder = {alphabet[i]: i for i in range(len(alphabet))}
    base_size = 5
    buffer = []
    buffer_len = 0
    result = []
    for c in message:
        if c not in decoder:
            continue
        buffer_len += base_size
        buffer.extend(int_to_bits(decoder[c], base_size))
        if buffer_len >= 8:
            result.extend(bits_to_bytes(buffer[:8]))
            buffer_len -= 8
            buffer = buffer[8:]
    return result


def sha1(message):
    def bits_xor(*arrs):
        result = arrs[0][:]
        for arr in arrs[1:]:
            for i in range(len(result)):
                result[i] ^= arr[i]
        return result

    def bits_leftrotate(arr, shift_size):
        return arr[shift_size:] + arr[:shift_size]

    def bits_or(*arrs):
        result = arrs[0][:]
        for arr in arrs[1:]:
            for i in range(len(result)):
                result[i] |= arr[i]
        return result

    def bits_and(*arrs):
        result = arrs[0][:]
        for arr in arrs[1:]:
            for i in range(len(result)):
                result[i] &= arr[i]
        return result

    def bits_not(arr):
        return [b ^ 1 for b in arr]

    def bits_add(*arrs):
        result = arrs[0][:]
        for arr in arrs[1:]:
            for i in range(len(result)):
                result[i] += arr[i]
            carry = 0
            for i in range(len(result)):
                result[~i] += carry
                carry = result[~i] // 2
                result[~i] %= 2
        return result

    """
    intput: List[int in range(256)]
    otuput: List[int in range(256)]
    """

    block_size = 512
    word_size = 32
    size = int(block_size / word_size)
    rounds = 80

    # Initial variables
    hash_value = [
        [0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1],
        [1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1],
        [1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0],
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0],
        [1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0],
    ]

    buffer = [b for x in message for b in int_to_bits(x, 8)]

    # append the bit '1' to the message
    buffer.append(1)

    # append k bits '0', where k is the minimum number >= 0 such that the resulting message length ( in bits) is congruent to 448(mod 512)
    message_bit_length = len(message) * 8
    k = (448 - (message_bit_length + 1) % block_size + block_size) % block_size
    buffer.extend([0] * k)

    # append length of message
    buffer.extend(int_to_bits(message_bit_length, 64))

    # Process the message in successive 512-bit chunks
    for j in range(len(buffer) // block_size):
        # break message into 512-bit chunks
        chunk = buffer[block_size * (j) : block_size * (j + 1)]
        words = []
        for i in range(len(chunk) // word_size):
            # break chunk into sixteen 32-bit big-endian words
            word = chunk[word_size * (i) : word_size * (i + 1)]
            words.append(word)

        for i in range(size, rounds):
            x = bits_xor(words[i - 3], words[i - 8], words[i - 14], words[i - 16])
            new_word = bits_leftrotate(x, 1)
            words.append(new_word)

        # Initialize hash value for this chunk:
        a, b, c, d, e = hash_value

        # Main loop
        for i in range(rounds):
            if i < 20:
                f = bits_or(bits_and(b, c), bits_and(bits_not(b), d))
                k = [0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1]
            elif i < 40:
                f = bits_xor(b, c, d)
                k = [0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1]
            elif i < 60:
                f = bits_or(bits_and(b, c), bits_and(b, d), bits_and(c, d))
                k = [1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0]
            else:
                f = bits_xor(b, c, d)
                k = [1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0]

            temp = bits_add(bits_leftrotate(a, 5), f, e, k, words[i])
            e = d
            d = c
            c = bits_leftrotate(b, 30)
            b = a
            a = temp

        # Add this chunk's hash to result so far:
        chunk_hash = (a, b, c, d, e)
        for i in range(len(chunk_hash)):
            hash_value[i] = bits_add(hash_value[i], chunk_hash[i])

    result = [x for h in hash_value for x in bits_to_bytes(h)]
    print('sha1', result)
    return result


def hmac(key, msg, digestmod, blocksize=64):
    # 若 key 長度超過 blocksize 就先 hash
    if len(key) > blocksize:
        key = digestmod(key)

    # 若現在 key 長度小於 blocksize 就用 0x00 填滿
    if len(key) < blocksize:
        key = key + [0] * (blocksize - len(key))

    o_key_pad = [x ^ 0x5C for x in key]
    i_key_pad = [x ^ 0x36 for x in key]

    result = digestmod(o_key_pad + digestmod(i_key_pad + msg))
    print('hmac', result)
    return result


def otp(hasher, length):
    def bytes_to_int(arr):
        result = 0
        for byte in arr:
            result *= 256
            result += byte
        return result

    # 取最右邊的 4 bit 作為 offset
    offset = hasher[-1] & 0xF

    hmac_hash = hasher[offset : offset + 4]
    code = bytes_to_int(hmac_hash) & 0x7FFFFFFF

    # 十進位 truncate
    result = str(code)[-length:]
    print('otp', result)
    return result


if __name__ == '__main__':
    SECRET = 'H' * 32
    INTERVAL = 30
    from time import time

    TIMECODE = from_int(int(time()) // INTERVAL, 8, 256)
    DIGITS = 6
    hasher = hmac(key=b32d(SECRET), msg=TIMECODE, digestmod=sha1)
    print('hasher', hasher)
    totp = otp(hasher, DIGITS)
    print(totp, '(array version)')
