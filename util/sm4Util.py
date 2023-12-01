# -*- coding: utf-8 -*-
import base64

from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
import binascii
import os

def str_to_hexStr(hex_str):
    """
    字符串转hex
    :param hex_str: 字符串
    :return: hex
    """
    hex_data = hex_str.encode('utf-8')
    str_bin = binascii.unhexlify(hex_data)
    return str_bin.decode('utf-8')

def encrypt(crypt_sm4,encrypt_key, value):
    """
    国密sm4加密
    :param encrypt_key: sm4加密key
    :param value: 待加密的字符串
    :return: sm4加密后的hex值
    """
    crypt_sm4.set_key(encrypt_key, SM4_ENCRYPT)
    encrypt_value = crypt_sm4.crypt_ecb(value)  # bytes类型
    return encrypt_value.hex()

def decrypt(crypt_sm4,decrypt_key, encrypt_value):
    """
    国密sm4解密
    :param decrypt_key:sm4加密key
    :param encrypt_value: 待解密的hex值
    :return: 原字符串
    """
    crypt_sm4.set_key(decrypt_key, SM4_DECRYPT)
    decrypt_value = crypt_sm4.crypt_ecb(bytes.fromhex(encrypt_value))  # bytes类型
    return str_to_hexStr(decrypt_value.hex())

def getKey():
    key = os.urandom(16)
    encoded_string = base64.b64encode(key)
    return encoded_string.decode()

def str2byte(key):
    s = key.encode()
    return base64.b64decode(s)

if __name__ == '__main__':
    key = os.urandom(16)
    print(key)
    encoded_string = base64.b64encode(key)
    print(encoded_string)
    str = encoded_string.decode()

    #print(base64.b64encode(key).decode())
    s = str.encode()
    ss = base64.b64decode(str.encode())
    print(ss)
    # key = os.urandom(16)
    # str = "Hello@2023"
    # value = bytes(str, encoding = "utf8")
    # crypt_sm4 = CryptSM4()
    #
    # # 加密
    # enc_value = encrypt(crypt_sm4, key, value)
    # print(enc_value)
    #
    # # 解密
    # dec_value = decrypt(crypt_sm4, key, enc_value)
    # print(dec_value)
