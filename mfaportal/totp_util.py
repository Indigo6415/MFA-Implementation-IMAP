import os
import time
import base64
import hmac
import hashlib
import struct
import qrcode
import io


class TOTP:
    def __init__(self, secret_b32: str):
        self.secret_b32 = secret_b32

    @staticmethod
    def generate_secret(num_bytes: int = 20) -> str:
        return base64.b32encode(os.urandom(num_bytes)).decode("utf-8")

    def _key(self):
        return base64.b32decode(self.secret_b32, casefold=True)

    def generate(self, interval: int = 30, digits: int = 6) -> str:
        key = self._key()
        counter = int(time.time() // interval)
        counter_bytes = struct.pack(">Q", counter)
        hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        offset = hmac_digest[-1] & 0x0F
        code_int = struct.unpack(">I", hmac_digest[offset:offset + 4])[0] & 0x7FFFFFFF
        totp = code_int % (10 ** digits)
        return f"{totp:0{digits}d}"

    def verify(self, token: str, window: int = 1, interval: int = 30, digits: int = 6) -> bool:
        key = self._key()
        token_str = str(token).zfill(digits)
        base_counter = int(time.time()) // interval
        for step in range(-window, window + 1):
            counter = base_counter + step
            counter_bytes = struct.pack(">Q", counter)
            hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
            offset = hmac_digest[-1] & 0x0F
            code_int = struct.unpack(">I", hmac_digest[offset:offset + 4])[0] & 0x7FFFFFFF
            totp = code_int % (10 ** digits)
            if token_str == f"{totp:0{digits}d}":
                return True
        return False

    def otpauth_url(self, issuer: str, account_name: str, digits: int = 6, period: int = 30) -> str:
        return f"otpauth://totp/{issuer}:{account_name}?secret={self.secret_b32}&issuer={issuer}&digits={digits}&period={period}"

    def qr_png_bytes(self, issuer: str, account_name: str) -> bytes:
        url = self.otpauth_url(issuer, account_name)
        qr = qrcode.make(url)
        buf = io.BytesIO()
        qr.get_image().save(buf, format="PNG")
        buf.seek(0)
        return buf.read()
