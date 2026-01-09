import os
import time
import base64
import hmac
import hashlib
import struct
import qrcode


class TOTP:
    def __init__(self, secret):
        self.secret = secret

    def generate_totp(self, interval=30, digits=6) -> str:
        """
        Generate a TOTP based on the current time and the shared secret.

        :param interval: Time step in seconds (default is 30 seconds).
        :param digits: Number of digits in the TOTP (default is 6).
        :return: The generated TOTP as a string.
        """
        # Normalize secret to bytes. Accept either raw bytes or a base32 string.
        if isinstance(self.secret, str):
            key = base64.b32decode(self.secret, casefold=True)
        else:
            key = self.secret

        # Component 1
        # Time counter (number of intervals since epoch)
        counter = int(time.time() // interval)  # 1928571

        # Component 2
        # 8-byte big-endian counter per RFC4226/RFC6238
        counter_bytes = struct.pack(">Q", counter)

        # Combine components 1 and 2 to create HMAC input
        # HMAC-SHA1 digest
        hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()

        # Dynamic truncation to obtain a 31-bit value
        offset = hmac_digest[-1] & 0x0F
        code_int = struct.unpack(
            ">I", hmac_digest[offset:offset + 4])[0] & 0x7FFFFFFF

        # Reduce to requested number of digits and zero-pad
        totp = code_int % (10 ** digits)  # code_int % 1000000
        return f"{totp:0{digits}d}"  # 123984 e.g.

    def verify(self, token, interval=30, digits=6, window=1) -> bool:
        """
        Verify a provided TOTP token against the secret for the given timestamp.

        This allows a small window to account for clock skew (±1 interval).

        :param token: The TOTP token to verify (string or int).
        :param timestamp: Unix timestamp (seconds) to check against.
        :return: True if the token is valid within the allowed window, else False.
        """
        # Get current timestamp
        timestamp = int(time.time())

        # Normalize token to zero-padded string
        token_str = str(token).zfill(6)

        # Normalize secret to bytes (accept raw bytes or base32-encoded string)
        if isinstance(self.secret, str):
            key = base64.b32decode(self.secret, casefold=True)
        else:
            key = self.secret

        # Base counter for provided timestamp
        base_counter = int(timestamp) // interval

        for step in range(-window, window + 1):
            counter = base_counter + step
            counter_bytes = struct.pack(">Q", counter)

            hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
            offset = hmac_digest[-1] & 0x0F
            code_int = struct.unpack(
                ">I", hmac_digest[offset:offset + 4])[0] & 0x7FFFFFFF
            totp = code_int % (10 ** digits)

            if token_str == f"{totp:0{digits}d}":
                return True

        return False

    def generate_totp_qr(self, issuer, account_name) -> str:
        # Setup OTP URL
        otp_url = f"otpauth://totp/{issuer}:{account_name}?secret={self.secret}&issuer={issuer}&digits=6&period=30"

        # Generate QR code
        qr = qrcode.make(otp_url)
        qr.get_image().save("totp_qr.png")

        print("URL:", otp_url)

        return otp_url

    def generate_otp_url(self, issuer, account_name) -> str:
        # Setup OTP URL
        otp_url = f"otpauth://totp/{issuer}:{account_name}?secret={self.secret}&issuer={issuer}&digits=6&period=30"
        return otp_url
