"""In mã TOTP hiện tại, dùng cho script tấn công/test:  python -m scripts.totp [secret]"""
import sys

import pyotp

print(pyotp.TOTP(sys.argv[1] if len(sys.argv) > 1 else "JBSWY3DPEHPK3PXP").now())
