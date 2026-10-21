"""SMTP email delivery for login verification codes."""
import smtplib
from email.message import EmailMessage

from app.config import settings


class EmailDeliveryError(Exception):
    """Raised when SMTP is not configured or cannot deliver an email."""


def send_login_code(recipient: str, username: str, code: str) -> None:
    if not settings.smtp_host or not settings.smtp_from:
        raise EmailDeliveryError("SMTP_HOST and SMTP_FROM must be configured")
    if settings.smtp_use_ssl and settings.smtp_starttls:
        raise EmailDeliveryError("Configure either SMTP_USE_SSL or SMTP_STARTTLS, not both")
    if not settings.smtp_use_ssl and not settings.smtp_starttls:
        raise EmailDeliveryError("SMTP must use SSL or STARTTLS")

    message = EmailMessage()
    message["Subject"] = "Mã xác thực đăng nhập TrustSign"
    message["From"] = settings.smtp_from
    message["To"] = recipient
    message.set_content(
        f"Xin chào {username},\n\n"
        f"Mã xác thực đăng nhập TrustSign của bạn là: {code}\n"
        f"Mã có hiệu lực trong {settings.otp_ttl_minutes} phút và chỉ dùng một lần.\n"
        "Nếu bạn không yêu cầu đăng nhập, hãy bỏ qua email này.\n"
    )

    try:
        if settings.smtp_use_ssl:
            with smtplib.SMTP_SSL(
                settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout_seconds
            ) as smtp:
                if settings.smtp_username:
                    smtp.login(settings.smtp_username, settings.smtp_password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(
                settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout_seconds
            ) as smtp:
                smtp.ehlo()
                if settings.smtp_starttls:
                    smtp.starttls()
                    smtp.ehlo()
                if settings.smtp_username:
                    smtp.login(settings.smtp_username, settings.smtp_password)
                smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise EmailDeliveryError("SMTP delivery failed") from exc
