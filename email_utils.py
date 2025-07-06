import os
from sendgrid.helpers.mail import Mail as SGMail
from sendgrid.helpers.mail import TrackingSettings, ClickTracking, OpenTracking
from sendgrid import SendGridAPIClient


MAIL_USERNAME = os.getenv('MAIL_USERNAME')


# Sendgrid API for mail
def send_reset_email_via_sendgrid(to_email: str, reset_url: str):
    message = SGMail(
        from_email=MAIL_USERNAME,
        to_emails=to_email,
        subject="Password Reset Request",

        plain_text_content=(
            "Hi,\n\n"
            "To reset your password, visit:\n"
            f"{reset_url}\n\n"
            "If you did not request this, just ignore this email."
        ),

        html_content=(
            "<p>Hi,</p>"
            f"<p>To reset your password, click <a href='{reset_url}'>here</a>.</p>"
            "<p>If you did not request this, you can ignore this email.</p>"
        )
    )

    message.tracking_settings = TrackingSettings(
        click_tracking=ClickTracking(enable=False, enable_text=False),
        open_tracking=OpenTracking(enable=False)
    )

    sg = SendGridAPIClient(os.environ["SENDGRID_API_KEY"])
    resp = sg.send(message)
    if resp.status_code >= 400:
        raise Exception(f"SendGrid error {resp.status_code}")

