import smtplib
import traceback
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import os

load_dotenv()

SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", 587))
SMTP_USER     = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
ADMIN_EMAIL   = os.getenv("ADMIN_EMAIL")


def _send(to: str, subject: str, html: str) -> None:
    print(f"[EMAIL] Attempting to send '{subject}' to {to}")
    print(f"[EMAIL] SMTP_HOST={SMTP_HOST}, SMTP_PORT={SMTP_PORT}, SMTP_USER={SMTP_USER}")

    if not SMTP_USER or not SMTP_PASSWORD:
        raise ValueError("SMTP_USER or SMTP_PASSWORD is not set in .env")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = SMTP_USER
    msg["To"]      = to
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
        server.set_debuglevel(1)       # prints full SMTP conversation to terminal
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, to, msg.as_string())
        print(f"[EMAIL] ✓ Sent successfully to {to}")


def send_admin_welcome(admin_email: str) -> None:
    _send(
        to=admin_email,
        subject="[PFE 2026] Welcome, Administrator!",
        html=f"""
        <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;background:#f5f2eb;border-radius:12px">
          <div style="background:#1a1a2e;border-radius:8px;padding:20px 24px;margin-bottom:24px">
            <h2 style="color:#c9a96e;margin:0;font-size:18px">PFE 2026 · Welcome</h2>
          </div>
          <p style="color:#4a4a6a;font-size:15px">Hello <strong>Administrator</strong>,</p>
          <p style="color:#4a4a6a;margin-top:12px;line-height:1.6">
            Your admin account has been created on the <strong>PFE 2026 platform</strong>.
            You have full access to manage users, approve registrations, and oversee the platform.
          </p>
          <table style="width:100%;border-collapse:collapse;margin:20px 0;background:#fff;border-radius:8px;overflow:hidden">
            <tr style="border-bottom:1px solid #f0ece4">
              <td style="padding:12px 16px;color:#8a8aaa;font-size:13px">Email</td>
              <td style="padding:12px 16px;color:#1a1a2e;font-weight:500">{admin_email}</td>
            </tr>
            <tr style="border-bottom:1px solid #f0ece4">
              <td style="padding:12px 16px;color:#8a8aaa;font-size:13px">Role</td>
              <td style="padding:12px 16px;color:#1a1a2e;font-weight:500">Administrator</td>
            </tr>
            <tr>
              <td style="padding:12px 16px;color:#8a8aaa;font-size:13px">Status</td>
              <td style="padding:12px 16px;color:#1a6b45;font-weight:500">✓ Active</td>
            </tr>
          </table>
          <div style="margin:28px 0;text-align:center">
            <a href="http://localhost:5173/login"
               style="background:#1a1a2e;color:#e8e4d9;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:500;font-size:14px">
              Go to platform →
            </a>
          </div>
        </div>
        """,
    )


def send_new_user_notification(user_email: str, user_name: str) -> None:
    _send(
        to=ADMIN_EMAIL,
        subject=f"[PFE 2026] New user registration: {user_name}",
        html=f"""
        <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;background:#f5f2eb;border-radius:12px">
          <div style="background:#1a1a2e;border-radius:8px;padding:20px 24px;margin-bottom:24px">
            <h2 style="color:#c9a96e;margin:0;font-size:18px">PFE 2026 · New Registration</h2>
          </div>
          <p style="color:#4a4a6a">A new user has registered and is awaiting your approval:</p>
          <table style="width:100%;border-collapse:collapse;margin:20px 0;background:#fff;border-radius:8px;overflow:hidden">
            <tr style="border-bottom:1px solid #f0ece4">
              <td style="padding:12px 16px;color:#8a8aaa;font-size:13px">Name</td>
              <td style="padding:12px 16px;color:#1a1a2e;font-weight:500">{user_name}</td>
            </tr>
            <tr style="border-bottom:1px solid #f0ece4">
              <td style="padding:12px 16px;color:#8a8aaa;font-size:13px">Email</td>
              <td style="padding:12px 16px;color:#1a1a2e">{user_email}</td>
            </tr>
            <tr>
              <td style="padding:12px 16px;color:#8a8aaa;font-size:13px">Status</td>
              <td style="padding:12px 16px;color:#e67e22;font-weight:500">⏳ Pending approval</td>
            </tr>
          </table>
          <p style="color:#8a8aaa;font-size:13px">Log in to the admin dashboard to approve or reject this account.</p>
        </div>
        """,
    )


def send_approval_notification(user_email: str, user_name: str) -> None:
    _send(
        to=user_email,
        subject="[PFE 2026] Your account has been approved!",
        html=f"""
        <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;background:#f5f2eb;border-radius:12px">
          <div style="background:#1a1a2e;border-radius:8px;padding:20px 24px;margin-bottom:24px">
            <h2 style="color:#c9a96e;margin:0;font-size:18px">PFE 2026 · Account Approved</h2>
          </div>
          <p style="color:#4a4a6a">Hello <strong>{user_name}</strong>,</p>
          <p style="color:#4a4a6a;margin-top:12px;line-height:1.6">
            Great news — the administrator has approved your account. You can now log in.
          </p>
          <div style="margin:28px 0;text-align:center">
            <a href="http://localhost:5173/login"
               style="background:#1a1a2e;color:#e8e4d9;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:500;font-size:14px">
              Log in now →
            </a>
          </div>
        </div>
        """,
    )


def send_rejection_notification(user_email: str, user_name: str) -> None:
    _send(
        to=user_email,
        subject="[PFE 2026] Account registration update",
        html=f"""
        <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;background:#f5f2eb;border-radius:12px">
          <div style="background:#1a1a2e;border-radius:8px;padding:20px 24px;margin-bottom:24px">
            <h2 style="color:#c9a96e;margin:0;font-size:18px">PFE 2026 · Registration Update</h2>
          </div>
          <p style="color:#4a4a6a">Hello <strong>{user_name}</strong>,</p>
          <p style="color:#4a4a6a;margin-top:12px;line-height:1.6">
            Unfortunately, your registration request has not been approved at this time.
            Please contact the admin team for more information.
          </p>
        </div>
        """,
    )


def send_feedback_notification(admin_email: str, user_name: str, user_email: str, message: str) -> None:
    """Notify admin of new feedback submission."""
    _send(
        to=admin_email,
        subject=f"[PFE 2026] New feedback from {user_name}",
        html=f"""
        <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;background:#f5f2eb;border-radius:12px">
          <div style="background:#1a1a2e;border-radius:8px;padding:20px 24px;margin-bottom:24px">
            <h2 style="color:#c9a96e;margin:0;font-size:18px">PFE 2026 · New Feedback</h2>
          </div>
          <p style="color:#4a4a6a">You received a new feedback from <strong>{user_name}</strong> ({user_email}):</p>
          <div style="background:#fff;border-radius:8px;padding:16px 20px;margin:20px 0;border-left:3px solid #c9a96e;color:#4a4a6a;font-style:italic;line-height:1.6">
            "{message}"
          </div>
          <p style="color:#8a8aaa;font-size:13px">Log in to the admin dashboard to approve or reject this feedback.</p>
        </div>
        """,
    )


def send_feedback_approved(user_email: str, user_name: str) -> None:
    """Notify user their feedback was approved and published."""
    _send(
        to=user_email,
        subject="[PFE 2026] Your feedback has been published!",
        html=f"""
        <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;background:#f5f2eb;border-radius:12px">
          <div style="background:#1a1a2e;border-radius:8px;padding:20px 24px;margin-bottom:24px">
            <h2 style="color:#c9a96e;margin:0;font-size:18px">PFE 2026 · Feedback Published</h2>
          </div>
          <p style="color:#4a4a6a">Hello <strong>{user_name}</strong>,</p>
          <p style="color:#4a4a6a;margin-top:12px;line-height:1.6">
            Your feedback has been approved and is now visible in the Testimonials section of the platform. Thank you for sharing your thoughts!
          </p>
          <div style="margin:28px 0;text-align:center">
            <a href="http://localhost:5173/home"
               style="background:#1a1a2e;color:#e8e4d9;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:500;font-size:14px">
              View platform →
            </a>
          </div>
        </div>
        """,
    )


def send_feedback_rejected(user_email: str, user_name: str) -> None:
    """Notify user their feedback was rejected."""
    _send(
        to=user_email,
        subject="[PFE 2026] Feedback update",
        html=f"""
        <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;background:#f5f2eb;border-radius:12px">
          <div style="background:#1a1a2e;border-radius:8px;padding:20px 24px;margin-bottom:24px">
            <h2 style="color:#c9a96e;margin:0;font-size:18px">PFE 2026 · Feedback Update</h2>
          </div>
          <p style="color:#4a4a6a">Hello <strong>{user_name}</strong>,</p>
          <p style="color:#4a4a6a;margin-top:12px;line-height:1.6">
            Thank you for your submission. After review, your feedback was not approved for publication at this time.
          </p>
        </div>
        """,
    )





from config import RESET_TOKEN_TTL_MINUTES

def send_password_reset(to_email: str, reset_link: str) -> None:
    subject = "Réinitialisation de votre mot de passe"
    html = f"""
    <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;background:#f5f2eb;border-radius:12px">
      <div style="background:#1a1a2e;border-radius:8px;padding:20px 24px;margin-bottom:24px">
        <h2 style="color:#c9a96e;margin:0;font-size:18px">PFE 2026 · Réinitialisation</h2>
      </div>
      <p style="color:#4a4a6a">Vous avez demandé la réinitialisation de votre mot de passe.</p>
      <p style="color:#4a4a6a">Ce lien est valable <strong>{RESET_TOKEN_TTL_MINUTES} minutes</strong>.</p>
      <div style="margin:28px 0;text-align:center">
        <a href="{reset_link}"
           style="background:#1a1a2e;color:#e8e4d9;padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:500;font-size:14px">
          Réinitialiser mon mot de passe →
        </a>
      </div>
      <p style="color:#8a8aaa;font-size:13px">Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.</p>
    </div>
    """
    _send(to=to_email, subject=subject, html=html)   # ← body= remplacé par html=


def send_otp(email: str, code: str) -> None:
    subject = "Votre code de vérification"
    html = f"""
    <div style="font-family:sans-serif;max-width:520px;margin:auto;padding:32px;background:#f5f2eb;border-radius:12px">
      <div style="background:#1a1a2e;border-radius:8px;padding:20px 24px;margin-bottom:24px">
        <h2 style="color:#c9a96e;margin:0;font-size:18px">PFE 2026 · Code de vérification</h2>
      </div>
      <p style="color:#4a4a6a">Votre code de connexion est :</p>
      <div style="text-align:center;margin:28px 0">
        <span style="font-size:36px;font-weight:700;letter-spacing:8px;color:#1a1a2e;background:#fff;padding:16px 28px;border-radius:8px;border:2px solid #c9a96e">
          {code}
        </span>
      </div>
      <p style="color:#8a8aaa;font-size:13px;text-align:center">Ce code expire dans <strong>10 minutes</strong>.</p>
    </div>
    """
    _send(to=email, subject=subject, html=html)      # ← body= remplacé par html=