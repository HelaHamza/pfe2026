"""Crée le compte admin par défaut. À lancer une fois : python -m scripts.seed_admin"""
from core.security import hash_password
from core.email import send_admin_welcome
from repositories import user_repository as users


def seed_admin() -> None:
    email = "helahamza2020@gmail.com"
    if users.email_exists(email):
        print("Admin already exists")
        return

    users.create({
        "email":      email,
        "password":   hash_password("admin123"),
        "first_name": "Admin", "last_name": "User",
        "role":       "admin", "status": "approved", "specialty": "admin",
        "phone": "", "sex": "", "address": "", "avatar": None,
    })

    try:
        send_admin_welcome(email)
    except Exception as e:
        print(f"[EMAIL WARNING] Admin welcome email failed: {e}")
    print("Admin created successfully")


if __name__ == "__main__":
    seed_admin()