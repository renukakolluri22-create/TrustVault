import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")

    if not SECRET_KEY:
        raise RuntimeError(
            "SECRET_KEY environment variable is not set."
        )

    SQLALCHEMY_DATABASE_URI = os.environ.get(
    "TRUSTVAULT_DATABASE_URI",
    "sqlite:///" + os.path.join(BASE_DIR, "trustvault.db")
)

    SQLALCHEMY_TRACK_MODIFICATIONS = False