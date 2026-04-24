from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    APP_NAME: str = "VM Portal"
    SECRET_KEY: str = "changeme"
    DEBUG: bool = False
    SEED_DEMO_DATA: bool = True

    DATABASE_URL: str = "sqlite:///./vmportal.db"

    # Nessus
    NESSUS_URL: Optional[str] = None
    NESSUS_ACCESS_KEY: Optional[str] = None
    NESSUS_SECRET_KEY: Optional[str] = None
    NESSUS_VERIFY_SSL: bool = False

    # Microsoft Defender for Endpoint
    MDE_TENANT_ID: Optional[str] = None
    MDE_CLIENT_ID: Optional[str] = None
    MDE_CLIENT_SECRET: Optional[str] = None

    # OpenVAS
    OPENVAS_HOST: Optional[str] = None
    OPENVAS_PORT: int = 9390
    OPENVAS_USERNAME: Optional[str] = None
    OPENVAS_PASSWORD: Optional[str] = None

    # NMAP
    NMAP_TARGETS: Optional[str] = None
    NMAP_ARGS: str = "-sV -sC --open -T4"

    # PAC Scanner
    PAC_URL: Optional[str] = None
    PAC_API_KEY: Optional[str] = None

    # AWS
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    AWS_DEFAULT_REGION: str = "eu-central-1"

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
