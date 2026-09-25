from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "postgresql+psycopg://vaultpass:vaultpass@localhost:5432/vaultpass"
    redis_url: str = "redis://localhost:6379/0"
    allowed_origins: list[str] = ["http://localhost:3000"]
    allowed_hosts: list[str] = ["localhost", "127.0.0.1", "testserver", "api"]
    environment: str = "development"
    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    smtp_username: str = ""
    smtp_password: str = ""
    mail_from: str = "VaultPass <security@localhost>"
    public_web_url: str = "http://localhost:3000"
    webauthn_rp_id: str = "localhost"
    webauthn_origin: str = "http://localhost:3000"
    rate_limit: int = Field(default=20, ge=1, le=10000)
    max_request_bytes: int = Field(default=400000, ge=1024, le=10000000)
    max_vault_items: int = Field(default=5000, ge=1, le=100000)
    max_active_sessions: int = Field(default=20, ge=1, le=1000)
    max_passkeys: int = Field(default=10, ge=1, le=100)
    max_teams_per_user: int = Field(default=25, ge=1, le=1000)
    max_team_members: int = Field(default=100, ge=2, le=1000)
    audit_retention_days: int = Field(default=365, ge=30, le=3650)


settings = Settings()
