from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "postgresql+psycopg://vaultpass:vaultpass@localhost:5432/vaultpass"
    redis_url: str = "redis://localhost:6379/0"
    allowed_origins: list[str] = ["http://localhost:3000"]
    environment: str = "development"
    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    smtp_username: str = ""
    smtp_password: str = ""
    mail_from: str = "VaultPass <security@localhost>"
    public_web_url: str = "http://localhost:3000"
    rate_limit: int = 20


settings = Settings()
