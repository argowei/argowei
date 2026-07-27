from pydantic import SecretStr, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings.

    Values are read from environment variables (see .env.example), falling
    back to the defaults below for local development without Docker. The
    defaults mirror docker-compose.yml so a plain `uvicorn app.main:app`
    against a locally running Postgres/Redis works out of the box.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    postgres_user: str = "argowei"
    postgres_password: SecretStr = SecretStr("argowei")
    postgres_db: str = "argowei"
    postgres_host: str = "localhost"
    postgres_port: int = 5432

    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0

    @computed_field
    @property
    def database_url(self) -> str:
        """Async SQLAlchemy DSN, assembled from the discrete settings above.

        Built from parts (rather than read as a single env var) so the
        password stays wrapped in SecretStr up to this point, instead of
        sitting in plaintext in the environment/config as a full DSN.
        """
        password = self.postgres_password.get_secret_value()
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @computed_field
    @property
    def redis_url(self) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"


settings = Settings()
