from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "Nexora Control Plane"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    DATABASE_URL: str = "postgresql+asyncpg://nexora_user:nexora_password@localhost:5432/nexora_db"
    REDIS_URL: str = "redis://localhost:6379/0"
    OPA_URL: str = "http://localhost:8181"
    TEMPORAL_HOST: str = "localhost:7233"

    OPENAI_API_KEY: str = ""
    LLM_MODEL: str = "gpt-4o-mini"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
