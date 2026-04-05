from pydantic import BaseModel


class Settings(BaseModel):
    app_name: str = "VulBox Security Assessment"
    app_version: str = "0.1.0"
    database_url: str = "sqlite:///./data/findings.db"


settings = Settings()
