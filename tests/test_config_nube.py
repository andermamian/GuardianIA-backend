"""La URL de PostgreSQL que entregan Neon/Render se adapta sola al driver psycopg."""
from app.core.config import Settings


def test_url_postgres_se_normaliza():
    assert Settings(database_url="postgres://u:p@h/db").database_url == "postgresql+psycopg://u:p@h/db"
    assert Settings(database_url="postgresql://u:p@h/db?sslmode=require").database_url == "postgresql+psycopg://u:p@h/db?sslmode=require"
    assert Settings(database_url="sqlite:///./x.db").database_url == "sqlite:///./x.db"
