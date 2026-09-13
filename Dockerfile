FROM python:3.11.14-slim@sha256:c8271b1f627d0068857dce5b53e14a9558603b527e46f1f901722f935b786a39
RUN pip install --no-cache-dir uv==0.11.7
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev && useradd --uid 10001 --create-home app
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 10001
EXPOSE 8000
CMD ["uvicorn", "saas_auth.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
