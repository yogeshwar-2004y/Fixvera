FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -r -u 10001 appuser
COPY agentic ./agentic
RUN mkdir /app/data && chown -R appuser:appuser /app/data
USER appuser
ENV AGENTIC_DB_PATH=/app/data/agentic.sqlite3
EXPOSE 8000
CMD ["uvicorn", "agentic.main:app", "--host", "0.0.0.0", "--port", "8000"]
