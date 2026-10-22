FROM python:3.13-alpine

WORKDIR /app

# Copy application sources
COPY pyproject.toml .
COPY envguard/ ./envguard/

# Install application in editable or standard mode
RUN pip install --no-cache-dir .

# Non-root secure execution
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')" || exit 1

ENTRYPOINT ["envguard"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
