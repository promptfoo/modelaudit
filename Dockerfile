FROM python:3.11-slim

WORKDIR /app

# Copy only necessary files for installation
COPY pyproject.toml README.md ./
COPY modelaudit ./modelaudit

# Install only the base package without heavy ML dependencies
# This keeps the lightweight image small and fast to build
RUN pip install --no-cache-dir .

# Create a non-root user
ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser

USER appuser

# Set the entrypoint
ENTRYPOINT ["modelaudit"]
CMD ["--help"] 
