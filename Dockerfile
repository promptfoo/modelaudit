# Lightweight build for CI testing and basic functionality
FROM python:3.9-slim

WORKDIR /app

# Install Poetry
RUN pip install --no-cache-dir poetry==1.5.1

# Copy Poetry configuration files
COPY pyproject.toml poetry.lock* ./

# Configure Poetry
RUN poetry config virtualenvs.create false

# Copy project code first (needed for editable install)
COPY . .

# Install the package and main dependencies (no heavy ML extras)
RUN poetry install --only main --no-interaction

# Set entrypoint
ENTRYPOINT ["modelaudit"]
CMD ["--help"] 
