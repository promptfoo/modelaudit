# Lightweight build for CI testing and basic functionality
FROM python:3.9-slim

WORKDIR /app

# Install Poetry
RUN pip install --no-cache-dir poetry==1.5.1

# Copy Poetry configuration files first (for better layer caching)
COPY pyproject.toml poetry.lock* ./

# Configure Poetry
RUN poetry config virtualenvs.create false

# Install dependencies first (this layer will be cached unless deps change)
RUN poetry install --only main --no-interaction --no-root

# Copy project code after dependencies are installed
COPY . .

# Install the package itself (editable install)
RUN poetry install --only main --no-interaction --no-deps

# Set entrypoint
ENTRYPOINT ["modelaudit"]
CMD ["--help"] 
