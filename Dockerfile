# Lightweight build for CI testing and basic functionality
FROM python:3.13-slim

WORKDIR /app

# Install build dependencies and Poetry
RUN apt-get update && apt-get install -y \
    gcc g++ \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir poetry==1.5.1

# Copy Poetry configuration files first (for better layer caching)
COPY pyproject.toml poetry.lock* ./

# Configure Poetry
RUN poetry config virtualenvs.create false

# Export dependencies to requirements.txt for layer caching
RUN poetry export --only main --format requirements.txt --output requirements.txt --without-hashes

# Install dependencies using pip (better layer caching, no Poetry conflicts)
RUN pip install --no-cache-dir -r requirements.txt

# Copy project code after dependencies are installed
COPY . .

# Install the package itself using pip
RUN pip install --no-cache-dir .

# Clean up build dependencies to keep image lightweight
RUN apt-get remove -y gcc g++ \
    && apt-get autoremove -y \
    && apt-get clean

# Set entrypoint
ENTRYPOINT ["modelaudit"]
CMD ["--help"] 
