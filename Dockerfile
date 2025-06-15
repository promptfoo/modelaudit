FROM python:3.11-slim

WORKDIR /app

# Install Rye
RUN pip install rye

# Copy project configuration files
COPY pyproject.toml ./

# Configure Rye to not create a virtual environment inside the container
ENV RYE_NO_AUTO_INSTALL=1
ENV RYE_USE_UV=1

# Install dependencies
RUN rye sync --no-dev

# Copy the rest of the application
COPY . .

# Install the application
RUN rye install

# Create a non-root user
RUN useradd -m appuser
USER appuser

# Set the entrypoint
ENTRYPOINT ["modelaudit"]
CMD ["--help"] 
