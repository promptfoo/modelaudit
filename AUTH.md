# ModelAudit Authentication System

ModelAudit supports authentication that seamlessly integrates with promptfoo's authentication system, providing a unified authentication experience across both tools.

## Overview

The authentication system provides:
- **Seamless Integration**: Automatic credential sharing from promptfoo when using the wrapper
- **Standalone Use**: Direct authentication when using modelaudit independently
- **Consistent UX**: Same auth commands and flow as promptfoo
- **Secure Storage**: Platform-appropriate credential storage

## Quick Start

### Using with Promptfoo (Recommended)

If you're already authenticated with promptfoo, modelaudit will automatically use your credentials:

```bash
# If you're logged into promptfoo, this just works
promptfoo scan-model /path/to/model
```

### Standalone Authentication

You can also authenticate modelaudit directly:

```bash
# Login with your API key
modelaudit auth login --api-key YOUR_API_KEY

# Check who you're logged in as
modelaudit auth whoami

# Logout
modelaudit auth logout
```

## Commands

### `modelaudit auth login`

Login to promptfoo services.

```bash
# Login with API key
modelaudit auth login --api-key YOUR_API_KEY

# Login with custom host
modelaudit auth login --api-key YOUR_API_KEY --host https://your-api.example.com

# Short form
modelaudit auth login -k YOUR_API_KEY -h https://your-api.example.com
```

**Options:**
- `--api-key, -k`: Your promptfoo API key
- `--host, -h`: Custom API host URL (optional)

### `modelaudit auth logout`

Logout and clear stored credentials.

```bash
modelaudit auth logout
```

### `modelaudit auth whoami`

Show current user information.

```bash
modelaudit auth whoami
```

Displays:
- User email
- Organization name  
- App URL

## How It Works

### Configuration Storage

ModelAudit stores configuration in platform-appropriate directories:
- **Linux/macOS**: `~/.config/modelaudit/config.json`
- **Windows**: `%APPDATA%/modelaudit/config.json`

### Credential Priority

ModelAudit checks for credentials in this order:

1. **Environment Variables** (highest priority, used by promptfoo wrapper):
   - `MODELAUDIT_API_KEY`
   - `MODELAUDIT_API_HOST`
   - `MODELAUDIT_USER_EMAIL`
   - `MODELAUDIT_APP_URL`

2. **Config File** (used for standalone authentication):
   - Stored in user config directory

### Integration with Promptfoo

When you run `promptfoo scan-model`, promptfoo automatically:

1. Checks if you're authenticated with promptfoo
2. Passes your credentials to modelaudit via environment variables
3. Logs a message: "Using promptfoo authentication for modelaudit"

This means you only need to authenticate once with promptfoo, and modelaudit will automatically work.

## API Compatibility

ModelAudit uses the same API endpoints as promptfoo:
- **Default API Host**: `https://api.promptfoo.app`
- **Endpoint**: `/api/v1/users/me`
- **Authentication**: Bearer token

## Error Handling

Common authentication errors and solutions:

### "Not authenticated"
```bash
# Solution: Login first
modelaudit auth login --api-key YOUR_API_KEY
```

### "Authentication failed: Unauthorized"
```bash
# Solution: Check your API key is valid
# Get a new one from https://promptfoo.app/welcome
```

### "Failed to get user info"
```bash
# Solution: Check network connection and API host
modelaudit auth login --api-key YOUR_API_KEY --host https://api.promptfoo.app
```

## Security

- API keys are stored locally in user config directories
- No credentials are transmitted except to the configured API host
- Environment variables take precedence (for promptfoo integration)
- Logout completely removes stored credentials

## Development

### Environment Variables for Testing

```bash
export MODELAUDIT_API_KEY="your-test-key"
export MODELAUDIT_API_HOST="https://test-api.example.com"
export MODELAUDIT_USER_EMAIL="test@example.com"
```

### Configuration File Format

```json
{
  "api_key": "your-api-key",
  "api_host": "https://api.promptfoo.app",
  "user_email": "user@example.com",
  "app_url": "https://www.promptfoo.app"
}
```

## Best Practices

### For Teams Using Promptfoo
- Set up authentication once with promptfoo: `promptfoo auth login --api-key <key>`
- Use `promptfoo scan-model` for seamless integration
- Team members can share the same authentication workflow

### For CI/CD Pipelines
```bash
# Set environment variables in your CI system
export MODELAUDIT_API_KEY="${PROMPTFOO_API_KEY}"
export MODELAUDIT_API_HOST="https://api.promptfoo.app"

# Then run scans without explicit login
modelaudit scan /path/to/models/
```

### For Standalone Development
```bash
# Login once per development environment
modelaudit auth login --api-key YOUR_KEY

# Verify authentication
modelaudit auth whoami

# Run scans
modelaudit scan test_model.pkl
```

## Troubleshooting

### Common Issues

**Authentication commands not showing up in CLI:**
This may occur due to Python package caching issues. Try:
```bash
pip uninstall modelaudit -y
pip install modelaudit
```

**"Command 'auth' not found":**
Ensure you have the latest version of modelaudit installed:
```bash
pip install --upgrade modelaudit
```

**Environment variables not being read:**
Make sure environment variable names are exactly:
- `MODELAUDIT_API_KEY` (not `MODELAUDIT_API_TOKEN`)
- `MODELAUDIT_API_HOST`
- `MODELAUDIT_USER_EMAIL`
- `MODELAUDIT_APP_URL`

**API validation failures:**
- Check your API key is valid at [promptfoo.app/welcome](https://promptfoo.app/welcome)
- Verify network connectivity to `https://api.promptfoo.app`
- Try with verbose logging for more details

## Migration

If you have existing promptfoo authentication, no migration is needed. ModelAudit will automatically use your promptfoo credentials when called via the wrapper.

For standalone use, simply run:
```bash
modelaudit auth login --api-key YOUR_EXISTING_KEY
``` 