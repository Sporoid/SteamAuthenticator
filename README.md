# Steam Authenticator

A Python-based Steam Guard authenticator that generates time-based one-time passwords (TOTP) and manages trade confirmations for multiple Steam accounts.

## Features

- Generate Steam Guard codes for multiple accounts simultaneously
- Real-time code generation with countdown timer
- Automatic token refresh when expired
- Trade confirmation management (approve/deny)
- Support for multiple account types (trades, market listings, etc.)
- Cross-platform support (Windows, macOS, Linux)

## Requirements

- Python 3.7+
- Dependencies listed in `requirements.txt`

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/SteamAuthenticator.git
cd SteamAuthenticator
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `maFiles` directory in the project root:
```bash
mkdir maFiles
```

4. Add your Steam Guard `.maFile` files to the `maFiles` directory. These files should be named with your Steam ID (e.g., `76561199059431362.maFile`).

## Usage

### Generate Steam Guard Codes

Run the main script to display Steam Guard codes for all configured accounts:

```bash
python SteamGuard.py
```

The interface will display:
- Account username and Steam ID
- Current Steam Guard code
- Progress bar showing time until next code
- Remaining seconds

Press `Ctrl+C` to exit.

### Manage Trade Confirmations

While the authenticator is running, press `2` and `Enter` to access the confirmation management interface. You can:
- View all pending confirmations across accounts
- Approve or deny individual confirmations
- Approve or deny all confirmations at once

### Refresh Account Tokens

To manually refresh expired tokens for all accounts:

```bash
python refresh_all_accounts.py
```

This script will:
- Check token expiration status for each account
- Automatically refresh expired tokens using stored credentials
- Update `.maFile` files with new tokens

## Configuration

Edit the `credentials_map` dictionary in `refresh_all_accounts.py` to add your account credentials:

```python
credentials_map = {
    'username1': ('username1', 'password1'),
    'username2': ('username2', 'password2'),
}
```

## Security Considerations

- Keep your `.maFile` files secure and never commit them to version control
- The `maFiles` directory is included in `.gitignore` by default
- Store credentials securely and consider using environment variables for sensitive data
- This tool requires your Steam credentials for token refresh functionality

## Project Structure

```
SteamAuthenticator/
├── SteamGuard.py              # Main authenticator script
├── refresh_all_accounts.py    # Token refresh utility
├── requirements.txt           # Python dependencies
├── maFiles/                   # Directory for .maFile files (not tracked)
└── README.md                  # This file
```

## How It Works

The authenticator uses the Steam Web API to:
1. Sync with Steam servers for accurate time
2. Generate TOTP codes using HMAC-SHA1 algorithm
3. Manage authentication sessions with JWT tokens
4. Handle trade confirmations through Steam Community API

## Troubleshooting

### Token Expired Errors

If you see token expiration errors, run the refresh script:
```bash
python refresh_all_accounts.py
```

### No Codes Displayed

Ensure your `.maFile` files are properly formatted and located in the `maFiles` directory.

