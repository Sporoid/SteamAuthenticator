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

### Quick Start

Run the main authenticator:

```bash
python SteamGuard.py
```

If no accounts are configured, you'll be prompted to add one automatically.

### Main Interface

The authenticator displays:
- Account username and Steam ID
- Current Steam Guard code (refreshes every 30 seconds)
- Progress bar showing time until next code
- Remaining seconds

**Available Commands:**
- Press `Ctrl+C` to exit
- Type `2` + Enter to add a new account
- Type `3` + Enter to manage trade confirmations

### Add New Account

You can add accounts in two ways:

**Option 1: From the main interface**
- Run `python SteamGuard.py`
- Type `2` and press Enter
- Follow the setup wizard

**Option 2: Run the script directly**
```bash
python add_account.py
```

**Setup Process:**
1. Enter your Steam username and password
2. If Email Steam Guard is enabled, you'll be guided to disable it first
3. Write down your revocation code (CRITICAL - save this!)
4. Verify you saved the revocation code
5. Enter the SMS code sent to your phone
6. Account is added and ready to use

**Requirements:**
- Account must NOT already have Mobile Authenticator enabled
- Must disable Email Steam Guard if enabled (script will guide you)
- Access to phone for SMS verification
- Valid Steam credentials

### Manage Trade Confirmations

While the authenticator is running, type `3` and press Enter to access confirmations:
- View all pending confirmations across accounts
- Approve or deny individual confirmations
- Approve or deny all confirmations at once
- See verification codes for trade safety

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
├── add_account.py             # Add new account with authenticator
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

### Email Steam Guard Conflict

If you get an error about Email Steam Guard being enabled:
1. Go to https://store.steampowered.com/twofactor/manage
2. Look for "Login Confirmation" or "Confirmación de inicio de sesión"
3. Click "Remove Security Method" or "Eliminar método de seguridad"
4. Confirm the removal
5. Run the add account script again

### SMS Code Not Working

- Make sure you're entering the code quickly (they expire)
- The code should be 5 digits
- If it fails, wait for a new SMS and try again
- Check that your phone number is correct on your Steam account

### Cannot Add Account

Common issues:
- **Account already has authenticator**: Remove it first at https://store.steampowered.com/twofactor/manage
- **Email Steam Guard enabled**: Follow the steps above to disable it
- **Wrong credentials**: Double-check your username and password
- **Rate limited**: Wait a few minutes and try again

