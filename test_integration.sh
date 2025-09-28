#!/bin/bash

# Integration test script for the antispam action
set -e

echo "Running Integration Tests for Antispam Action"
echo "============================================="

# Build the action
echo "Building action..."
go build -o action ./cmd/action

# Test 1: English spam detection
echo ""
echo "Test 1: English spam detection"
cat > test_issue_1.json << 'EOF'
{
  "action": "opened",
  "issue": {
    "number": 123,
    "title": "Transaction failed - need help",
    "body": "My transaction failed and I did not receive my funds. Please help me recover my money.",
    "state": "open",
    "user": {
      "login": "spamuser"
    }
  },
  "repository": {
    "name": "test-repo",
    "owner": {
      "login": "testowner"
    }
  }
}
EOF

export GITHUB_EVENT_NAME="issues"
export GITHUB_EVENT_PATH="test_issue_1.json"
export INPUT_TOKEN="test_token_placeholder"
unset SCAM_ACTION_WHITELISTED_LOGINS

echo "Running action with spam content..."
if ./action 2>&1 | grep -q "Action failed.*401"; then
    echo "✓ Spam detection triggered (failed at API call as expected)"
else
    echo "✗ Spam detection may not have triggered"
    exit 1
fi

# Test 2: Whitelisted user
echo ""
echo "Test 2: Whitelisted user (should not trigger)"
cat > test_issue_2.json << 'EOF'
{
  "action": "opened",
  "issue": {
    "number": 124,
    "title": "Transaction failed - need help",
    "body": "My transaction failed and I did not receive my funds. Please help me recover my money.",
    "state": "open",
    "user": {
      "login": "whitelisteduser"
    }
  },
  "repository": {
    "name": "test-repo",
    "owner": {
      "login": "testowner"
    }
  }
}
EOF

export GITHUB_EVENT_PATH="test_issue_2.json"
export SCAM_ACTION_WHITELISTED_LOGINS="whitelisteduser"

echo "Running action with whitelisted user..."
if ./action 2>&1 | grep -q "Author is whitelisted"; then
    echo "✓ Whitelisted user properly bypassed"
else
    echo "✗ Whitelisted user not properly handled"
    exit 1
fi

# Test 3: Legitimate issue
echo ""
echo "Test 3: Legitimate issue (should not trigger)"
cat > test_issue_3.json << 'EOF'
{
  "action": "opened",
  "issue": {
    "number": 125,
    "title": "Bug report",
    "body": "I found a bug in the authentication system that needs to be fixed.",
    "state": "open",
    "user": {
      "login": "legituser"
    }
  },
  "repository": {
    "name": "test-repo",
    "owner": {
      "login": "testowner"
    }
  }
}
EOF

export GITHUB_EVENT_PATH="test_issue_3.json"
unset SCAM_ACTION_WHITELISTED_LOGINS

echo "Running action with legitimate issue..."
if ./action 2>&1 | grep -q "Action failed.*401"; then
    echo "✗ Legitimate issue incorrectly triggered spam detection"
    exit 1
else
    echo "✓ Legitimate issue properly ignored"
fi

# Test 4: Spanish spam
echo ""
echo "Test 4: Spanish spam detection"
cat > test_issue_4.json << 'EOF'
{
  "action": "opened",
  "issue": {
    "number": 126,
    "title": "Mi transacción falló",
    "body": "Mi transacción falló y no recibí mis fondos. Necesito ayuda para recuperar mi dinero.",
    "state": "open",
    "user": {
      "login": "spanishuser"
    }
  },
  "repository": {
    "name": "test-repo",
    "owner": {
      "login": "testowner"
    }
  }
}
EOF

export GITHUB_EVENT_PATH="test_issue_4.json"
unset SCAM_ACTION_WHITELISTED_LOGINS

echo "Running action with Spanish spam content..."
if ./action 2>&1 | grep -q "Action failed.*401"; then
    echo "✓ Spanish spam detection triggered (failed at API call as expected)"
else
    echo "✗ Spanish spam detection may not have triggered"
    exit 1
fi

# Cleanup
echo ""
echo "Cleaning up..."
rm -f test_issue_*.json action

echo ""
echo "All integration tests passed! ✓"
