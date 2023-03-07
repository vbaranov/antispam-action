# antispam-action

GitHub action to automatically close spam issues and pull requests.

Currently I use this to close PRs from Russian bots on [traitor](https://github.com/liamg/traitor).

## Usage

Add the following to `.github/workflows/antispam.yml` in your repository:

```
name: antispam

on: [issues, pull_request]

permissions:
  pull-requests: write
  issues: write

jobs:
  build:
    name: Antispam
    runs-on: ubuntu-latest

    steps:
      - uses: liamg/antispam-action@1
```

