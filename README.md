# antispam-action

GitHub action to automatically close spam issues.

## Usage

Add the following to `.github/workflows/antispam.yml` in your repository:

```
name: antispam

on:
  issues:
    types:
      - opened
      - edited
      - reopened

permissions:
  pull-requests: write
  issues: write

jobs:
  build:
    name: Antispam
    runs-on: ubuntu-latest

    steps:
      - uses: vbaranov/antispam-action@1
        with:
          token: ${{ github.token }}
```

