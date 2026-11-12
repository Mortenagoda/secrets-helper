# bw-gh-secrets

Interactive, cross-platform Node CLI that:

1. Asks for a describing name and a username, and generates a strong password with Bitwarden's generator (`bw generate`), falling back to Node's crypto if that fails.
2. Saves them as a Login item in Bitwarden (via the bundled `@bitwarden/cli`; works with bitwarden.com or self-hosted/Vaultwarden).
3. Sets `<NAME>_USERNAME` / `<NAME>_PASSWORD` as GitHub Actions secrets on one or more repos with `gh`.

## Requirements
- Node.js 20+
- GitHub CLI (`gh`) logged in: `gh auth login`

## Usage
```sh
npm install
npm start            # interactive menu
npm run dry-run      # walk through the flow without writing anything
npm link             # optional: install as global `bw-gh-secrets` command
```

The repo picker shows ★ pinned projects, ↺ repos you used recently with this tool, then your most recently pushed GitHub repos. Manage pins from the main menu.

- Config (pins, recents, password length, server URL): `~/.config/bw-gh-secrets/config.json`
- Set `BW_SESSION` to reuse an unlocked vault session, or `BW_CLI` to use a different `bw` binary.
- Secret values are passed to `gh` via stdin, never as command-line arguments.
