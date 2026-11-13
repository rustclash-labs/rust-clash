# Repository Agent & Maintainer Rules (`rustclash-labs/rust-clash`)

## Mandatory Privacy & Anonymous Bot Identity Policy

This repository is maintained under the organization identity **`RustClash Labs <rustclash.labs@proton.me>`** and automated bots (`rustclash-push-bot[bot]`, `github-actions[bot]`). Never expose a personal GitHub username or `@users.noreply.github.com` email in commits, pull requests, tags, or releases.

1. **Configure Git Identity Before Any Commit**
   Cloud agent VMs (such as Antigravity) pre-populate `git config` with the signed-in user's personal GitHub OAuth account. **Always** override the repository Git identity first:
   ```bash
   ./scripts/setup_git_identity.sh
   ```
   Verify that both `git var GIT_AUTHOR_IDENT` and `git var GIT_COMMITTER_IDENT` report `RustClash Labs <rustclash.labs@proton.me>`. Both `.githooks/pre-commit` and GitHub Actions (`ci.yml` / `release.yml`) reject commits with personal emails.

2. **Never Open PRs or Releases via a Personal GitHub OAuth Token**
   - Do **not** run `gh pr create`, `gh pr merge`, or `gh release create` when `gh auth status` is authenticated as a personal GitHub user — GitHub permanently attributes the PR/Release creator to that personal `@username`.
   - Instead:
     - If `rustclash-push-bot[bot]` GitHub App credentials are configured, authenticate as `rustclash-push-bot[bot]`.
     - Otherwise, push commits authored and committed as `RustClash Labs <rustclash.labs@proton.me>` directly to `main` (Git over HTTPS does not embed the pusher's username into commit objects).
   - Trigger releases strictly by pushing a `v*.*.*` tag (or `gh workflow run release.yml`) so **`github-actions[bot]`** publishes the GitHub Release with author-free release notes.
