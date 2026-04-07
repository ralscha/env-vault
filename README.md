# env-vault

Store named sets of environment variables in a local encrypted vault and inject them directly into processes — no plaintext files, no shell history exposure.

## Install

Build from source:

```sh
git clone https://github.com/ralscha/env-vault
cd env-vault
go build -o env-vault ./cmd/cli
```

## Concepts

**Groups** hold shared environment variables. **Apps** link one or more groups and can define their own variables that override linked values.

Both apps and groups live in one flat namespace — names must be unique across both kinds.

**Selections** are comma-separated lists of app and/or group names. They are merged left to right: later entries override earlier ones. Within an app, group values are applied in link order, then the app's own variables are applied last.

The vault is encrypted on disk using [age](https://age-encryption.org) with a post-quantum hybrid recipient. The master password protects a separate encrypted age identity file using age scrypt. Neither file is readable without the password.

## Quick Example

The complete flow: create a vault, store secrets, run a command with them injected.

```sh
# 1. Create the vault (prompts for a master password)
env-vault init

# 2. Create a shared group with an API key (prompts for the value)
env-vault set --group llm OPENAI_API_KEY

# 3. Create an app that links the group
env-vault set --app chat MODEL gpt-4o
env-vault link chat llm

# 4. Run a command with the chat app's secrets injected
env-vault exec chat -- printenv OPENAI_API_KEY
env-vault exec chat -- printenv MODEL

# 5. Or drop into a subshell with secrets in the environment
env-vault shell chat
```

## Commands

Shared flags apply to every command that reads or writes the vault:

| Flag | Description |
|---|---|
| `--dir PATH` | Vault directory (default: `~/.env-vault`) |
| `--password-stdin` | Read the master password from stdin |
| `--password-file PATH` | Read the master password from a file |
| `--password-fd N` | Read the master password from an open file descriptor |
| `--unlock-window DURATION` | Start or extend a short-lived helper process so later commands can reuse the decrypted identity automatically |

---

### `init`

Create a new vault. Prompts for a master password interactively unless a non-interactive source is supplied.

```
env-vault init [--dir PATH] [--work-factor N] [--password-stdin|--password-file PATH|--password-fd N]
```

`--work-factor N` controls the scrypt difficulty (default: 18). Higher values are slower but more resistant to brute force.

```sh
env-vault init
env-vault init --dir ~/.config/my-vault
echo "my-password" | env-vault init --password-stdin
```

---

### `info`

Show the paths to the vault data file and the encrypted identity file.

```
env-vault info [--dir PATH]
```

```sh
env-vault info
```

---

### `set`

Add or update a variable in an app or group. Without a value argument, prompts for the value with hidden input.

```
env-vault set [shared flags] [--stdin|--interactive] [--app|--group] NAME [KEY [VALUE]]
```

- `--app` or `--group` explicitly creates that kind of entity if it does not exist yet. Omit the flag to update an existing entity of either kind.
- `--stdin` reads the value from stdin (avoids shell history; requires a different unlock source than `--password-stdin`).
- `--interactive` starts a multi-key edit session in a prompt loop.
- Passing `VALUE` as a literal argument works but may leak through shell history and process inspection.

```sh
# Prompt for the value (safest)
env-vault set --group llm OPENAI_API_KEY

# Multiple keys in one session
env-vault set --group --interactive llm

# Read value from stdin
echo "sk-abc123" | env-vault set --group llm OPENAI_API_KEY --stdin

# Inline value (shell history risk)
env-vault set --group remotedb DB_HOST db.example.com
env-vault set --app chat MODEL gpt-4o
```

---

### `exec`

Run a command with secrets injected as environment variables. Use `--` to separate vault arguments from the command.

```
env-vault exec [shared flags] NAME[,NAME...] -- COMMAND [ARGS...]
```

The selection is merged before injection. The child process inherits the current environment plus all resolved secrets (secrets override any existing env vars with the same name).

```sh
env-vault exec chat -- printenv OPENAI_API_KEY
env-vault exec chat,remotedb -- ./start-server
env-vault exec --unlock-window 5m chat -- make test
```

`exec` is the preferred way to consume secrets. Unlike `export`, it never writes plaintext to disk or a terminal.

---

### `shell`

Start a subshell with secrets injected into its environment.

```
env-vault shell [shared flags] [--shell PATH] [--allow-nested] NAME[,NAME...] [-- SHELL_ARGS...]
```

- `--shell PATH` overrides the shell binary (default: `$SHELL`).
- `--allow-nested` removes the guard that prevents starting an `env-vault shell` inside another one.
- The `ENV_VAULT` and `ENV_VAULT_PROFILE` environment variables are set inside the subshell to indicate the active vault and selection.

```sh
env-vault shell chat
env-vault shell chat,remotedb
env-vault shell --shell /bin/zsh chat
```

---

### `link`

Add a group to an app so the group's variables are included when the app is resolved.

```
env-vault link [shared flags] APP GROUP
```

Groups are merged in the order they are linked. Variables defined directly on the app override all group values.

```sh
env-vault link chat llm
env-vault link chat remotedb
```

---

### `unlink`

Remove a group from an app.

```
env-vault unlink [shared flags] APP GROUP
```

```sh
env-vault unlink chat remotedb
```

---

### `list`

List all apps and groups, or list the resolved keys for a specific selection.

```
env-vault list [shared flags] [--json] [NAME[,NAME...]]
```

- Without a name: shows all apps and groups in the vault.
- With a name or selection: shows the resolved environment variable keys.
- `--json` emits machine-readable output.

```sh
env-vault list
env-vault list chat
env-vault list chat,llm --json
env-vault ls
```

`ls` is an alias for `list`.

---

### `show`

Display detailed information about one entity or a resolved selection.

```
env-vault show [shared flags] [--resolved] [--json] [app|group] NAME[,NAME...]
```

- `app` or `group` narrows the lookup when both exist (they cannot, but the qualifier is accepted).
- `--resolved` also prints the merged variable values with per-key provenance (which entity each key came from).
- `--json` emits machine-readable metadata.

```sh
env-vault show group llm
env-vault show app chat
env-vault show --resolved chat
env-vault show --json chat,llm
env-vault inspect group llm
```

`inspect` is an alias for `show`.

---

### `edit`

Open an app or group's direct key/value pairs in your `$EDITOR`.

```
env-vault edit [shared flags] [--editor PATH] NAME
```

The editor receives a temporary plaintext file. The file is removed after the editor exits. Treat `edit` like `export` from a local-exposure standpoint — plaintext values are on disk while the editor is open.

```sh
env-vault edit chat
env-vault edit --editor vim llm
```

---

### `unset`

Remove a single key from an app or group.

```
env-vault unset [shared flags] [--force] NAME KEY
```

Prompts for confirmation unless `--force` is given.

```sh
env-vault unset chat OPENAI_API_KEY
env-vault unset --force remotedb DB_PASSWORD
```

---

### `remove`

Delete an app or group entirely.

```
env-vault remove [shared flags] [--force] NAME
```

Prompts for confirmation unless `--force` is given. Removing a group does not automatically unlink it from apps that reference it.

```sh
env-vault remove old-app
env-vault remove --force temp-group
env-vault rm old-app
```

`rm` is an alias for `remove`.

---

### `rename`

Rename an app or group. When a group is renamed, all apps that link it are updated automatically.

```
env-vault rename [shared flags] OLD_NAME NEW_NAME
```

```sh
env-vault rename remotedb remote-db
```

---

### `copy`

Duplicate an app or group under a new name with fresh timestamps.

```
env-vault copy [shared flags] SOURCE_NAME DEST_NAME
```

```sh
env-vault copy chat chat-staging
```

---

### `export`

Write plaintext secrets to stdout or a file.

```
env-vault export [shared flags] [--format env|export-env|json|dotenv] [--metadata] [--output FILE] [--force-stdout] NAME[,NAME...]
```

| Format | Output |
|---|---|
| `env` | `KEY="value"` lines |
| `export-env` | `export KEY="value"` lines for POSIX shell sourcing |
| `json` | flat JSON object |
| `dotenv` | `.env`-style `KEY="value"` lines |

- `--metadata` wraps the output with entity metadata plus both the direct and resolved env maps (JSON only).
- `--output FILE` writes to a file with mode 0600 and prints a warning.
- `--force-stdout` is required to print plaintext secrets to an interactive terminal.

`exec` and `shell` are safer for most use cases. Use `export` when you need the data in a file or a format another tool consumes.

```sh
env-vault export --format export-env --force-stdout chat
env-vault export --format json --output secrets.json chat
env-vault export --format json --metadata chat,llm
source <(env-vault export --format export-env --force-stdout llm)
```

---

### `unlock`

Inspect or stop the short-lived unlock helper started by `--unlock-window`.

```
env-vault unlock [--dir PATH] status|clear
```

- `status` shows whether the helper is running and prints its recent activity log.
- `clear` stops the helper and removes its socket.

The helper keeps the decrypted age identity in memory only. It communicates over a Unix domain socket (macOS/Linux) or a named pipe (Windows) accessible only to the same user.

```sh
env-vault unlock status
env-vault unlock clear
```

---

### `completion`

Print a shell completion script.

```
env-vault completion bash|zsh|fish|powershell
```

```sh
# Bash
eval "$(env-vault completion bash)"

# Zsh
env-vault completion zsh > ~/.zsh/completions/_env-vault

# Fish
env-vault completion fish > ~/.config/fish/completions/env-vault.fish
```

The generated scripts cover commands and flags. They do not query vault contents for dynamic app and group names.

---

## Non-interactive Unlock

For scripts and CI, supply the password without a prompt:

```sh
# From a file
env-vault exec --password-file ~/.vault-pass chat -- ./deploy.sh

# From stdin
echo "my-password" | env-vault list --password-stdin

# Start one unlock window, then reuse it across several commands
env-vault exec --password-file ~/.vault-pass --unlock-window 2m chat -- make build
env-vault exec chat -- make test
env-vault list chat
```

`--password-stdin` reads from stdin before the command runs. If you also need `set --stdin`, use `--password-file` or `--password-fd` instead.

---

## Security Notes

- Secrets prompted interactively use hidden terminal input and are held in locked memory via [memguard](https://github.com/awnumar/memguard).
- `set --stdin` and `set --interactive` avoid placing secret values in shell history.
- Passing `VALUE` inline on the command line can leak through shell history and `ps` output.
- `exec` and `shell` are the safe default workflows. `export` writes plaintext and should be treated as an escape hatch.
- `export` refuses to print to an interactive terminal unless `--force-stdout` is given.
- `export --output FILE` creates the file with mode 0600 and prints a warning.
- `edit` writes a temporary plaintext file to disk while your editor is open.
- The `--unlock-window` helper uses same-user IPC only (Unix socket or Windows named pipe).
- Atomic writes protect both encrypted files against corruption.
- Once secrets reach a child process, that process and the OS control further exposure.
