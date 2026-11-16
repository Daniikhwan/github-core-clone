# github-core-clone

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/Daniikhwan/github-core-clone/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/Daniikhwan/github-core-clone/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A GitHub-compatible git forge in a single Node.js file — a real git object store (SHA-1 loose objects, packfiles with deltas, git smart HTTP) so `git clone` / `git push` / `git fetch` work against it, plus a GitHub-compatible REST API (repos, contents, commits, branches, refs, issues, pull requests with merge) and a small web UI. No dependencies, Node.js standard library only.

## Run it

```sh
node main.ts --serve --port 3000
```

Then open http://127.0.0.1:3000, or use the API and git:

```sh
# create a user and a repo
curl -X POST http://127.0.0.1:3000/api/users -H 'content-type: application/json' \
  -d '{"login":"alice","name":"Alice"}'
curl -X POST http://127.0.0.1:3000/api/user/repos -H 'Authorization: token <token>' \
  -H 'content-type: application/json' -d '{"name":"hello"}'

# push and clone with real git
git clone http://127.0.0.1:3000/alice/hello.git
cd hello && git commit --allow-empty -m "first" && git push origin main
```

Running `node main.ts` with no arguments runs the built-in deterministic
end-to-end self-test (31 checks: users, repos, git push/clone/fetch over the
real protocol, contents, branches, issues, pull requests, merge, web UI).

Options: `--serve` (start the server), `--port <n>` (default 3000),
`--data <dir>` (default `./data`). Env: `FORGE_PORT`, `FORGE_DATA_DIR`,
`FORGE_HOST` (default `127.0.0.1`).

---

<sub>Entered on [make.fun](https://make.fun/?ref=vnsny7za&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
