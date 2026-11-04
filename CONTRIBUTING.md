# Contributing to Trawl

Bug reports and pull requests are welcome. A flag Trawl missed is as useful a report as a
crash, so please send those too.

## Getting it running

You need Rust with the `wasm32-unknown-unknown` target, `wasm-pack`, Node 20 or newer, and
Python 3. Then:

```bash
git clone https://github.com/Yuv1s/Trawl
cd Trawl
python serve.py
```

For hot reloading while you work on the interface:

```bash
npm install
npm run build:wasm
npm run dev
```

## Where things live

| Path                      | What it is                                                 |
| ------------------------- | ---------------------------------------------------------- |
| `trawl-core/`             | The analysis core, Rust compiled to WebAssembly            |
| `src/lib/worker/`         | The web worker that drives the core and spends its budgets |
| `src/routes/`, `src/lib/` | The page, its components and the writeup                   |
| `trawl-scan/`             | Remora's scanner, the only part that reaches the network   |
| `fixtures/`               | Scripts that build test files from scratch                 |
| `static/samples/`         | Sample files with known answers, and clean controls        |

## Before you open a pull request

Run what CI runs:

```bash
npm run check
npm run lint
npx playwright install chromium # once, for the browser tests
npm test
cargo clippy --manifest-path trawl-core/Cargo.toml --all-targets --all-features -- -D warnings
cargo clippy --manifest-path trawl-scan/Cargo.toml --all-targets --all-features -- -D warnings
cargo test --release --manifest-path trawl-core/Cargo.toml
cargo test --manifest-path trawl-scan/Cargo.toml
npm run build && npm run exposure
```

The last line builds the site and fails if the build holds a source map, a secret, a private
path or a debug call.

## What a change needs

- **A detector needs two tests.** One on a file with a known answer, and one on a clean control
  to show it stays quiet. A tool that reports something on every file is no better than one that
  reports nothing.
- **Every file is hostile.** Someone can build one to beat your code, so anything it asks for,
  whether bytes, time or rows on the page, needs a limit.
- **A limit has to say so.** When a file reaches one, the page and the writeup must say what went
  unread. A missing result with no note looks the same as a clean file.
- **Tests run natively, and the core ships as wasm32.** `usize` is 32 bits in the shipped build,
  so arithmetic on anything a file controls has to be checked, or it can wrap there and pass here.
- **Text from a file stays text.** No `{@html}`, and anything going into the writeup goes through
  `clean()`.
- **Key an each block on an index,** unless the value truly cannot repeat. Svelte throws on a
  duplicate key, and a file can repeat anything.
- **Ask before adding a dependency.** `package.json` has no runtime dependencies, and the core's
  only one is `wasm-bindgen`. Open an issue first.

## Reporting a bug

Use one of the [issue templates](https://github.com/Yuv1s/trawl/issues/new/choose). A small sample
file helps most, but please don't attach anything from a competition that is still running.

Security problems go through [SECURITY.md](SECURITY.md), not a public issue.

## Licence

Contributions are released under the [MIT licence](LICENCE.md), the same as the rest of Trawl.
