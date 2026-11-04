# Security

Please report a vulnerability through
[GitHub's private reporting form](https://github.com/Yuv1s/trawl/security/advisories/new), not in a
public issue. Include what you did, what happened, and a file or steps that show it. There is no
fixed response time.

## What counts

- A file or pasted text that runs script in the page.
- A small file that freezes the tab, exhausts memory or crashes the analysis.
- A web page reaching the Remora scanner without its pairing token, or reading that token.
- The scanner reaching something it should refuse, such as a local address outside local mode, or
  a cloud metadata address in any mode.
- Anything in the deployed site that a browser should not get.
- A way to tamper with the installers or the release workflow.

A flag Trawl fails to report is a normal bug, unless the file gets it hidden with nothing on the
page saying the analysis stopped short. Use the
[missed finding template](https://github.com/Yuv1s/trawl/issues/new/choose) for those.

## Known limits

A very small PNG can claim a very large image. Trawl allows up to 256 MiB of pixel data so that
real large images work, which means a 250 KB file can use about 1.2 GB of memory and may crash a
tab on a phone. You don't need to report this one.

## Versions

The site is always the latest code. For the scanner, only the latest release gets fixes, and the
page warns you when the scanner it connects to is out of date.
