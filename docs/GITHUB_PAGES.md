# GitHub Pages Website

## Current status

The Telosieve website source is complete under `site/`, builds locally into
`target/pages/`, and is authorized to deploy from reviewed `master` through
`.github/workflows/pages.yml` after the repository becomes public.

The website contains no telemetry, cookies, remote fonts, client-side scripts,
third-party runtime assets, forms, credentials, private handoff material, or
production claims. Its architecture illustration and copy use the same claim
boundary as the README and product documentation.

## Local build and preview

Build and validate the exact static output:

```sh
python3 scripts/build-pages-site.py
python3 scripts/validate-pages-site.py
python3 -m http.server 8080 --directory target/pages
```

The build is dependency-free, byte-deterministic on the same source tree, and
bounded to an explicit file allowlist. `target/pages/site-manifest.json` binds
every published byte. The output includes `.nojekyll` so a future branch-based
deployment serves the validated files without Jekyll transformation.

## Deployment controls

The public-launch pull request and explicit owner instruction satisfy the prior activation gate. Deployment must:

1. confirm the repository is ready for public website exposure and rerun the
   final public-history and prohibited-content audits;
2. update `docs/RELEASE.md` with the exact Pages source branch and deployment
   authorization;
3. review workflow permissions, deployment provenance, public visibility,
   secrets, cost, dependency, supply-chain, and untrusted-contribution behavior;
4. build the exact site locally and bind its output manifest to the reviewed
   source commit;
5. configure GitHub Pages to deploy from reviewed `master` only after the
   authorizing change is merged and visibility is public;
6. verify the live URL, TLS, asset paths, narrow and desktop rendering, metadata,
   and absence of private content without describing the website as production
   assurance.

The workflow uses only commit-pinned GitHub-owned actions, grants read-only
content access to the build job, and grants `pages: write` plus `id-token: write`
only to the deployment job. It receives no repository secrets.

GitHub's current publishing-source documentation is retained as the operational
reference: <https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site>.
