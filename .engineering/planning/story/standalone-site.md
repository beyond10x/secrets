---
format: aep.planning-md/2
id: story:standalone-site
kind: story
status: active
title: Secrets publishes its own documentation site at /secrets/
relations:
- depends_on: story:ess-current-format
- decomposes: epic:encrypted-custody
revision: 4
---
# Story: standalone-site

## Outcome

Someone evaluating or operating Secrets reads one compact site at
`https://beyond10x.github.io/secrets/`, built from this repository, with every page saying what
ships today and what is planned.

## Context

Documentation rode the unified Website at `/docs/secrets/` through `b10x.docs.yaml`, with a redirect
façade at `/secrets/`. Loom, Canon, ELS, Commission, Substrate and Metaharness publish their own
Docusaurus sites through Website's `project-site.yml`; Secrets follows them. Depends on
`story:ess-current-format` for the reference pages.

## Acceptance

- `website/` builds with `npm ci && npm run build` and links nothing broken (`onBrokenLinks: throw`).
- `pages.yml` builds the site, writes `.well-known/b10x-site.json` and `.well-known/b10x-routes.json`
  for the built commit, and uploads `b10x-project-site`; `b10x-docs-site.yml` hands it to Website's
  `project-site.yml` for `/secrets/`.
- `b10x.docs.yaml`, the documentation bundle, check and façade workflows are gone.
- `README.md` is for people and links the site; `AGENTS.md` is for agents and carries the commands,
  boundaries and documentation rules.
- After merge, `https://beyond10x.github.io/secrets/.well-known/b10x-site.json` names the `main` commit.

## Out of Scope

Retiring `/docs/secrets/` on the unified site (Website and Atlas changes) follows separately.

## Ambiguities

None.
