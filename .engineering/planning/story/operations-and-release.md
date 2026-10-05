---
format: aep.planning-md/3
id: story:operations-and-release
kind: story
status: implemented
title: Ship and operate Secrets 0.1.0
summary: Provide probes, metrics, key rewrap, image publication and release evidence.
relations:
- derived_from: epic:encrypted-custody
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-09-01T11:07:39Z", actor: "human:timo", revision: 2, decided_on: {"recorded":{"test_result":1}}, imported: true}
- {from: "proposed", to: "active", at: "2026-09-01T11:07:39Z", actor: "human:timo", revision: 3, decided_on: {"recorded":{"test_result":1}}, imported: true}
- {from: "active", to: "implemented", at: "2026-09-01T11:07:39Z", actor: "human:timo", revision: 4, decided_on: {"recorded":{"test_result":1}}, imported: true}
---
## Acceptance

The complete repository gate, container smoke test and public-source provenance fence pass for the released 0.1.0 image and source tag.
