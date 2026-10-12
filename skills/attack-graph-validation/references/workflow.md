# Attack Graph Validation Workflow

## Inputs

- Authorized lab scope
- MulVAL/MAVO raw graph
- Skill registry (`skills/registry.json`) + generated index (`skills/index.json`)
- Optional executor configuration

## Outputs

- `action_graph.json`
- enriched action graph
- dry-run validation plan
- evidence records
- final report

## Procedure

1. Parse the raw graph.
2. Project `AND/OR/LEAF` logic into an AND-only action graph.
3. Preserve `OR/LEAF` facts as step context.
4. Extract step semantics.
5. Match skills (registry 召回 + 覆盖核对，见 `docs/product/skill_contract.md` 第 5/6 节).
6. Plan validation order.
7. Execute only through structured executor requests.
8. Store evidence.
9. Build the report from evidence.

