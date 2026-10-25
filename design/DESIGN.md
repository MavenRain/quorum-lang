# quorum-lang domain design

This file is the only source of the core types and the core operations of
quorum-lang. `docs/PLAN.md` sections 2 and 3 cite it. Do not add a core
type or a core operation that this file does not give.

Sections 1 and 2 are the USER text of 2026-10-25, verbatim. The gate lets
this file hold an em-dash for that reason (as bridge-lang, ruling
2026-10-09). Do not edit sections 1 and 2.

## 1. The USER ask (2026-10-25, verbatim)


I want to write a programming language with the following characteristics:

For type constructors and higher-kinded types, admit only cell monads and their duals in a  locally presentable locally cartesian closed \((\infty,1)\)-category, as realized computationally in Cubical Type Theory.

For base types and operations, admit only what is in this denotational design: https://claude.ai/artifact/U8nr2dLKZM7WCCuC1goruP

The host language shall be TinyCC.  Use your judgment to prompt me with multiple choice options for the compilation target(s).

Finally, I'd really like agents to want to reach for this language in the situations where it is most appropriate, so use this data to shape the repo appropriately: 

Agent Incentives to Use DSL Programming Languages

**Make using your DSL the rational choice for the agent.** Agents (LLM coding agents, multi-agent systems, or autonomous on-chain agents) do not need “motivation” in the human sense. They respond to lower expected cost (tokens, retries, failure probability, verification effort) and higher expected utility of the resulting artifact (mechanical checkability, composability, downstream value). Design both the language and the surrounding harness/protocol so that the DSL path dominates alternatives.

### 1. Technical superiority as the primary incentive (highest leverage for AI agents)

Novel DSLs normally underperform because of sparse training data. Counter this with designs that are *easier* for models than the general-purpose languages they were heavily trained on.

- **Canonical, constrained surface syntax** (Anka-style and the “syntactic camp” on agentlanguages.dev). Prefer one obvious way to express each operation, explicit named intermediates (`INTO` / named steps), and verbose keywords rather than overloaded operators or implicit state. Anka showed Claude 3.5 Haiku reaching ~99.9% parse success and +40 percentage points accuracy on multi-step pipelines versus Python—purely from in-context learning, with zero prior training on the language.
- **Fast, structured feedback loops**. Ship a parser/typechecker/verifier that returns domain-level, actionable diagnostics (structured JSON with suggested fixes or retry fields, as in Codong and similar systems). Agents that can call this in a tool loop self-correct cheaply; this is the densest practical reward signal available.
- **LLM-friendly surface + mechanical backend**. Borrow patterns from high-resource languages for the surface while keeping the semantics narrow and compositional. The Microsoft Azure guidance on AI coding agents + DSLs emphasizes seeding 3–5 high-quality examples, custom agent instructions, MCP servers that expose the schema/types, and a validator-in-the-loop.

These changes alone often make the DSL preferred because success rate and iteration cost improve.

### 2. Verification and denotational superiority (your strongest unique lever)

Given your formal-methods background (Lean 4, category theory, Cubical TT/HoTT, denotational design, ZK, self-referential systems), embed the payoff in the semantics:

- Every well-formed program in the DSL should come with a clear denotational semantics (or refinement types, resource bounds, effect system, or circuit generation) that is machine-checkable. Agents that emit the DSL obtain free or cheap proofs/properties; agents that emit general-purpose code do not.
- Prefer compositional denotations (monads, Kan extensions, fixed-points, etc.) so large agentic or self-referential constructions remain tractable to reason about. Agents can query or manipulate the meaning rather than reverse-engineering it.
- Multi-target compilation (to Lean, ZK circuits, EVM/TVM IR, etc.) makes “write DSL → verified executable artifact” mechanical. Downstream systems (oracles, executors, marketplaces, other agents) can then preferentially accept, lower fees for, or automatically reward those artifacts.

This turns the DSL into the *only* practical way to produce high-assurance outputs. In a self-referential DAO or agent governance setting, you can encode the preference directly: only (or preferentially) programs inhabiting useful semantic types (e.g., resource-bounded, extractable, self-constituting) are valid or receive higher weight. The incentive becomes a fixed point of the system itself.

### 3. Protocol and economic incentives

- **Exclusion or strong preference at the boundary**. The runtime, executor, or DAO only accepts (or ranks highest) programs written in and verified against the DSL. This is the strongest possible incentive.
- Soft versions: fee discounts, lower collateral, preferential matching, or reward multipliers for verified DSL programs in agent marketplaces, bounty platforms, or OpenCollective-style systems.
- Token-efficient designs further reduce operator cost (context burn and generation cost).
- Explicit bounties or grants for high-quality programs, examples, or small-model fine-tunes on the DSL.
- Reward shaping in any RL/fine-tuning loop: dense credit for successful parse / typecheck / proof-obligation discharge (verifier-grounded rewards of the kind recently explored for Dafny-style verification) rather than binary pass/fail.

### 4. Distribution and bootstrapping

- Package the grammar, type definitions, curated examples, and a small validator as an Agent Skill (SKILL.md + supporting files) or MCP server so Claude Code, Cursor, and similar systems discover and default to it when the domain matches.
- Fine-tune or distill a small model (<500 MB) that is fluent in the DSL and release it as a specialized coding backend. This aligns directly with current small-model and inference work.
- Publish reference implementations, an agent-friendly grammar + examples corpus, and list the language in catalogues such as agentlanguages.dev (syntactic / verification / orchestration taxonomy). Early high-quality examples and clear denotational documentation compound quickly.

### Practical starting sequence

1. Design (or refine) the surface for canonical forms and explicit intermediates; add a fast validator that returns structured domain errors.
2. Give the language a clean denotational semantics (Lean embedding or equivalent) so successful programs carry machine-checkable properties.
3. Expose the tools via MCP / agent skill and seed every relevant agent context with the grammar + 3–5 excellent examples.
4. For any multi-agent or on-chain deployment, make verified DSL programs the preferred or exclusive interface and encode the preference in the protocol or governance rules.
5. Optionally fine-tune a small specialized model and open the skill/validator.

Agents will adopt the DSL when it is simultaneously easier to generate correctly, cheaper to iterate on, and produces artifacts of higher downstream value. Your formal-methods and denotational-design strengths make the verification premium especially powerful—use it.

## 2. The rulings (2026-10-25, verbatim)


1. Q: "Which execution target(s) should the compiler emit? (The design is an offline protocol with no blockchain.)" Options offered: Wasm replica (Recommended), Native via TinyCC, EVM contract, JSON transcript only.
   A: "Wasm replica (Recommended)"
2. Q: "Which proof/certificate target(s) should every well-typed program also compile to?" Options offered: Cubical Agda (Recommended), zkml-lang Circuit IR, Lean 4 obligations, MPC circuit (Bristol).
   A (USER free text): "All proofs should be expressible within the guest language itself that we create."
3. Q: "How real should the cryptography be in v1?" Options offered: Sealed, law-only (Recommended); ElGamal tallies; ElGamal + FROST certs.
   A: "ElGamal + FROST certs"

## 3. The base design

The artifact in section 1 is "ThresholdVC Design", a denotational design in
Cubical Agda. Its two source listings are copied here without change:

- `design/ThresholdVC/Design.agda` (288 lines)
- `design/ThresholdVC/Prelude.agda` (79 lines)

Check (2026-10-25, Agda 2.7.0.1):

```sh
agda --cubical --safe -i design design/ThresholdVC/Design.agda
```

Exit code 0. No hole, no postulate, no unsafe pragma.

These two files are the reference meaning only. Ruling 2 says that each
proof is a guest term. So no build step and no gate step runs Agda.
`docs/PLAN.md` section 3 maps each name in the two files to a guest base
type, a guest operation or a guest law.
