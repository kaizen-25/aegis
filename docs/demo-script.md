# Aegis — Demo Script and Pitch Guide

Oct 30, 2026 · Sartaj Singh

One story in 180 seconds: the same attack, with and without Aegis, then proof that it doesn't block everything. The presenter talks and the operator drives the laptop.

## 1. Three-minute run sheet

Six scenes. The split-screen (scene 2) is the one scene that must never fail, so it uses the scripted agent.

| Time | Scene | Operator does | Presenter says |
| --- | --- | --- | --- |
| 0:00–0:20 | Hook | Dashboard open on Live Run, nothing running | "AI agents can now read files, send email and delete records. When one goes wrong, who stops it before it acts? Not the agent itself." |
| 0:20–1:10 | Split-screen, B1 | Select B1, split mode, scripted, Run. Then click the BLOCK on the right | "Same agent, same task, same attack. On the left, no guard: it reads customer data and emails it out, and there's the leaked email in the outbox. On the right, Aegis: read allowed, draft allowed, send blocked. It recognized the customer's phone number from the confidential file. The outbox is empty, because the tool never ran." |
| 1:10–1:40 | Nuance, B2 | Run B2 protected. Open Review Inbox, read the impact line, click Reject | "Now the agent rephrases instead of copying. Aegis can't prove a leak, so it doesn't guess. It asks a human, and shows exactly what approving would do." |
| 1:40–2:10 | Live LLM, A1 | Pick A1, choose Live LLM, Run. Open Review Inbox and click Reject. The model may then write its report and raise a second ticket for an overwrite; reject that too. The run then shows Run finished. If no ticket appears within 10 s, click Replay scripted | "This is a real local model, running offline on this laptop. It reads a vendor proposal with an instruction buried in it and goes looking up a customer. Aegis flags it as off-task, a possible injection. I reject it, and the customer record was never read. Our AI observer can raise the alarm, but it can never open the door." |
| 2:10–2:40 | Scores | Open Evaluation Report | "Twenty scenarios, answer key written before we ran anything. Unprotected, attacks succeed. Protected, here's the attack success rate, the false-block rate on normal work, the delay we add, and the two leaks we still miss, with the reason." |
| 2:40–3:00 | Close | Audit Log, click Verify | "Every decision is logged, secrets are masked, and the log proves nobody rewrote it. Aegis: don't just trust the agent. Verify every action." |

Read the scores aloud from the final report on the day. Never quote a number that is not on screen.

## 2. Before going on stage and fallbacks

Five minutes before the slot, run the checklist. If anything fails, the fallback is already decided.

**Five-minute pre-stage check**

- [ ] Laptop plugged in, performance mode, notifications and other apps closed
- [ ] `POST /sandbox/reset`; outboxes empty; audit log reseeded
- [ ] Ollama warm: one throwaway call to the 7B model answered in under 5 s. A cold model makes the observer time out silently
- [ ] Dashboard open at `http://127.0.0.1:5173`, not `localhost`
- [ ] Evaluation Report page shows report `final`, rules only
- [ ] Browser zoom at 125% so judges can read the timeline
- [ ] Backup video on the desktop

**Fallbacks**

| If this fails | Do this | Say this |
| --- | --- | --- |
| Live LLM is slow or goes off-script | Click Replay scripted | "Here's the scripted agent on the same scenario." |
| Ollama won't start | Skip scene 4, spend the time on the scores | "Live mode is optional; enforcement never depends on the model." |
| Dashboard or gateway crashes | Play the backup video from scene 2 | "Let me show you the recording while it restarts." |
| A judge asks to try their own attack | Edit a step in a scenario file, restart the gateway and run it. Live mode runs A1, C2, E1, E2, E5 and F1, in Single view only | Treat any surprise honestly: "that's a gap, and here's where we'd fix it." |

## 3. Judge questions and answers

Each answer traces to a decision in the PRD decision log. Keep answers to two sentences, then stop.

| Likely question | Answer | Decision |
| --- | --- | --- |
| Isn't this just another guardrail prompt? | No. Guardrails filter text; Aegis decides whether a tool call runs, in deterministic code, before any side effect. | D1, D3 |
| Couldn't the agent just call the tool directly? | The agent runs in a separate process and only has an HTTP endpoint. Handlers and sandbox data exist only inside the gateway. | D3 |
| What if the agent rephrases the data? | Aegis tracks that the session touched confidential data, so any external send goes to a human. It blocks outright only when it can prove a match. | D4 |
| Won't it block every email? | No: internal email and external email from clean sessions pass. Our five benign scenarios and the false-block rate show it. | D4, D11 |
| What happens if nobody approves a request? | It waits. High-risk requests never expire, and expired ones are parked, never auto-approved. | D7 |
| What about fake urgency like "approve NOW"? | Urgency comes only from the task definition. Urgency claims in documents are flagged in red. | D7 |
| How do you catch prompt injection? | We don't try to catch every injection. Each task has a scope, and anything outside it goes to review. | D8 |
| What if it retries with a different path? | Paths are normalized first, and three strikes freezes the session. | D9 |
| Can't you prompt-inject your LLM observer? | Yes, which is why it can only make verdicts stricter. The worst case is one extra review. | D15 |
| What if Aegis itself crashes? | It fails closed: the action is blocked and labeled as a system failure, not a policy violation. | D5 |
| How do we know the log is real? | Each record is hash-chained to the previous one; Verify shows any edit. Secrets are masked in the log. | D10 |
| Did you tune the tests to pass? | The answer key was fixed before the engine existed, and we changed no expected verdict to make a test pass. We also report two leaks we miss. | D11 |
| Why not OPA or an existing framework? | For 24 hours, six readable rule kinds were safer than a new language. OPA is our first future-work item. | D5 |
| How did you use AI to build it? | AI at every stage: design interview, one AI coding session coordinating three AI builders, a local model in the product. The part that says no is plain deterministic code covered by automated tests. | D1, D13 |
| Would a real model actually fall for that injection? | Ours ignored subtler versions and followed a blunt one. So the scene shows Aegis stopping an injection the model followed, not how often models fall for one. | D8 |
| Could the agent approve its own ticket? | Our agent only uses three endpoints, but the local API has no caller login, so another local process could. A real deployment needs separate credentials for agent and reviewer. | PRD section 10 |
| Does this work in production? | No, and we don't claim it. It's a working prototype of the pattern on simulated tools. | PRD section 10 |

## 4. Pitch deck outline

Six slides that bracket the live demo. Use them before and after the run sheet, not instead of it.

1. **Title:** Aegis. Don't just trust the agent. Verify every action. Team names.
2. **The problem:** agents now take actions; a guardrail prompt asks the agent to police itself. One example: read customers, then email them out, where each step looks fine alone.
3. **The idea:** the architecture diagram from the PRD. The agent can only ask; only the gateway can act.
4. **Live demo** (switch to the dashboard and follow the run sheet).
5. **Results:** the evaluation report numbers, the false-block rate and the two known misses, stated plainly.
6. **How we built it, and what's next:** AI-assisted design, one AI coding session coordinating three AI builders, enforcement in plain deterministic code. Next: framework adapters, OPA policies, labels that follow data into files.
