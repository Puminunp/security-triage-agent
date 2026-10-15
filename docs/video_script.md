# Video demo script

The whole demo runs from the local demo app (`python -m demo`, then http://127.0.0.1:8765).

- **Part 1, scenes 1–6:** Paul Prommark. Already recorded (6 clips, about 13 minutes). He covers why triage matters, CVE / NVD / CVSS / KEV, the Northbridge company, the rulebook and playground, and the tools. He ends with: *"Supawich will now show how the agent uses it, and what happens when things go wrong."*
- **Part 2, scenes 7–12:** Supawich. About 8 minutes. Script below.

## How to use this script

- **Don't read it word for word.** Read each scene once or twice before you record it. Then speak from the short **cue card** under each scene, in your own words. The full text is there so you know what the story is; the cue card is what you look at while talking.
- Record **one scene at a time** and join the clips afterwards, the way Paul did. If you stumble, redo just that scene.
- The thread to keep in mind for the whole part: **"We let the AI do the investigating, but we never let it have the last word."** Every scene is one piece of that idea.

### Before recording

1. Start the app and open http://127.0.0.1:8765 in Chrome, with a big window at 100% zoom.
2. Press **`P`** for the presenter window (it shows the cue cards). Drag it outside the recorded area.
3. Do one warm-up run on scene 8, so you know Ollama Cloud is responding today.
4. Record with **QuickTime → File → New Screen Recording → Record Selected Portion**, framing only the browser.

---

## Scene 7 · How the agent works (about 1:15)

**Do:** stay on the diagram. Press **Animate a run** after your first two sentences.

**Say (full text):**

> Thanks, Paul. So far you've seen the ingredients: the bug, the company, the rulebook, and the tools. Now I'll show how we put an AI in charge of using them, and how we make sure we can trust what it tells us.
>
> Think of the AI as a new intern. We hand it one bug ID and say: "find out which of our machines this affects." The intern is good at deciding *what to look up next*. Here it looks the bug up in NVD, checks the KEV list, then searches our company inventory for the Windows versions that are affected. Every time it wants something, it asks one of Paul's tools, and our code runs the lookup and hands the result back. That's this loop on the left.
>
> But an intern can make mistakes, or skip a step, or confidently make something up. So when the AI says "I'm done, here are my facts," we don't take its word for it. Our code checks every fact against what the tools actually returned. That's the validator. Then the rating is decided by the rulebook, written as normal code. To be precise about something from Paul's part: **the AI never picks the rating.** It gathers the facts; the rules decide.
>
> At the end, the AI writes a short "what to do next," and a person reviews the whole thing. The red boxes are where the system *stops and says "I'm not sure"* instead of guessing. I'll show you one of those in a minute.

**Cue card:**
- Thanks Paul: ingredients done, now the AI that uses them, and how we trust it
- The AI is like an intern: good at deciding *what to look up*
- The loop: the AI asks, a tool answers, the AI decides the next step
- We don't trust it: the validator checks every fact
- The rulebook, not the AI, picks the rating (correct Paul's slip)
- A human signs off; the red boxes mean "stop instead of guess"

---

## Scene 8 · A complete run (about 2:30)

**Do:** base snapshot, failure "None", then press **Run the agent**. Talk while the cards appear (it takes 1–2 minutes). Click one green tool card to show what came back. When it finishes, point at the **Bottom line**, then click **W15**.

**Say:**

> Now a real run. The only thing I give it is the bug ID, CVE-2026-85880. This is the real AI model on Ollama Cloud, plus live data from NVD and from CISA.
>
> Each card is one step. The purple cards are the AI deciding what to do. Here it decides to look up the bug in NVD first. The green card is the tool's answer, and I can click it to see the exact data that came back, including where it came from and when.
>
> Now it's searching our inventory for "Windows Server 2016," because NVD said that version is affected. Nobody told it to search for that; it worked it out from the NVD answer. Then it searches for the other affected versions and reads the supporting notes on each machine.
>
> *(when the orange validator card appears)* And here's the interesting part. The AI said "I'm done," and our validator sent it back. It forgot some machines, or skipped some evidence. It fixes that and tries again. This happens in almost every run, and I'll come back to it.
>
> *(when finished)* So, the answer to our question. Out of 23 Windows machines that *could* be affected, only one needs patching right now: W15, the old payroll servers. One is worth planning for: the offline root certificate server, which is vulnerable but switched off. One group needs a person to check: 12 laptops whose patch level we simply don't know. The other 20 are already patched.
>
> *(click W15)* And it doesn't just say "High." It shows why: the build is older than the fix, normal users log on to it, and it holds payroll data. Every fact links back to its source. It lists the assumptions it relied on and tells us what to do: install the September update.

**Cue card:**
- Only input: the bug ID. Real AI, live NVD and CISA
- Purple = the AI decides; green = a tool answers (click one)
- It chose to search "Windows Server 2016" on its own, from the NVD answer
- Validator card: the first answer gets sent back (come back to this)
- Bottom line: 1 patch now (W15), 1 plan (root CA, switched off), 12 laptops unknown so a person checks, 20 fine
- Click W15: why, sources, assumptions, what to do

### Scene 8b · When something breaks (about 0:45)

**Do:** set *Controlled failure* to **NVD unreachable, no cache** and press Run. It stops within a few seconds.

**Say:**

> Paul said I'd show what happens when things go wrong. Here I've cut off NVD, the database that tells us which builds are fixed, and there's no saved copy either. Without that, nobody can know which machines are safe. A bad system would guess, or quietly say everything's fine. Ours stops straight away and says "insufficient evidence," and names exactly which lookup failed. For security, "I don't know" is a much better answer than a confident wrong one.

**Cue card:** cut off NVD, no backup copy → it can't know what's fixed → it stops and says "insufficient evidence", naming the failed lookup → "I don't know" beats a confident wrong answer

---

## Scene 9 · The validator (about 1:00)

**Do:** point at the six checks, then at attempt 1 vs attempt 2 on the right.

**Say:**

> This is the validator, the part I'm most glad we built. Remember the AI's first answer got sent back? In every live run we did, the AI's first answer was incomplete. Sometimes it forgot 20 servers. Sometimes it never searched for Windows 10 at all.
>
> In a security tool, that's the worst kind of mistake. A machine you forgot to check looks exactly like a machine that's safe. So the validator checks six things against what the tools really returned. Does each machine actually exist? Does every number match? Did the AI search for every affected product? Did it read the evidence it relied on?
>
> If something's wrong, the AI gets the list of problems and two chances to fix them. If it still can't, that machine is marked "insufficient evidence." It never gets quietly rated as safe.

**Cue card:**
- The first answer was incomplete in every live run (forgot servers, skipped Windows 10)
- Worst mistake in security: a forgotten machine looks safe
- 6 checks against the real tool results
- 2 chances to fix, otherwise "insufficient evidence", never a silent "Low"

---

## Scene 10 · Testing (about 1:15)

**Do:** show the table. Press **Replay** on check 3b if you have time. Press **Run python -m pytest** at the end.

**Say:**

> How do we know this works beyond one example? We treated it like an experiment. Before running anything, we wrote down what the rulebook *should* say. Then we changed one thing at a time, using Paul's four test versions of the company.
>
> If we patch W15, it should drop to Low, and it does. If W15 holds no personal data and sits deep inside the network, it should drop to Medium, and it does. If we delete its build number, or give it two records that disagree, the agent should refuse to guess, and it says "insufficient evidence" both times, naming both sources in the second case.
>
> We also broke things on purpose: NVD down but with a saved copy, NVD down with no copy, and the AI asking for a tool that doesn't exist. Every result matches what we predicted. And there are 119 automatic tests that run without the internet. *(press the button)*

**Cue card:**
- An experiment: expected answers written first, then one change at a time
- Patched → Low ✓ · no personal data → Medium ✓ · missing or conflicting → "not sure" ✓
- Broke it on purpose: NVD down (with/without copy), fake tool ✓
- 119 automatic tests

---

## Scene 11 · Human review (about 1:00)

**Do:** open **Show me the source** on A1, then A2. Scroll to **A11** (⚠). Scroll to the sign-off.

**Say:**

> The last check is a person. Paul and I went through every claim behind the W15 rating and compared it with the original sources, not with the AI's own words.
>
> For example, the claim "W15 is on build 9339." The company record says 9339, the patch report says 9339, and the AI reported 9339. And the fix is build 9512: that's what NVD says, and also what Microsoft's own advisory says. So W15 is behind, and it's vulnerable.
>
> We confirmed 18 of 19 claims. One we flagged: the AI's suggested action included a step that misread a setting in the company file. That doesn't change the rating, because the rating comes from code, but it's exactly why a human signs off before anyone acts on it.

**Cue card:**
- A person checks every claim against the original sources
- Example: build 9339 in two company records and in the AI's answer; fix 9512 per NVD and Microsoft → vulnerable
- 18 of 19 confirmed; 1 flagged: a wrong step in the AI's advice (the rating is unaffected because code decides)
- That's why a human signs off

---

## Scene 12 · Limitations and wrap-up (about 1:00)

**Do:** stay on the cards, then end on "Thank you".

**Say:**

> To be honest about the limits: the company is fictional, so in real life you'd need a real, up-to-date inventory. The AI doesn't do exactly the same thing twice; the steps vary between runs, but the ratings didn't, because code decides them. Our "can it work here" check is written for this kind of bug, one that needs a normal user account. A bug that's attackable straight from the internet would need a different check. And the free AI service sometimes fails, so we retry and stop cleanly if it stays down.
>
> So, back to the question we started with: does this Windows bug put our company at risk? Yes, but really only on one machine, W15, which should be patched now. We get there with an AI that does the investigating, code that checks it and applies our rules, and a person who signs off. Thank you.

**Cue card:**
- Fictional company → real use needs a real inventory
- The AI's steps vary, the ratings didn't (code decides)
- The "can it work here" check is written for this bug type (needs a user account)
- Free AI service is flaky → retry, stop cleanly
- Answer: yes, but only W15, patch it now. AI investigates, code checks and decides, a human signs. Thank you

---

## If something goes wrong while recording

- **The run is slow or stops with `stopped_model_error`** (Ollama's free tier sometimes fails): switch to the **Replay saved run** tab, choose *Baseline main run*, speed 2×, and press Play. Say: "the AI service is busy right now, so here's the same run we recorded earlier."
- **A scene shows "Could not load":** restart `python -m demo` and refresh the page.
- Live runs made while recording are saved in `outputs/demo_runs/`. Tell Claude which one is in the video so it gets committed as evidence.
