# Recording the video demo

The whole demo runs from one page: the local demo app. The assignment asks the video to show **the design, the complete workflow, tool calls, rating rationale, evidence, and limitations**. All six are scenes in the app.

- **Narrators:** Paul records Part 1 (scenes 1–6), Supawich records Part 2 (scenes 7–12).
- **Length:** about 10–12 minutes in total.

## Before recording (5 minutes)

1. Start the app:

   ```bash
   cd assignment3/security-triage-agent
   source .venv/bin/activate
   python -m demo
   ```

2. Open **http://127.0.0.1:8765** in Chrome. Make the window large (about 1440×900 or bigger) and zoom to 100%.
3. Press **`P`** to open the **presenter window**. It shows the sentences to say for the current scene and follows you as you change scenes. Drag it to a second screen, or anywhere outside the area you record. Allow pop-ups if Chrome asks.
4. Press **`F`** if you want to hide the sidebar for a cleaner frame. The sidebar is useful on camera, though, because it shows where you are.
5. **Warm-up run** (Supawich): open scene 8 and press *Run the agent* once before recording. This shows whether Ollama Cloud is responsive today. A run takes about 40–110 seconds.

## Recording (macOS)

- Use **QuickTime Player → File → New Screen Recording**, choose *Record Selected Portion*, and frame only the browser window. Under *Options*, pick your microphone.
- Alternatively, use **Cmd + Shift + 5**.
- Each person records their own half; the two clips are joined afterwards. Or record together and hand over on scene 7.

## Scene by scene

The presenter window has the full narration for every scene. Below are the things to **click**.

| # | Scene | Who | Click / show | ~Time |
|---|---|---|---|---|
| 1 | The question we answer | Paul | Nothing; introduce both of you and the pipeline | 0:45 |
| 2 | CVE, NVD, CVSS and KEV | Paul | Point at the fixed-build table (Server 2016 → 9512), the CVSS vector (AV:L, PR:L), and the KEV dates | 1:30 |
| 3 | Northbridge Services | Paul | Click **W15**, scroll the drawer, click evidence **S08**. Switch the snapshot dropdown to *Check 1* and back | 1:30 |
| 4 | The rulebook | Paul | "23 High vs 1/1/1/20", the 5 steps, the matrices | 1:00 |
| 5 | Policy playground | Paul | Presets: W15 base → Check 1 → Check 2 → Check 3a → CA-ROOT01 | 1:15 |
| 6 | What the agent can call | Paul | **Try it** on lookup_vulnerability and lookup_environment; then the **scan_network** button. Hand over | 1:15 |
| 7 | How the agent works | Supawich | Press **Animate a run**; click the Validator and Policy boxes | 1:00 |
| 8 | Complete run | Supawich | **Run the agent** (base snapshot, no fault). Narrate while it runs, click a tool card, point at the validator card. At the end click **W15** and its evidence rows | 2:30 |
| 8b | Controlled failure | Supawich | Set *Controlled failure* to **NVD unreachable, no cache** and run: it stops in seconds and names `lookup_vulnerability`. Optional: **Model requests a fake tool** | 0:45 |
| 9 | The validator | Supawich | The baseline's attempt 1 (problems) vs attempt 2 (passed) | 0:45 |
| 10 | Expected vs actual | Supawich | The table; press **Replay** on check 3b; press **Run python -m pytest** | 1:15 |
| 11 | Human review of the evidence | Supawich | Open **Show me the source** on A1 and A2 (W15's build vs NVD and Microsoft's fixed build); show A11 marked ⚠; scroll to the signed sign-off | 1:00 |
| 12 | Limitations | Supawich | Read the cards and end on "Thank you" | 0:45 |

## If something goes wrong while recording

- **The live run is slow or stops with `stopped_model_error`** (Ollama's free tier sometimes returns HTTP 500): switch to the **Replay saved run** tab, choose *Baseline main run*, set the speed to 2×, and press *Play*. It replays a real recorded run with its real tool results. Say so on camera: "the model service is busy, so here is the recorded baseline run."
- **A scene shows "Could not load"**: the server stopped. Restart `python -m demo` and refresh.

## Before submitting the video

- **Before recording:** both of you go through scene 11 together (about 10 minutes): open each claim's source, mark ✓ or ⚠, then each signs at the bottom. Your marks are saved into `docs/evidence_review.md`; commit it afterwards.
- Live runs made during recording are saved in `outputs/demo_runs/`. Commit the one shown in the video as evidence of the demonstrated run.
