# Target Venues

> Conferences and journals for potential submission of the Rootstock paper.
> Ranked by relevance to macOS security research and likelihood of acceptance.

## Primary Target

### Objective by the Sea (OBTS)

- **Website:** https://objectivebythesea.org
- **Focus:** macOS and iOS security — the only conference dedicated entirely to Apple platform security
- **Format:** Single-track, 2-day conference; 30–45 minute talks
- **Audience:** macOS security researchers, red teamers, Apple platform defenders
- **Why ideal:** OBTS is the natural home for Rootstock — the audience cares deeply about TCC, entitlements, and code signing. Past talks include Wojciech Regula's TCC bypass research and Csaba Fitzl's TCC deep dives.
- **Typical deadline:** CFP opens ~3 months before event (usually October/November)
- **Location:** Rotating (previously Hawaii, Spain, virtual)
- **Submission:** Abstract + demo proposal via CFP form

## Secondary Targets

### Black Hat Arsenal

- **Website:** https://www.blackhat.com/call-for-tools.html
- **Focus:** Tool demonstrations (not full papers)
- **Format:** 50-minute demo slot in the Arsenal area
- **Why suitable:** Arsenal is specifically for open-source security tools. BloodHound was first demoed at Arsenal. Rootstock fits the "new tool, live demo" format.
- **Deadlines:** USA (August) CFP typically March–April; Europe (December) CFP typically July–August
- **Submission:** Tool description + demo plan

### BSides (BSidesLV, BSidesSF, local chapters)

- **Website:** https://www.securitybsides.com
- **Focus:** Grassroots security research, tooling, and community talks
- **Format:** 20–30 minute talks; some chapters have tool tracks
- **Why suitable:** Lower barrier to entry than Black Hat/DEF CON. Good venue for first presentation of research tools. BSidesLV runs alongside DEF CON/Black Hat week.
- **Deadlines:** Vary by chapter; BSidesLV CFP typically March–May
- **Submission:** Abstract via CFP form

## Reach Targets (Full Academic Papers)

### USENIX Security Symposium

- **Website:** https://www.usenix.org/conference/usenixsecurity
- **Focus:** Systems security research (highly selective, ~15% acceptance)
- **Format:** Full paper (13 pages + references), peer-reviewed
- **Why relevant:** Published BloodHound-adjacent research and macOS security papers. Would require substantial evaluation section with multi-host scans.
- **Deadlines:** Rolling (3 cycles/year, typically June, October, February)
- **Submission:** Full paper via HotCRP

### ACM CCS (Conference on Computer and Communications Security)

- **Website:** https://www.sigsac.org/ccs/
- **Focus:** Broad computer security (highly selective, ~20% acceptance)
- **Format:** Full paper (12 pages), peer-reviewed
- **Deadlines:** Typically January and May (two submission cycles)

### IEEE S&P (Oakland)

- **Website:** https://www.ieee-security.org/TC/SP/
- **Focus:** Top-tier security venue (highly selective, ~12% acceptance)
- **Format:** Full paper (13 pages), peer-reviewed
- **Deadlines:** Rolling (quarterly)
- **Note:** Would require significant novelty beyond the tool itself — e.g., a formal model of macOS trust transitivity

## Recommendation

**Start with Objective by the Sea (OBTS)** as the primary target. The audience is perfectly aligned, the format (talk + demo) suits a tool presentation, and the acceptance bar is reasonable for a well-built open-source tool with real results.

**Simultaneously submit to Black Hat Arsenal** for tool exposure to a broader audience.

**If evaluation results are strong** (multiple novel attack paths discovered across a fleet), consider expanding the paper for USENIX Security or ACM CCS submission.
