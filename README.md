# mo-jobs – Multi-Organisation RSS Job Feeds

Automated scraper that collects job vacancies from [UNjobs.org](https://unjobs.org/) for **18 international organisations** and publishes each as a separate RSS 2.0 feed. Designed to be consumed by an external job portal where each feed maps to a different organisation profile/logo.

## How it works

1. A GitHub Actions workflow runs **twice daily** (07:15 and 19:15 Copenhagen time).
2. For each organisation, the scraper:
   - Fetches the UNjobs.org listing pages (with pagination).
   - Collects vacancy links and deduplicates.
   - Fetches each vacancy detail page to extract title, description, dates, and original employer links.
   - Applies **global** and **org-specific filters** (see below).
   - Writes valid RSS 2.0 XML to `feeds/<org>_jobs.xml`.
3. Changed feeds are committed and pushed automatically.

## Filters

### Global exclusion: NO JPO

**All JPO (Junior Professional Officer) positions are excluded from every feed.** A vacancy is excluded if its title or description contains any of the following (case-insensitive):

- `JPO` (word boundary)
- `Junior Professional Officer`
- `JPO Service Centre`
- `JPOSC`
- `Japanese JPO`
- `Korean JPO`
- `sponsored JPO`

Rationale: JPO posts are country-financed; Switzerland posts its own JPOs separately, and non-Swiss JPOs are not relevant.

### UN Agency filters (UNDP, UNICEF, UNFPA, UN Women, UNHCR, WFP, RCS, OCHA, IFAD)

**Include:**
- UN staff grades P1–P6 and D1–D2.
- Senior leadership (ASG / USG / DSG) if present.
- UNV (UN Volunteer) opportunities related to that organisation.

**Exclude** (unless it is clearly UNV):
- Intern / Internship / Traineeship
- Consultant / Consultancy
- SSA / Individual Contractor
- National Officer / NOA–NOD / National Professional

The include rule (P/D grades + UNV) is primary; exclusions are secondary and do not remove valid P/D posts.

### Development Bank filters

| Organisation | Include | Exclude |
|---|---|---|
| **World Bank** | Grades GE / GF / GG / GH / GI / GJ / GK / GL | Grades GA–GD, Interns, Consultants |
| **IFC** | Same as World Bank (GE+) | Same as World Bank |
| **ADB** | Position Grade TI (any TI*) | Position Grade TL, Interns, Consultants |
| **AfDB** | PL* and EL* (Professional/Executive) | GS*, Interns, Consultants |
| **IDB** | International/professional staff signals (permissive) | Interns, National Staff |
| **IDB Invest** | Same approach as IDB | Same as IDB |
| **EBRD** | Titles: Analyst, Associate, Principal, Director, Managing Director, Banker | Intern, Assistant, Trainee |
| **GCF** | Grade C–F (permissive) | Intern |
| **AIIB** | All posts (permissive) | Intern |

Filter patterns are centralised in `config/filters.yml` and can be adjusted without touching the scraper code.

## Enabling GitHub Pages

To serve the RSS feeds as public URLs:

1. Go to **Settings** → **Pages** in this repository.
2. Under **Build and deployment**, select:
   - **Source:** Deploy from a branch
   - **Branch:** `main`
   - **Folder:** `/ (root)`
3. Click **Save**.
4. After a few minutes, your feeds will be available at the URLs below.

## RSS Feed URLs

Once GitHub Pages is enabled, feeds are available at:

```
https://cinfoposte.github.io/mo-jobs/feeds/<file>
```

### Full list (copy-paste ready)

- **UNDP:** https://cinfoposte.github.io/mo-jobs/feeds/undp_jobs.xml
- **UNICEF:** https://cinfoposte.github.io/mo-jobs/feeds/unicef_jobs.xml
- **UNFPA:** https://cinfoposte.github.io/mo-jobs/feeds/unfpa_jobs.xml
- **UN Women:** https://cinfoposte.github.io/mo-jobs/feeds/unwomen_jobs.xml
- **UNHCR:** https://cinfoposte.github.io/mo-jobs/feeds/unhcr_jobs.xml
- **WFP:** https://cinfoposte.github.io/mo-jobs/feeds/wfp_jobs.xml
- **RCS:** https://cinfoposte.github.io/mo-jobs/feeds/rcs_jobs.xml
- **OCHA:** https://cinfoposte.github.io/mo-jobs/feeds/ocha_jobs.xml
- **IFAD:** https://cinfoposte.github.io/mo-jobs/feeds/ifad_jobs.xml
- **World Bank:** https://cinfoposte.github.io/mo-jobs/feeds/worldbank_jobs.xml
- **IFC:** https://cinfoposte.github.io/mo-jobs/feeds/ifc_jobs.xml
- **AfDB:** https://cinfoposte.github.io/mo-jobs/feeds/afdb_jobs.xml
- **IDB:** https://cinfoposte.github.io/mo-jobs/feeds/idb_jobs.xml
- **IDB Invest:** https://cinfoposte.github.io/mo-jobs/feeds/idbinvest_jobs.xml
- **ADB:** https://cinfoposte.github.io/mo-jobs/feeds/adb_jobs.xml
- **EBRD:** https://cinfoposte.github.io/mo-jobs/feeds/ebrd_jobs.xml
- **GCF:** https://cinfoposte.github.io/mo-jobs/feeds/gcf_jobs.xml
- **AIIB:** https://cinfoposte.github.io/mo-jobs/feeds/aiib_jobs.xml

## Validating feeds

You can validate any feed using the W3C Feed Validation Service at `https://validator.w3.org/feed/` by pasting the feed URL. All feeds are generated as valid RSS 2.0 with UTF-8 encoding.

## Project structure

```
mo-jobs/
├── scraper.py                   # Main scraper script
├── requirements.txt             # Python dependencies
├── config/
│   ├── orgs.yml                 # Organisation definitions (URLs, filter profiles)
│   └── filters.yml              # Centralised filter patterns (global + per-org)
├── feeds/                       # Generated RSS feed files (one per org)
│   ├── undp_jobs.xml
│   ├── unicef_jobs.xml
│   └── ...
├── .github/workflows/
│   └── scrape.yml               # GitHub Actions: twice-daily scrape + commit
└── README.md
```

## Configuration

### Adding or modifying organisations

Edit `config/orgs.yml` to add a new organisation or change a UNjobs URL. Each entry needs:
- `key`: short identifier (used in logs)
- `display_name`: human-readable name (used in RSS title)
- `unjobs_url`: the UNjobs.org organisation listing URL
- `output_file`: path to the output RSS file
- `filter_profile`: name of the filter profile in `filters.yml`

### Adjusting filter rules

Edit `config/filters.yml`. Patterns are Python-compatible regular expressions matched case-insensitively against job title + description text.

## Running locally

```bash
pip install -r requirements.txt
python scraper.py
```

The scraper will create/update all XML files in `feeds/`. It logs progress to stdout and handles partial failures gracefully (one org failing does not stop the others).

## Notes

- **AIIB**: Listed on UNjobs.org but may have limited vacancy coverage. The feed scaffold exists and will populate if/when vacancies appear. If AIIB is not reliably available on UNjobs, the feed will remain empty — this is documented and expected.
- **IDB Invest**: Uses a best-guess UNjobs URL (`/organizations/idb-invest`). If this URL is not valid, the feed will be an empty scaffold. Adjust the URL in `config/orgs.yml` if a different slug is found.
- **GCF**: Uses the UNjobs path `/non-un-organizations/green-climate-fund` (GCF is listed under non-UN organisations on UNjobs).
- Rate limiting: the scraper sleeps between requests to be polite to UNjobs.org servers.
- GUIDs are stable SHA-256 hashes of the UNjobs vacancy URL, so items are not duplicated across feed updates.
