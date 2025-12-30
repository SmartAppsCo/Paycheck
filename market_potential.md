# Paycheck Market Analysis

## Executive Summary

Paycheck targets indie developers who need licensing for offline-capable apps without the complexity of enterprise solutions or the revenue cut of platforms like Gumroad/LemonSqueezy.

**Key opportunity:** No existing solution offers full-featured licensing with integrated payments. Keygen does licensing but not payments. LemonSqueezy does payments but only basic licensing (API validation, no offline support, no device limits). Paycheck bridges this gap — and can use LemonSqueezy as a payment backend, giving developers the best of both worlds: LemonSqueezy's MoR tax handling + Paycheck's powerful licensing features.

---

## Market Size

### Total Addressable Market (TAM)

**Software Licensing Management Market**
- $3.3B in 2024, projected $7.9B by 2030 (16.2% CAGR)
- Source: [Grand View Research](https://www.grandviewresearch.com/industry-analysis/software-licensing-management-market-report)

**Stripe Merchant Base**
- 4+ million businesses use Stripe
- 1,000+ new companies join daily
- 673,952 stores in USA alone
- Source: [Stripe Statistics](https://capitaloneshopping.com/research/stripe-statistics/)

### Serviceable Addressable Market (SAM)

**Indie/Solo Developers**
- 47.2 million software developers worldwide
- 39% of indie SaaS founders are solo (MicroConf 2024)
- 48% of profitable software businesses have 3 or fewer people
- Source: [Indie Hackers](https://www.indiehackers.com/post/saas-benchmark-report-2024-9b1e470a0b)

**Gumroad as Proxy**
- 19,280 live stores on Gumroad
- 46,000 creators made money on platform (2020)
- $171M GMV in 2023
- Source: [Gumroad Statistics](https://getlatka.com/companies/gumroad)

**Indie Games Market**
- $4.85B market in 2025, projected $9.55B by 2030
- 58% of Steam copies sold are indie games
- Source: [Mordor Intelligence](https://www.mordorintelligence.com/industry-reports/indie-game-market)

### Serviceable Obtainable Market (SOM)

Conservative estimate of developers who:
1. Sell software (not just SaaS)
2. Need real licensing (not just API key validation)
3. Want integrated payments
4. Are underserved by current solutions

**Estimate: 50,000 - 100,000 potential customers**

Based on:
- Gumroad has ~20K active stores
- Keygen has unknown but smaller base (niche)
- Many devs use no licensing (just honor system)
- Growing "vibe coding" trend creating more indie apps

---

## Competitive Landscape

| Solution | Payments | Licensing Features | Tax Handling | Pricing |
|----------|----------|-------------------|--------------|---------|
| **Keygen** | No | Full (offline, device limits, etc.) | No | Free CE / Paid cloud |
| **LemonSqueezy** | Yes | Basic (API validation only) | Yes (MoR) | 5% + $0.50 |
| **Gumroad** | Yes | Minimal | Yes (MoR) | 10% + fees |
| **Paddle** | Yes | Basic | Yes (MoR) | 5% + $0.50 |
| **Paycheck + Stripe** | Yes | Full (offline, device limits, etc.) | No | Flat fee |
| **Paycheck + LemonSqueezy** | Yes | Full (offline, device limits, etc.) | Yes (MoR) | Flat fee + LS fees |

**Key insight:** Paycheck doesn't compete with LemonSqueezy — it complements it. Use LemonSqueezy as your payment backend to get their MoR tax handling, plus Paycheck's full licensing capabilities (offline validation, device limits, perpetual + updates model, feature flags) that LemonSqueezy doesn't offer.

### Competitor Analysis

**Keygen**
- Strengths: Mature, self-hostable, full-featured
- Weaknesses: No payment integration, complex for simple use cases
- Pricing: Free tier (100 ALUs), paid tiers unlisted
- Source: [Keygen Pricing](https://keygen.sh/pricing/)

**LemonSqueezy**
- Strengths: Easy setup, handles taxes, nice UI
- Weaknesses: Basic licensing only (no offline, no device limits, requires API call for every validation)
- Pricing: 5% + $0.50 per transaction
- Risk: Acquired by Stripe (July 2024), future uncertain
- Source: [LemonSqueezy Docs](https://docs.lemonsqueezy.com/help/licensing)

**Gumroad**
- Strengths: Simple, established, creator-focused
- Weaknesses: High fees (10%), basic licensing, declining GMV
- Revenue: $23.8M in 2024, down from COVID peak
- Source: [Sacra Research](https://sacra.com/c/gumroad/)

### Paycheck's Differentiation

1. **Offline-first**: Cryptographically signed JWTs work without phone-home
2. **Bring Your Own Payment Provider**: Supports both Stripe and LemonSqueezy backends
3. **Best of both worlds**: Use LemonSqueezy for tax handling + Paycheck for full licensing
4. **Self-hostable**: Docker container, no vendor lock-in
5. **Integrated flow**: Payment → license in one step
6. **Flat pricing**: Predictable costs that don't scale with your revenue

---

## Target Customer Segments

### Segment 1: Indie App Developers (Primary)

**Profile:**
- Solo or small team (1-3 people)
- Building desktop apps, CLI tools, browser extensions
- Selling for $10-100 one-time or small subscriptions
- Technical but don't want to build licensing infrastructure

**Pain points:**
- LemonSqueezy doesn't work offline
- Keygen requires separate payment integration
- Gumroad takes 10%
- Building own solution is weeks of work

**Size:** ~30,000 potential customers

### Segment 2: Indie Game Developers

**Profile:**
- Solo or small studio
- Selling on itch.io, own website (not just Steam)
- Need offline validation (games shouldn't require internet)
- Price-sensitive, every % matters

**Pain points:**
- Steam takes 30%
- Existing solutions don't understand games
- Need simple DRM-free licensing

**Size:** ~15,000 potential customers (non-Steam focused)

### Segment 3: "Vibe Coders" (Emerging)

**Profile:**
- Building apps with AI assistance
- First-time software sellers
- Want simplest possible setup
- Making tools, utilities, small SaaS

**Pain points:**
- Don't know where to start with licensing
- Overwhelmed by enterprise solutions
- Just want to get paid

**Size:** ~20,000 and growing rapidly

### Segment 4: Bootstrapped SaaS with Desktop/Offline Components

**Profile:**
- Small SaaS with desktop app or offline mode
- Subscription + perpetual license hybrid
- Need device limits, updates expiration

**Pain points:**
- LemonSqueezy can't do offline
- Keygen requires managing two systems (payments + licensing)

**Size:** ~10,000 potential customers

---

## Pricing Structure

### Tiers

| Tier | Price | Revenue Cap | Target |
|------|-------|-------------|--------|
| **Self-hosted** | $0 | Unlimited | DIYers, enterprises evaluating |
| **Starter** | $10/mo | <$1K/mo | Testing the market, first product |
| **Indie** | $50/mo | <$10K/mo | Serious indie dev, multiple products |
| **Pro** | $100/mo | <$100K/mo | Full-time business, needs API |
| **Business** | $500/mo | <$1M/mo | Compliance needs, revocation |
| **Enterprise** | Let's talk | $1M+/mo | Custom everything |

### Feature Matrix

| Feature | Self-host | Starter | Indie | Pro | Business | Enterprise |
|---------|-----------|---------|-------|-----|----------|------------|
| Offline activation | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Online activation | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| Device limits | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| Activation limits | ✓ | — | ✓ | ✓ | ✓ | ✓ |
| Products | ∞ | 1 | 5 | ∞ | ∞ | ∞ |
| API access | ✓ | — | — | ✓ | ✓ | ✓ |
| Online checks | ✓ | — | — | — | ✓ | ✓ |
| Revocation | ✓ | — | — | — | ✓ | ✓ |
| Audit logs | ✓ | — | — | — | ✓ | ✓ |
| SSO | ✓ | — | — | — | ✓ | ✓ |
| SLA | — | — | — | — | 99.9% | Custom |
| Support | Community | Email | Email | Priority | Priority | Dedicated |

### Upgrade Triggers

| Transition | Trigger | Your Price | Their Revenue | Your % |
|------------|---------|------------|---------------|--------|
| Starter → Indie | $1K/mo revenue | $50/mo | $1K/mo | 5% |
| Indie → Pro | $10K/mo revenue | $100/mo | $10K/mo | 1% |
| Pro → Business | $100K/mo revenue | $500/mo | $100K/mo | 0.5% |
| Business → Enterprise | $1M/mo revenue | Custom | $1M+/mo | <0.1% |

### Comparison to Alternatives

**Option A: Paycheck + Stripe (you handle taxes)**

| Revenue | Paycheck | Stripe (~3%) | Total | vs Gumroad (10%) | vs LemonSqueezy (5%) |
|---------|----------|--------------|-------|------------------|----------------------|
| $1K/mo | $10/mo | $30/mo | $40/mo | $100/mo | $50/mo |
| $5K/mo | $50/mo | $150/mo | $200/mo | $500/mo | $250/mo |
| $10K/mo | $50/mo | $300/mo | $350/mo | $1,000/mo | $500/mo |
| $50K/mo | $100/mo | $1,500/mo | $1,600/mo | $5,000/mo | $2,500/mo |
| $100K/mo | $500/mo | $3,000/mo | $3,500/mo | $10,000/mo | $5,000/mo |

**Option B: Paycheck + LemonSqueezy (they handle taxes)**

| Revenue | Paycheck | LemonSqueezy (5%) | Total | What you get |
|---------|----------|-------------------|-------|--------------|
| $10K/mo | $50/mo | $500/mo | $550/mo | Full licensing + MoR tax handling |
| $50K/mo | $100/mo | $2,500/mo | $2,600/mo | Full licensing + MoR tax handling |

**Option C: Hybrid (developer-configured routing)**

Developer defines routing rules by geography:
- Country level (US, GB, DE...)
- Bloc level (EU, EEA...)
- State/province level (CA, NY, Ontario...)
- County level if needed (for complex US jurisdictions)

Example: Route EU/UK → LemonSqueezy (MoR), everywhere else → Stripe (cheaper).

**Important:** Paycheck provides the routing mechanism. The developer configures the rules based on their tax situation. Tax compliance is the developer's responsibility — we don't provide tax advice or make routing decisions for them.

**Bottom line:**
- Want cheapest? Paycheck + Stripe (handle taxes yourself or use Quaderno ~$50/mo)
- Want easiest? Paycheck + LemonSqueezy (they handle taxes, you get full licensing they don't offer)
- Want optimized? Paycheck + both (configure your own routing rules based on your tax situation)
- At $10K/mo: Option A saves ~$150/mo vs LemonSqueezy alone, plus full licensing features

---

## Revenue Projections

### Year 1 Projections (Conservative)

| Metric | Q1 | Q2 | Q3 | Q4 |
|--------|-----|-----|-----|-----|
| **Starter** ($10) | 20 | 50 | 100 | 150 |
| **Indie** ($50) | 5 | 15 | 40 | 70 |
| **Pro** ($100) | 1 | 3 | 8 | 15 |
| **Business** ($500) | 0 | 1 | 2 | 5 |
| **MRR** | $550 | $2,050 | $4,800 | $9,000 |

**Year 1 totals:**
- Total paying customers: 240
- MRR at end of Y1: $9,000
- ARR run rate: **$108,000**

### Year 2 Projections (Growth)

| Tier | Customers | MRR |
|------|-----------|-----|
| Starter | 300 | $3,000 |
| Indie | 150 | $7,500 |
| Pro | 40 | $4,000 |
| Business | 15 | $7,500 |
| Enterprise | 2 | $4,000 |
| **Total** | **507** | **$26,000** |

**Year 2 totals:**
- MRR: $26,000
- ARR: **$312,000**

### Year 3 Projections (Established)

| Tier | Customers | MRR |
|------|-----------|-----|
| Starter | 500 | $5,000 |
| Indie | 300 | $15,000 |
| Pro | 80 | $8,000 |
| Business | 40 | $20,000 |
| Enterprise | 5 | $15,000 |
| **Total** | **925** | **$63,000** |

**Year 3 totals:**
- MRR: $63,000
- ARR: **$756,000**

### Revenue Growth Summary

| Year | Customers | MRR | ARR |
|------|-----------|-----|-----|
| Y1 | 240 | $9,000 | $108,000 |
| Y2 | 507 | $26,000 | $312,000 |
| Y3 | 925 | $63,000 | $756,000 |

### Average Revenue Per Customer

| Year | ARPC | Notes |
|------|------|-------|
| Y1 | $37.50/mo | Starter-heavy, early adopters |
| Y2 | $51.28/mo | Mix shifts toward Indie/Pro |
| Y3 | $68.11/mo | Business tier growing |

The ARPC growth reflects customers succeeding and upgrading through tiers — exactly how the pricing is designed to work.

---

## Go-to-Market Strategy

### Phase 1: Launch

1. **Ship MVP**
   - Paycheck server (Stripe + LemonSqueezy backends)
   - Web SDK (TypeScript)
   - Basic dashboard
   - Docker image for self-hosting

2. **Seed community**
   - Post on Indie Hackers, Hacker News
   - "Show HN: Open source licensing for indie apps"
   - Target: 500 GitHub stars, 200 signups

3. **Content**
   - "How to add real licensing to your LemonSqueezy app"
   - "The missing piece for desktop apps: offline-first licensing"
   - "Stop paying 10% to Gumroad"

### Phase 2: Growth

1. **Expand SDK support**
   - Desktop SDKs (Electron, Tauri, native)
   - Mobile (React Native, Flutter)

2. **Add payment providers**
   - Paddle
   - Stripe Link

3. **Partnerships**
   - Integration with popular frameworks
   - Tutorials with indie dev YouTubers

### Phase 3: Scale

1. **Enterprise features** (paid tier differentiator)
   - Team seats
   - SSO
   - Audit logs

2. **Geographic expansion**
   - Multi-currency
   - Localized docs

---

## Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Stripe builds this | Medium | High | Self-hosted option, multi-provider support |
| Keygen adds payments | Medium | Medium | Focus on simplicity, indie positioning |
| LemonSqueezy adds offline | Low | Medium | We integrate with LS — if they add it, we pivot to other value props |
| Low conversion to paid | Medium | Medium | Self-host is genuinely free, paid tiers offer real value (hosting, support) |
| Self-hosters don't pay | Expected | Low | They become evangelists, enterprise needs paid support |

---

## Why Now?

1. **"Vibe coding" explosion**: AI tools creating more indie devs who need simple solutions
2. **LemonSqueezy uncertainty**: Stripe acquisition creating churn opportunity
3. **Gumroad backlash**: 10% fee + declining platform driving creators away
4. **Desktop renaissance**: Electron, Tauri, and native apps growing (not everything is SaaS)
5. **Offline-first movement**: Privacy concerns, unreliable internet, air-gapped environments

---

## Success Metrics

### Year 1 Goals

- [ ] 1,000 GitHub stars
- [ ] 5,000 Docker pulls (self-hosted adoption)
- [ ] 240 paid customers
- [ ] $108K ARR
- [ ] Self-sustaining (covers infrastructure costs)

### Year 2 Goals

- [ ] 3,000 GitHub stars
- [ ] 20,000 Docker pulls
- [ ] 500 paid customers
- [ ] $312K ARR
- [ ] Profitable (founder salary)

---

## Conclusion

Paycheck sits at the intersection of three underserved needs:

1. **Indie developers** who want simple licensing
2. **Offline-capable apps** that can't rely on API calls
3. **Price-conscious creators** who resent platform fees

The market is large enough ($3B+ licensing, millions of Stripe merchants), and we've found a unique position: **complement, not compete.** Keygen does licensing but not payments. LemonSqueezy does payments and taxes but only basic licensing. Paycheck bridges the gap — and by supporting LemonSqueezy as a backend, we offer the best of both worlds.

**Bottom line:** A $300K-700K ARR business is achievable within 2-3 years with focused execution on the indie developer segment.

---

## Sources

- [Grand View Research - Software Licensing Market](https://www.grandviewresearch.com/industry-analysis/software-licensing-management-market-report)
- [Mordor Intelligence - Indie Game Market](https://www.mordorintelligence.com/industry-reports/indie-game-market)
- [Gumroad Statistics](https://getlatka.com/companies/gumroad)
- [Stripe Statistics](https://capitaloneshopping.com/research/stripe-statistics/)
- [Indie Hackers SaaS Report](https://www.indiehackers.com/post/saas-benchmark-report-2024-9b1e470a0b)
- [Keygen Pricing](https://keygen.sh/pricing/)
- [LemonSqueezy Docs](https://docs.lemonsqueezy.com/help/licensing)
- [Sacra - Gumroad Research](https://sacra.com/c/gumroad/)
