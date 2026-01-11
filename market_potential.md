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
| **Free Trial** | $0 | — | 14-day full Hobby experience |
| **Hobby** | $15/mo | <$500/mo | Vibe coders, side projects, validating ideas |
| **Indie** | $29/mo | <$5K/mo | Serious indie dev, multiple products |
| **Pro** | $99/mo | <$50K/mo | Full-time business, needs API automation |
| **Business** | $499/mo | <$500K/mo | Scale with confidence, enterprise sales |
| **Enterprise** | Custom | $500K+/mo | Custom everything |

### Feature Matrix

| Feature | Self-host | Free Trial | Hobby | Indie | Pro | Business | Enterprise |
|---------|-----------|------------|-------|-------|-----|----------|------------|
| Offline activation | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Email activation codes | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Online activation | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Device limits | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Activation limits | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Products | ∞ | 1 | 1 | 3 | ∞ | ∞ | ∞ |
| Emails included | ∞ | 100 | 500 | 2K | 30K | 300K | Custom |
| Revenue cap | — | — | $500 | $5K | $50K | $500K | ∞ |
| API access | ✓ | — | — | — | ✓ | ✓ | ✓ |
| Online checks | ✓ | — | — | — | — | ✓ | ✓ |
| Revocation | ✓ | — | — | — | — | ✓ | ✓ |
| Audit logs | ✓ | — | — | — | — | ✓ | ✓ |
| SSO | ✓ | — | — | — | — | ✓ | ✓ |
| SLA | — | — | — | — | — | 99.9% | Custom |
| Support | Community | — | Email | Email | Priority | Priority | Dedicated |

### Upgrade Triggers

| Transition | Trigger | Your Price | Their Revenue | Your % |
|------------|---------|------------|---------------|--------|
| Hobby → Indie | $500/mo revenue | $29/mo | $500/mo | 5.8% |
| Indie → Pro | $5K/mo revenue | $99/mo | $5K/mo | 1.98% |
| Pro → Business | $50K/mo revenue | $499/mo | $50K/mo | 1.0% |
| Business → Enterprise | $500K/mo revenue | Custom | $500K+/mo | <0.1% |

### The Hobbyist Premium

Vibe coders at the Hobby tier are the ideal customer:
- **Pay reliably** — $15/month makes them feel like real developers
- **Use almost nothing** — No customers means no emails, no support tickets
- **Evangelize** — Excited about their projects, tell friends
- **Might graduate** — Some will ship and upgrade to Indie

A hobbyist with 0 sales costs us ~$0.01/month in email. That's **99.9% margin**. They subsidize the micro-product sellers who generate higher email volume.

### Upgrade Psychology

```
Old: $10 → $50 → $100 → $500 (5x, 2x, 5x jumps - uneven)
New: $15 → $29 → $99 → $499 (2x, 3.4x, 5x jumps - smooth progression)
```

Each jump is justified:
- **Hobby → Indie (2x)**: You're actually selling now, need multiple products
- **Indie → Pro (3.4x)**: You're scaling, need API automation
- **Pro → Business (5x)**: You're at scale, need control and visibility

### Comparison to Alternatives

**Option A: Paycheck + Stripe (you handle taxes)**

| Revenue | Paycheck | Stripe (~3%) | Total | vs Gumroad (10%) | vs LemonSqueezy (5%) |
|---------|----------|--------------|-------|------------------|----------------------|
| $500/mo | $15/mo | $15/mo | $30/mo | $50/mo | $25/mo |
| $2K/mo | $29/mo | $60/mo | $89/mo | $200/mo | $100/mo |
| $5K/mo | $29/mo | $150/mo | $179/mo | $500/mo | $250/mo |
| $10K/mo | $99/mo | $300/mo | $399/mo | $1,000/mo | $500/mo |
| $50K/mo | $99/mo | $1,500/mo | $1,599/mo | $5,000/mo | $2,500/mo |
| $100K/mo | $499/mo | $3,000/mo | $3,499/mo | $10,000/mo | $5,000/mo |

**Option B: Paycheck + LemonSqueezy (they handle taxes)**

| Revenue | Paycheck | LemonSqueezy (5%) | Total | What you get |
|---------|----------|-------------------|-------|--------------|
| $5K/mo | $29/mo | $250/mo | $279/mo | Full licensing + MoR tax handling |
| $10K/mo | $99/mo | $500/mo | $599/mo | Full licensing + MoR tax handling |
| $50K/mo | $99/mo | $2,500/mo | $2,599/mo | Full licensing + MoR tax handling |

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
- At $10K/mo: Option A saves ~$100/mo vs LemonSqueezy alone, plus full licensing features

---

## Revenue Projections

### Year 1 Projections (Conservative)

| Metric | Q1 | Q2 | Q3 | Q4 |
|--------|-----|-----|-----|-----|
| **Hobby** ($15) | 25 | 60 | 120 | 180 |
| **Indie** ($29) | 5 | 15 | 40 | 70 |
| **Pro** ($99) | 1 | 3 | 8 | 15 |
| **Business** ($499) | 0 | 1 | 2 | 5 |
| **MRR** | $599 | $2,430 | $5,988 | $11,225 |

**Year 1 totals:**
- Total paying customers: 270
- MRR at end of Y1: $11,225
- ARR run rate: **$134,700**

### Year 2 Projections (Growth)

| Tier | Customers | MRR |
|------|-----------|-----|
| Hobby | 350 | $5,250 |
| Indie | 150 | $4,350 |
| Pro | 40 | $3,960 |
| Business | 15 | $7,485 |
| Enterprise | 2 | $4,000 |
| **Total** | **557** | **$25,045** |

**Year 2 totals:**
- MRR: $25,045
- ARR: **$300,540**

### Year 3 Projections (Established)

| Tier | Customers | MRR |
|------|-----------|-----|
| Hobby | 550 | $8,250 |
| Indie | 300 | $8,700 |
| Pro | 80 | $7,920 |
| Business | 40 | $19,960 |
| Enterprise | 5 | $15,000 |
| **Total** | **975** | **$59,830** |

**Year 3 totals:**
- MRR: $59,830
- ARR: **$717,960**

### Revenue Growth Summary

| Year | Customers | MRR | ARR |
|------|-----------|-----|-----|
| Y1 | 270 | $11,225 | $134,700 |
| Y2 | 557 | $25,045 | $300,540 |
| Y3 | 975 | $59,830 | $717,960 |

### Customer Mix Evolution

| Year | Hobby % | Indie % | Pro % | Business % | Enterprise % |
|------|---------|---------|-------|------------|--------------|
| Y1 | 67% | 26% | 6% | 2% | 0% |
| Y2 | 63% | 27% | 7% | 3% | <1% |
| Y3 | 56% | 31% | 8% | 4% | <1% |

The mix naturally shifts toward higher tiers as customers succeed and upgrade. Hobby remains the largest segment by count but shrinks as a percentage over time.

### Average Revenue Per Customer

| Year | ARPC | Notes |
|------|------|-------|
| Y1 | $41.57/mo | Hobby-heavy, early adopters |
| Y2 | $44.96/mo | Mix shifting toward Indie/Pro |
| Y3 | $61.36/mo | Business tier growing, mature customer base |

The ARPC growth reflects customers succeeding and upgrading through tiers — exactly how the pricing is designed to work.

---

## Speculative: Stripe Connect Revenue Potential

### The Opportunity

Paycheck could evolve beyond SaaS subscription revenue by offering payment processing through Stripe Connect. This would position Paycheck as a Merchant of Record (MoR) for indie developers who:
- Don't want to set up their own Stripe accounts
- Need tax handling without LemonSqueezy's limitations
- Want a single vendor for payments + licensing

### Competitive Pricing Analysis

| Provider | Take Rate | Notes |
|----------|-----------|-------|
| Stripe Direct | 2.9% + $0.30 | Dev handles taxes, chargebacks |
| LemonSqueezy | 5% + $0.50 | MoR, handles taxes |
| Gumroad | 10% | MoR, handles taxes |
| Paddle | 5% + $0.50 | MoR, handles taxes |
| **Paycheck Connect** | 3.5% + $0.30 | MoR, handles taxes, full licensing |

**Proposed rate: 3.5% + $0.30 per transaction**

This is competitive because:
- **0.6% above Stripe Direct** — Fair premium for MoR tax handling
- **1.5% below LemonSqueezy** — Major savings at scale
- **Includes full licensing** — What LemonSqueezy can't do

At $50 average transaction:
- Stripe Direct: $1.75 (3.5%)
- Paycheck Connect: $2.05 (4.1%)
- LemonSqueezy: $3.00 (6.0%)
- Gumroad: $5.00 (10%)

### Transaction Volume Modeling

**Assumptions:**
- 20% of SaaS customers opt into Paycheck Connect (simplicity seekers)
- Average transaction: $50
- Transactions per customer: correlates with tier

| Year | Connect Customers | Avg Transactions/mo | GMV/mo | Transaction Revenue |
|------|-------------------|---------------------|--------|---------------------|
| Y1 | 54 (20% of 270) | 15 | $40,500 | $1,418 |
| Y2 | 111 (20% of 557) | 20 | $111,000 | $3,885 |
| Y3 | 195 (20% of 975) | 25 | $243,750 | $8,531 |

**Note:** These are net revenues after paying out to developers and covering Stripe's 2.9% + $0.30 base fees.

### Combined Revenue Model (SaaS + Connect)

| Year | SaaS ARR | Connect ARR | Total ARR | Connect % |
|------|----------|-------------|-----------|-----------|
| Y1 | $134,700 | $17,016 | $151,716 | 11% |
| Y2 | $300,540 | $46,620 | $347,160 | 13% |
| Y3 | $717,960 | $102,372 | $820,332 | 12% |

### Upside Scenario: Higher Adoption

If 40% of customers use Paycheck Connect (strong product-market fit for the "just works" crowd):

| Year | Connect Customers | GMV/mo | Connect ARR | Total ARR |
|------|-------------------|--------|-------------|-----------|
| Y1 | 108 | $81,000 | $34,032 | $168,732 |
| Y2 | 223 | $223,000 | $93,660 | $394,200 |
| Y3 | 390 | $487,500 | $204,744 | $922,704 |

### Strategic Benefits Beyond Revenue

1. **Stickier customers** — Payment processing + licensing = hard to leave
2. **Data insights** — Transaction data reveals product-market fit, churn risk
3. **Upsell trigger** — Can prompt tier upgrades based on actual revenue
4. **Network effects** — More volume = better negotiating position with Stripe
5. **Competitive moat** — "Full stack for indie devs" vs point solutions

### Risks and Considerations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Chargeback liability | High | Reserve fund, dev clawback policy |
| Tax complexity | High | Stripe Tax integration, start US-only |
| 1099 reporting burden | Medium | Automate with Stripe Connect payouts |
| Support volume increase | Medium | Clear SLAs, self-service dashboard |
| Regulatory overhead | Medium | Start simple, expand carefully |

### Implementation Phases

**Phase 1: US-Only Launch**
- Accept US customers only (simpler tax)
- 3.5% + $0.30 pricing
- Stripe Tax for sales tax
- Minimal chargeback reserve requirement

**Phase 2: International Expansion**
- EU/UK with VAT handling
- Per-country pricing if needed
- Partner with tax advisors

**Phase 3: Premium Features**
- Custom payout schedules
- White-label checkout
- Revenue analytics dashboard

### Connect Revenue Summary

Stripe Connect represents a meaningful revenue diversification opportunity:

- **Conservative (20% adoption):** +$100K ARR by Y3
- **Optimistic (40% adoption):** +$200K ARR by Y3
- **Combined potential:** $800K-$920K ARR by Y3

The transaction revenue serves as a "success tax" that scales with customer success — aligning Paycheck's incentives with developer outcomes while maintaining the flat-fee SaaS pricing that makes the core product attractive.

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
   - Paycheck Connect (Stripe Connect MoR option)

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
| Stripe Connect complexity | Medium | Medium | Phase rollout, start US-only |

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
- [ ] 270 paid customers
- [ ] $135K ARR
- [ ] Self-sustaining (covers infrastructure costs)

### Year 2 Goals

- [ ] 3,000 GitHub stars
- [ ] 20,000 Docker pulls
- [ ] 550 paid customers
- [ ] $300K ARR
- [ ] Profitable (founder salary)

### Year 3 Goals (with Connect)

- [ ] 5,000 GitHub stars
- [ ] 50,000 Docker pulls
- [ ] 975 paid customers
- [ ] $720K-$820K ARR (SaaS + Connect)
- [ ] Stripe Connect live and growing

---

## Conclusion

Paycheck sits at the intersection of three underserved needs:

1. **Indie developers** who want simple licensing
2. **Offline-capable apps** that can't rely on API calls
3. **Price-conscious creators** who resent platform fees

The market is large enough ($3B+ licensing, millions of Stripe merchants), and we've found a unique position: **complement, not compete.** Keygen does licensing but not payments. LemonSqueezy does payments and taxes but only basic licensing. Paycheck bridges the gap — and by supporting LemonSqueezy as a backend, we offer the best of both worlds.

With the addition of Stripe Connect, Paycheck can evolve into a full-stack solution for indie developers: licensing, payments, and tax handling in one place. The transaction revenue diversifies the business model while aligning with customer success.

**Bottom line:** A $700K-$800K ARR business is achievable within 3 years with focused execution on the indie developer segment. With Stripe Connect adoption, this could exceed $900K ARR.

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
