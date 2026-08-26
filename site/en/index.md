---
layout: home

hero:
  name: "SweepX"
  text: "Safety-first disk analysis and cleanup design snapshot"
  tagline: "This site documents a research and interface-design snapshot only. Real scanning, Trash, and permanent deletion remain under development and are unavailable or unqualified."
  image:
    src: /mark.svg
    alt: SweepX
  actions:
    - theme: brand
      text: Read Introduction
      link: /en/guide/introduction
    - theme: alt
      text: Safety Model
      link: /en/safety
    - theme: alt
      text: 中文
      link: /

features:
  - title: Honest current state
    details: SweepX is not a released product today. The site describes future acceptance constraints, not present-day deletion capability.
  - title: Destructive paths stay locked
    details: Trash and permanent deletion are constrained capability tracks. They are not available in the current implementation and have not been qualified for release.
  - title: One message across locales
    details: Chinese is the default locale at / and English lives under /en/. Both locales carry the same safety posture, navigation, and roadmap framing.
---

> [!WARNING]
> **SweepX is still under development.** The repository does not ship a runnable SweepX CLI/TUI today, and no destructive workflow should be treated as available.

## What this site is

SweepX aims to separate observation, explanation, authorization, and platform action instead of turning a scan result directly into deletion. This site explains that design intent without overstating current implementation status.

## What this site is not

| Topic | Current reality |
|---|---|
| Runnable product | Not provided |
| Real cleanup execution | Not provided |
| Qualified destructive feature | Not provided |
| Production support claim | Not provided |

## Core takeaway

The most important message is simple:

- The implementation is still under development.
- Destructive features are unavailable.
- Permanent mode is not qualified and must not be implied by the documentation.
