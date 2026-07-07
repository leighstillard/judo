# Issue tracker

This repo uses **GitHub Issues** (`leighstillard/judo`) for all planning artifacts.

## Wayfinding operations

The wayfinder map and its tickets live on GitHub Issues:

- **The map** is the issue labelled `wayfinder:map`. There is one per effort; its body is the low-res index (Destination, Notes, Decisions so far, Not yet specified, Out of scope).
- **Tickets** are issues labelled `wayfinder:research | wayfinder:prototype | wayfinder:grilling | wayfinder:task`, attached to the map as **sub-issues** (GitHub's native sub-issue relationship, via `gh api repos/{owner}/{repo}/issues/{map}/sub_issues`).
- **Claiming**: assign the issue to yourself (`gh issue edit N --add-assignee @me`) **before** any work. Open + unassigned = unclaimed.
- **Blocking** uses GitHub's native issue dependencies where available (`gh api repos/{owner}/{repo}/issues/{n}/dependencies/blocked_by`). Fallback if the API is unavailable: a `Blocked by: #N, #M` line at the top of the ticket body — a ticket is unblocked when every referenced issue is closed.
- **Frontier query**: open, unblocked, unassigned sub-issues of the map. Approximation: `gh issue list --label wayfinder:grilling,wayfinder:research,wayfinder:prototype,wayfinder:task --no-assignee`, then filter out tickets whose blockers are still open.
- **Resolving**: post the answer as a comment, close the issue, append a one-line pointer to the map's *Decisions so far*.
