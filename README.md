# Issue workshop

Private workshop for one journal issue or conference proceeding. Members upload papers, reviewers send reports, and the chief editor decides and produces page-numbered PDFs. This is separate from the public journal website.

Papers, reviews, accounts, and produced PDFs stay in `data/` on the computer that runs the workshop. That folder is not part of this repository.

## 1. Prerequisites

- Python 3.11 or newer
- pip

## 2. Run it

On Windows, double-click `start.bat`.

Or, from this folder:

```bash
python -m pip install -r requirements.txt
python workshop.py
```

The workshop listens on `http://127.0.0.1:8787/`. Keep that window open. Closing it stops the workshop.

The first visit asks for the chief editor and the journal or proceeding name. Volume and issue are optional. After that, sign in at the same address.

## 3. What the chief editor can do

- Edit the heading at the top of the page.
- Create a member when that person is ready to submit a paper.
- Create reviewers. Their sign-ins stay when the next issue starts.
- Assign two or three reviewers. Reviewers see the anonymous PDF, not the author names.
- Record a decision, then produce the issue from the starting page of the first article.
- Start a new issue when the current one is finished. That removes papers, comments, decisions, produced files, and member accounts. Save a copy of the history record and the page-numbered PDFs first.
