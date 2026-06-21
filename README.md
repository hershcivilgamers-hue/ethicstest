# CAIRO.AIC

Personnel & organizational management terminal (SCP Foundation roleplay — Omega-1 and the Ethics Committee).
Hosted on GitHub Pages, embedded in Google Sites via an iframe.

## The files

| File | What it is | When you'd edit it |
|------|------------|--------------------|
| `index.html` | Page structure (markup, modals, navigation) | Rarely |
| `styles.css` | All styling | To change the look |
| `config.js`  | The two editable URLs (Firebase + Worker) | To repoint the backend |
| `app.js`     | All application logic | To change behaviour |

> **Keep all four files in the same folder.** They reference each other by relative
> path, so they must stay side by side. Do not rename them.

## Deploying (GitHub web interface, no terminal)

1. Open this repository on github.com.
2. Above the file list, click **Add file → Upload files**.
3. Drag all four files (`index.html`, `app.js`, `styles.css`, `config.js`) into the
   upload area, into the **root** of the repo.
4. Type a commit message and click **Commit changes**.

## Confirming it's live

1. Go to the **Settings** tab → left sidebar **Pages**.
2. **Source** = *Deploy from a branch*, your main branch, folder **/ (root)**.
3. The page shows **"Your site is live at …"** — that URL is your site. Because
   `index.html` sits at the root, the app is served at that folder URL directly
   (no filename needed).
4. Open that URL in a browser and confirm the app loads **before** updating Google Sites.

## Pointing Google Sites at it

Edit the Google Sites page, select the existing embed, and set its URL to the live
URL above. Nothing else in Google Sites changes — it is still just framing one URL.

## Editing later

Open a file in the repo → click the **pencil (Edit)** icon → make the change →
**Commit changes**. GitHub rebuilds in about a minute.

GitHub's CDN caches for ~10 minutes. If an update doesn't appear, either wait, or
bump the version query string on the references inside `index.html`:

```html
<script src="./config.js"></script>
<link rel="stylesheet" href="./styles.css?v=2">
<script src="./app.js?v=2"></script>
```

(increment to `?v=3`, `?v=4`, … on each future change you want to force-refresh.)

## Notes

- `config.js` holds the Firebase database URL and the Cloudflare Worker URL. These are
  already public in the client and safe to commit; the Worker keeps the AI key server-side.
- Data writes (including the trainings log at `/trainings`) currently use unauthenticated
  Firebase REST calls, so database access depends entirely on your Firebase security rules.
  Locking those down (and moving privileged writes behind the Worker) is the recommended
  next hardening step.
