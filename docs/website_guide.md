# Website Deployment & Customization Guide

This guide explains how to customize, preview, and deploy the Mr Ninja website.

## Quick Links

- **Live Site**: https://your-group.gitlab.io/mr-ninja/
- **Documentation**: https://your-group.gitlab.io/mr-ninja/docs.html
- **GitLab Pages Settings**: https://gitlab.com/your-group/mr-ninja/-/pages

## Local Preview

Preview the website on your local machine before deploying:

### Unix/Linux/macOS
```bash
./preview_site.sh
```

### Windows PowerShell
```powershell
.\preview_site.ps1
```

The website will open automatically in your browser at `http://localhost:8000`.

## Customization

### 1. Update GitLab Project Links

The website currently uses placeholder links `your-group/mr-ninja`. Replace these with your actual GitLab project path:

**Files to update:**
- `public/index.html` — Search for `your-group/mr-ninja` and replace
- `public/docs.html` — Search for `your-group/mr-ninja` and replace
- `public/robots.txt` — Update sitemap URL
- `README.md` — Update website links at the top

**Quick find & replace (Unix/Linux/macOS):**
```bash
# From project root
find public README.md -type f -exec sed -i 's/your-group\/mr-ninja/actual-group\/mr-ninja/g' {} +
```

**Quick find & replace (Windows PowerShell):**
```powershell
# From project root
Get-ChildItem -Path public,. -Include *.html,*.md,*.txt -Recurse | 
  ForEach-Object {
    (Get-Content $_.FullName) -replace 'your-group/mr-ninja', 'actual-group/mr-ninja' | 
    Set-Content $_.FullName
  }
```

### 2. Customize Colors

Edit `public/styles.css` and modify the CSS custom properties:

```css
:root {
    --primary: #4F46E5;        /* Primary brand color */
    --secondary: #10B981;      /* Secondary color */
    --dark: #111827;           /* Dark text/backgrounds */
    --critical: #DC2626;       /* Critical severity */
    --warning: #F59E0B;        /* Warning severity */
    --success: #10B981;        /* Success color */
    --info: #3B82F6;          /* Info color */
}
```

### 3. Update Content

**Landing Page** (`public/index.html`):
- Hero section — Line 27-95
- Features — Line 171-205
- Demo examples — Line 266-309

**Documentation** (`public/docs.html`):
- Sidebar navigation — Line 41-73
- Content sections — Line 76 onwards

**404 Page** (`public/404.html`):
- Error message and links

### 4. Add New Documentation Sections

To add a new section to the documentation:

1. **Add to sidebar** in `docs.html`:
```html
<div class="nav-section">
    <div class="nav-title">Your Section</div>
    <a href="#new-topic" class="nav-link">New Topic</a>
</div>
```

2. **Add content section**:
```html
<section id="new-topic">
    <h1>New Topic</h1>
    <p>Your content here...</p>
</section>
```

The JavaScript will automatically:
- Highlight the active section in the sidebar
- Enable smooth scrolling
- Add anchor links to headings

### 5. Add Images or Assets

1. Create an `assets` or `images` folder in `public/`:
```bash
mkdir -p public/assets/images
```

2. Add your images

3. Reference in HTML:
```html
<img src="assets/images/screenshot.png" alt="Screenshot">
```

4. Optimize images before adding:
   - Use WebP format for modern browsers
   - Provide PNG/JPG fallback
   - Compress with tools like TinyPNG or ImageOptim

## Deployment

### Automatic Deployment (Recommended)

The website automatically deploys to GitLab Pages when you push to the `main` branch:

```bash
git add public/
git commit -m "Update website"
git push origin main
```

The GitLab CI pipeline will:
1. Run tests
2. Build the site (copy files to `public/` artifact)
3. Deploy to GitLab Pages

**Check deployment status:**
- Pipeline: https://gitlab.com/your-group/mr-ninja/-/pipelines
- Pages: https://gitlab.com/your-group/mr-ninja/-/pages

### Manual Testing Before Deploy

1. **Run local preview** (see above)
2. **Test on different devices/browsers**
3. **Check for broken links**:
```bash
# Install link checker (optional)
npm install -g broken-link-checker

# Check links
blc http://localhost:8000 -ro
```

4. **Validate HTML** (optional):
```bash
# Install HTML validator
npm install -g html-validator-cli

# Validate
html-validator public/index.html
html-validator public/docs.html
```

## Troubleshooting

### Site Not Updating

1. **Check GitLab Pages settings**:
   - Go to Settings → Pages in your GitLab project
   - Ensure Pages is enabled
   - Verify the deployment URL

2. **Check CI pipeline**:
   - Look at CI/CD → Pipelines
   - Ensure the `pages` job succeeded
   - Check job logs for errors

3. **Clear browser cache**:
   - Hard refresh: Ctrl+F5 (Windows/Linux) or Cmd+Shift+R (macOS)
   - Or open in incognito/private mode

### CSS/JS Not Loading

1. **Check file paths** — GitLab Pages serves from `your-group.gitlab.io/project-name/`
2. **Use relative paths** — All paths in HTML should be relative (e.g., `styles.css` not `/styles.css`)
3. **Verify artifact** — Download the `public` artifact from the pipeline and check files

### 404 Errors

1. **Ensure files are in the `public/` directory** (not subdirectories)
2. **Check filename case** — File systems are case-sensitive in production
3. **Verify GitLab Pages configuration** — Default 404 page should be `404.html`

### Python Server Won't Start

```bash
# Check if port 8000 is in use
lsof -i :8000        # Unix/Linux/macOS
netstat -ano | findstr :8000    # Windows

# Use a different port
python3 -m http.server 8080
```

## Advanced Customization

### Add Google Analytics

Add to `<head>` in `index.html` and `docs.html`:

```html
<!-- Google Analytics -->
<script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'G-XXXXXXXXXX');
</script>
```

### Add a Sitemap

Create `public/sitemap.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://your-group.gitlab.io/mr-ninja/</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://your-group.gitlab.io/mr-ninja/docs.html</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
</urlset>
```

### Use a Static Site Generator

For more complex sites, consider using:
- **Hugo** — Fast, Go-based SSG
- **Jekyll** — Ruby-based, native GitLab Pages support
- **MkDocs** — Python-based, great for documentation
- **Docusaurus** — React-based, feature-rich

## Performance Optimization

### Minify CSS/JS

```bash
# Install minifiers
npm install -g clean-css-cli uglify-js

# Minify CSS
cleancss -o public/styles.min.css public/styles.css

# Minify JS
uglifyjs public/script.js -o public/script.min.js -c -m
```

Then update HTML to reference `.min.css` and `.min.js` files.

### Optimize Images

```bash
# Install imagemagick
brew install imagemagick      # macOS
apt install imagemagick       # Linux

# Convert to WebP
convert image.png -quality 85 image.webp

# Resize large images
convert screenshot.png -resize 1200x screenshot-optimized.png
```

### Enable Caching

Add cache headers via `.gitlab-ci.yml` (requires GitLab Pages advanced config):

```yaml
pages:
  script:
    # ... existing build steps ...
    - echo "Cache-Control: public, max-age=86400" > public/_headers
```

## Security

### HTTPS

GitLab Pages automatically serves sites over HTTPS. No configuration needed.

### Content Security Policy

Add to `<head>` in HTML files:

```html
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;">
```

## Need Help?

- **GitLab Pages Docs**: https://docs.gitlab.com/ee/user/project/pages/
- **Open an Issue**: https://gitlab.com/your-group/mr-ninja/-/issues
- **Community**: GitLab community forum

---

*Last updated: March 2026*
