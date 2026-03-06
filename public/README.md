# Mr Ninja Website

This directory contains the static website for the Mr Ninja project, deployed via GitLab Pages.

## Structure

```
public/
├── index.html           # Landing page
├── docs.html            # Documentation page
├── styles.css           # Main stylesheet
├── docs-styles.css      # Documentation-specific styles
├── script.js            # Main JavaScript
├── docs-script.js       # Documentation JavaScript
├── 404.html             # Custom 404 error page
├── robots.txt           # SEO robots file
└── README.md            # This file
```

## Features

- **Modern Landing Page**: Hero section, feature showcase, demo examples, and quick start guide
- **Comprehensive Documentation**: Full API reference, usage guides, and code examples
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Interactive Elements**: Tab navigation, code copy buttons, smooth scrolling
- **SEO Optimized**: Proper meta tags, semantic HTML, and accessibility features

## Local Development

To view the website locally:

1. Install a simple HTTP server (optional, but recommended for testing):
   ```bash
   npm install -g http-server
   ```

2. Serve the public directory:
   ```bash
   cd public
   http-server -p 8080
   ```

3. Open http://localhost:8080 in your browser

Alternatively, you can open `index.html` directly in your browser for basic testing.

## Deployment

The website is automatically deployed to GitLab Pages when changes are pushed to the `main` branch.

The deployment is handled by the `.gitlab-ci.yml` pipeline in the `pages` job.

## Customization

### Updating Content

- **Landing page**: Edit [index.html](index.html)
- **Documentation**: Edit [docs.html](docs.html)
- **Styles**: Edit [styles.css](styles.css) and [docs-styles.css](docs-styles.css)
- **Behavior**: Edit [script.js](script.js) and [docs-script.js](docs-script.js)

### Updating GitLab Links

The website currently uses placeholder links `your-group/mr-ninja`. Update these in:
- `index.html` (navigation and CTA links)
- `docs.html` (navigation and example links)

### Color Theme

The color scheme is defined in CSS custom properties (`:root` in `styles.css`):
- `--primary`: Primary brand color (default: #4F46E5)
- `--secondary`: Secondary color (default: #10B981)
- `--dark`: Dark backgrounds and text
- etc.

## Browser Support

- **Modern browsers**: Chrome, Firefox, Safari, Edge (latest versions)
- **Mobile browsers**: iOS Safari, Chrome Mobile, Samsung Internet
- **Fallback**: Basic functionality works without JavaScript

## Performance

- No external dependencies except Google Fonts
- All CSS and JS inlined or locally hosted
- Optimized images (if added, use WebP with PNG fallback)
- Lazy loading for future media additions

## Accessibility

- Semantic HTML5 structure
- ARIA labels where appropriate
- Keyboard navigation support
- Color contrast compliance (WCAG AA)
- Responsive text sizing

## License

MIT License - See [LICENSE](../LICENSE) in the project root
