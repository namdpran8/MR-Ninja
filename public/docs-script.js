// Documentation page JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Update active nav link based on scroll position
    const navLinks = document.querySelectorAll('.docs-nav .nav-link');
    const sections = document.querySelectorAll('.docs-content section[id]');

    function updateActiveLink() {
        let currentSection = '';
        const scrollPosition = window.scrollY + 150;

        sections.forEach(section => {
            const sectionTop = section.offsetTop;
            const sectionHeight = section.offsetHeight;
            
            if (scrollPosition >= sectionTop && scrollPosition < sectionTop + sectionHeight) {
                currentSection = section.getAttribute('id');
            }
        });

        navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === `#${currentSection}`) {
                link.classList.add('active');
            }
        });
    }

    // Throttle scroll events
    let scrollTimeout;
    window.addEventListener('scroll', function() {
        if (scrollTimeout) {
            window.cancelAnimationFrame(scrollTimeout);
        }
        scrollTimeout = window.requestAnimationFrame(function() {
            updateActiveLink();
        });
    });

    // Initial check
    updateActiveLink();

    // Smooth scroll for nav links
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href').substring(1);
            const targetSection = document.getElementById(targetId);
            
            if (targetSection) {
                const offsetTop = targetSection.offsetTop - 100;
                window.scrollTo({
                    top: offsetTop,
                    behavior: 'smooth'
                });
            }
        });
    });

    // Add copy buttons to code blocks (if not already added by main script)
    if (!document.querySelector('.copy-btn')) {
        const codeBlocks = document.querySelectorAll('.docs-content pre code');
        
        codeBlocks.forEach((block, index) => {
            const pre = block.parentElement;
            const button = document.createElement('button');
            button.className = 'copy-btn';
            button.textContent = 'Copy';
            button.style.cssText = `
                position: absolute;
                top: 0.5rem;
                right: 0.5rem;
                padding: 0.25rem 0.75rem;
                background: rgba(255, 255, 255, 0.1);
                color: white;
                border: 1px solid rgba(255, 255, 255, 0.3);
                border-radius: 0.25rem;
                cursor: pointer;
                font-size: 0.75rem;
                font-weight: 600;
                transition: all 0.2s;
                z-index: 10;
            `;

            pre.style.position = 'relative';
            pre.appendChild(button);

            button.addEventListener('click', async function() {
                const code = block.textContent;
                try {
                    await navigator.clipboard.writeText(code);
                    button.textContent = 'Copied!';
                    button.style.background = 'rgba(16, 185, 129, 0.3)';
                    button.style.borderColor = 'rgba(16, 185, 129, 0.5)';
                    
                    setTimeout(() => {
                        button.textContent = 'Copy';
                        button.style.background = 'rgba(255, 255, 255, 0.1)';
                        button.style.borderColor = 'rgba(255, 255, 255, 0.3)';
                    }, 2000);
                } catch (err) {
                    console.error('Failed to copy:', err);
                    button.textContent = 'Failed';
                    setTimeout(() => {
                        button.textContent = 'Copy';
                    }, 2000);
                }
            });

            button.addEventListener('mouseenter', function() {
                if (this.textContent === 'Copy') {
                    this.style.background = 'rgba(255, 255, 255, 0.2)';
                }
            });

            button.addEventListener('mouseleave', function() {
                if (this.textContent === 'Copy') {
                    this.style.background = 'rgba(255, 255, 255, 0.1)';
                }
            });
        });
    }

    // Add anchor links to headings
    const headings = document.querySelectorAll('.docs-content h2, .docs-content h3');
    headings.forEach(heading => {
        if (!heading.id) {
            // Generate ID from heading text
            const id = heading.textContent
                .toLowerCase()
                .replace(/[^\w\s-]/g, '')
                .replace(/\s+/g, '-');
            heading.id = id;
        }

        const anchor = document.createElement('a');
        anchor.href = `#${heading.id}`;
        anchor.className = 'heading-anchor';
        anchor.innerHTML = '#';
        anchor.style.cssText = `
            margin-left: 0.5rem;
            color: var(--gray-light);
            text-decoration: none;
            opacity: 0;
            transition: opacity 0.2s;
            font-weight: normal;
        `;

        heading.style.position = 'relative';
        heading.appendChild(anchor);

        heading.addEventListener('mouseenter', function() {
            anchor.style.opacity = '1';
        });

        heading.addEventListener('mouseleave', function() {
            anchor.style.opacity = '0';
        });

        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            window.location.hash = this.getAttribute('href');
            heading.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
    });

    // Expand details if URL has hash pointing to content inside
    if (window.location.hash) {
        const hash = window.location.hash.substring(1);
        const target = document.getElementById(hash);
        if (target) {
            const details = target.closest('details');
            if (details) {
                details.open = true;
            }
        }
    }
});
