// Mr Ninja Website JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Demo tabs functionality
    const tabs = document.querySelectorAll('.tab');
    const demoPanes = document.querySelectorAll('.demo-pane');

    tabs.forEach(tab => {
        tab.addEventListener('click', function() {
            const targetTab = this.dataset.tab;

            // Remove active class from all tabs and panes
            tabs.forEach(t => t.classList.remove('active'));
            demoPanes.forEach(pane => pane.classList.remove('active'));

            // Add active class to clicked tab and corresponding pane
            this.classList.add('active');
            document.getElementById(`${targetTab}-pane`).classList.add('active');
        });
    });

    // Smooth scroll for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            const href = this.getAttribute('href');
            if (href !== '#' && href !== '') {
                e.preventDefault();
                const target = document.querySelector(href);
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            }
        });
    });

    // Navbar scroll effect
    let lastScroll = 0;
    const navbar = document.querySelector('.navbar');

    window.addEventListener('scroll', function() {
        const currentScroll = window.pageYOffset;

        if (currentScroll > 100) {
            navbar.style.boxShadow = '0 4px 6px -1px rgba(0, 0, 0, 0.1)';
        } else {
            navbar.style.boxShadow = 'none';
        }

        lastScroll = currentScroll;
    });

    // Copy code button functionality
    const codeBlocks = document.querySelectorAll('pre code');
    
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
        `;

        pre.style.position = 'relative';
        pre.appendChild(button);

        button.addEventListener('click', async function() {
            const code = block.textContent;
            try {
                await navigator.clipboard.writeText(code);
                button.textContent = 'Copied!';
                button.style.background = 'rgba(16, 185, 129, 0.2)';
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

    // Animate elements on scroll
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);

    // Observe feature cards, problem cards, and pipeline steps
    const animatedElements = document.querySelectorAll('.feature-card, .problem-card, .pipeline-step');
    animatedElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(el);
    });

    // Stats counter animation
    const stats = document.querySelectorAll('.stat-value');
    const statsObserver = new IntersectionObserver(function(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting && !entry.target.classList.contains('counted')) {
                entry.target.classList.add('counted');
                animateValue(entry.target);
            }
        });
    }, { threshold: 0.5 });

    stats.forEach(stat => statsObserver.observe(stat));

    function animateValue(element) {
        const text = element.textContent;
        const hasK = text.includes('k');
        const hasPlus = text.includes('+');
        const value = parseInt(text.replace(/\D/g, ''));
        
        if (isNaN(value)) return;

        const duration = 1000;
        const steps = 30;
        const increment = value / steps;
        let current = 0;
        const timer = setInterval(() => {
            current += increment;
            if (current >= value) {
                current = value;
                clearInterval(timer);
            }
            let displayValue = Math.floor(current).toString();
            if (hasK) displayValue += 'k';
            if (hasPlus) displayValue += '+';
            element.textContent = displayValue;
        }, duration / steps);
    }
});
