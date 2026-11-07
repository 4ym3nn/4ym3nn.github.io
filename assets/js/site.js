document.documentElement.classList.add('js');

const menuButton = document.querySelector('.menu-toggle');
const menu = document.querySelector('#site-menu');
const compact = window.matchMedia('(max-width: 1023px)');
function closeMenu() {
  menu.classList.remove('is-open');
  menuButton.setAttribute('aria-expanded', 'false');
}
function syncMenu() {
  menuButton.hidden = !compact.matches;
  closeMenu();
}
menuButton.addEventListener('click', () => {
  const open = menuButton.getAttribute('aria-expanded') !== 'true';
  menuButton.setAttribute('aria-expanded', String(open));
  menu.classList.toggle('is-open', open);
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && menu.classList.contains('is-open')) {
    closeMenu();
    menuButton.focus();
  }
});
compact.addEventListener('change', syncMenu);
syncMenu();

const themeButton = document.querySelector('.theme-toggle');
function updateThemeButton() {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  themeButton.querySelector('.theme-label').textContent = `${next === 'light' ? 'Light' : 'Dark'} theme`;
  themeButton.setAttribute('aria-label', `Switch to ${next} theme`);
}
themeButton.addEventListener('click', () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem('theme', next); } catch {}
  updateThemeButton();
});
updateThemeButton();

// Keep table overflow inside the table, and make the scroll region keyboard accessible.
document.querySelectorAll('.article-body table').forEach((table, index) => {
  const wrapper = document.createElement('div');
  wrapper.className = 'table-scroll';
  wrapper.tabIndex = 0;
  wrapper.setAttribute('role', 'region');
  wrapper.setAttribute('aria-label', `Table ${index + 1}, scroll horizontally to see all columns`);
  table.before(wrapper);
  wrapper.append(table);
});

document.querySelectorAll('.article-body pre').forEach(pre => {
  const wrapper = document.createElement('div');
  wrapper.className = 'code-wrap';
  pre.before(wrapper);
  wrapper.append(pre);
  pre.tabIndex = 0;
  const copy = document.createElement('button');
  copy.type = 'button';
  copy.className = 'copy-code';
  copy.textContent = 'Copy';
  copy.setAttribute('aria-label', 'Copy code');
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(pre.textContent);
      copy.textContent = 'Copied!';
    } catch { copy.textContent = 'Could not copy'; }
    setTimeout(() => { copy.textContent = 'Copy'; }, 2000);
  });
  wrapper.append(copy);
});

const toc = document.querySelector('.toc-disclosure');
if (toc) {
  const wide = window.matchMedia('(min-width: 1440px)');
  const syncToc = () => { toc.open = wide.matches; };
  wide.addEventListener('change', syncToc);
  syncToc();
  const links = [...toc.querySelectorAll('a')];
  const headings = links.map(link => document.getElementById(decodeURIComponent(link.hash.slice(1)))).filter(Boolean);
  const observer = new IntersectionObserver(entries => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      links.forEach(link => {
        if (decodeURIComponent(link.hash.slice(1)) === entry.target.id) link.setAttribute('aria-current', 'location');
        else link.removeAttribute('aria-current');
      });
    }
  }, { rootMargin: '-10% 0px -65% 0px' });
  headings.forEach(heading => observer.observe(heading));
}

const search = document.querySelector('[data-search]');
if (search) {
  const form = search.querySelector('form');
  const query = search.querySelector('#search-query');
  const section = search.querySelector('#search-section');
  const status = search.querySelector('.search-status');
  const results = search.querySelector('.search-results');
  const params = new URLSearchParams(location.search);
  query.value = params.get('q') || '';
  section.value = params.get('section') || '';
  let posts = null;
  const labels = { ctfs: 'CTF writeup', research: 'Research', reviews: 'Reviews & notes' };
  const node = (tag, className, text) => {
    const el = document.createElement(tag);
    el.className = className;
    el.textContent = text;
    return el;
  };
  function render() {
    if (!posts) return;
    const terms = query.value.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
    const matches = posts.filter(post => (!section.value || post.section === section.value) && terms.every(term => post.searchText.includes(term)));
    matches.sort((a, b) => {
      const score = post => terms.reduce((sum, term) => sum + (post.title.toLocaleLowerCase().includes(term) ? 3 : 0) + (post.tags.join(' ').toLocaleLowerCase().includes(term) ? 2 : 0), 0);
      return score(b) - score(a);
    });
    results.replaceChildren();
    status.textContent = matches.length ? `${matches.length} ${matches.length === 1 ? 'article' : 'articles'}${terms.length ? ` matching “${query.value.trim()}”` : ' to explore'}` : 'No articles found. Try a different term or choose all categories.';
    for (const post of matches) {
      const card = node('article', 'post-card', '');
      const meta = node('div', 'card-meta', '');
      const category = node('a', 'section-label', labels[post.section] || post.section);
      category.href = `/${post.section}/`;
      meta.append(category, node('span', '', `${post.readingTime} min read`));
      const heading = node('h2', '', '');
      const link = node('a', '', post.title);
      link.href = post.url;
      heading.append(link);
      const bottom = node('div', 'card-bottom', '');
      const read = node('a', 'read-link', 'Read article ↗');
      read.href = post.url;
      read.setAttribute('aria-label', `Read ${post.title}`);
      bottom.append(node('span', '', post.date), read);
      card.append(meta, heading, node('p', 'card-excerpt', post.summary), bottom);
      results.append(card);
    }
  }
  function updateUrl() {
    const params = new URLSearchParams();
    if (query.value.trim()) params.set('q', query.value.trim());
    if (section.value) params.set('section', section.value);
    history.replaceState(null, '', `${location.pathname}${params.size ? `?${params}` : ''}`);
  }
  form.addEventListener('submit', event => { event.preventDefault(); render(); updateUrl(); });
  let debounce;
  query.addEventListener('input', () => { clearTimeout(debounce); debounce = setTimeout(() => { render(); updateUrl(); }, 150); });
  section.addEventListener('change', () => { render(); updateUrl(); });
  window.addEventListener('popstate', () => {
    const params = new URLSearchParams(location.search);
    query.value = params.get('q') || '';
    section.value = params.get('section') || '';
    render();
  });
  fetch(search.dataset.index).then(response => {
    if (!response.ok) throw new Error('Index unavailable');
    return response.json();
  }).then(data => {
    posts = data.map(post => ({ ...post, searchText: `${post.title} ${post.summary} ${post.tags.join(' ')} ${post.content}`.toLocaleLowerCase() }));
    render();
  }).catch(() => { status.textContent = 'Search could not load. Please reload, or use the category links in the menu to browse articles.'; });
}
