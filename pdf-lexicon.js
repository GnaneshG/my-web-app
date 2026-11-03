(() => {
  const PDF_WORKER_URL = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
  const MAX_FILE_BYTES = 25 * 1024 * 1024;
  const MAX_EXCERPT_CHARS = 24000;
  const MAX_PAGES = 5;
  const sources = new WeakMap();

  function isAdminSurface() {
    return window.lexiconAdminMode === true
      || new URLSearchParams(window.location.search).get('embed') === 'admin';
  }

  function setStatus(section, message) {
    const status = section?.querySelector('#pdf-source-status');
    if (status) status.textContent = message;
  }

  document.addEventListener('change', async event => {
    const upload = event.target.closest?.('#pdf-upload');
    if (!upload) return;
    const section = upload.closest('[data-admin-materials]');
    const termInput = section?.querySelector('#pdf-term');
    const excerptInput = section?.querySelector('#pdf-excerpt');
    const saveButton = section?.querySelector('#save-pdf-term-btn');
    if (!section || !termInput || !excerptInput || !saveButton || !isAdminSurface()) return;

    sources.delete(upload);
    excerptInput.value = '';
    excerptInput.readOnly = true;
    saveButton.disabled = true;
    const file = upload.files?.[0];
    if (!file) {
      setStatus(section, 'No PDF selected. Files remain in this browser during extraction.');
      return;
    }
    if (file.type !== 'application/pdf' && !file.name.toLowerCase().endsWith('.pdf')) {
      setStatus(section, 'Choose a PDF file.');
      return;
    }
    if (file.size > MAX_FILE_BYTES) {
      setStatus(section, 'This PDF is larger than 25 MB. Choose a smaller file.');
      return;
    }
    if (!window.pdfjsLib) {
      setStatus(section, 'The PDF reader did not load. Check the PDF.js CDN connection and try again.');
      return;
    }

    setStatus(section, 'Extracting text locally…');
    try {
      window.pdfjsLib.GlobalWorkerOptions.workerSrc = PDF_WORKER_URL;
      const task = window.pdfjsLib.getDocument({ data: await file.arrayBuffer() });
      const pdf = await task.promise;
      const pagesToRead = Math.min(pdf.numPages, MAX_PAGES);
      const pageTexts = [];
      for (let pageNumber = 1; pageNumber <= pagesToRead; pageNumber++) {
        const page = await pdf.getPage(pageNumber);
        const content = await page.getTextContent();
        pageTexts.push(`Page ${pageNumber}: ${content.items.map(item => item.str || '').join(' ')}`);
      }
      const excerpt = pageTexts.join('\n\n').trim().slice(0, MAX_EXCERPT_CHARS);
      if (!excerpt) {
        setStatus(section, 'No selectable text was found. This may be a scanned PDF; OCR is not included.');
        return;
      }
      sources.set(upload, { filename: file.name, pages: pagesToRead, totalPages: pdf.numPages });
      excerptInput.value = excerpt;
      saveButton.disabled = false;
      setStatus(section, `Extracted pages 1–${pagesToRead} of ${pdf.numPages}. Review the excerpt and add a term.`);
    } catch (error) {
      console.error('PDF text extraction failed:', error);
      setStatus(section, 'Could not read this PDF. It may be damaged, encrypted, or image-only.');
    }
  });

  document.addEventListener('click', event => {
    const saveButton = event.target.closest?.('#save-pdf-term-btn');
    if (!saveButton) return;
    const section = saveButton.closest('[data-admin-materials]');
    if (!section || !isAdminSurface()) return;

    const upload = section.querySelector('#pdf-upload');
    const termInput = section.querySelector('#pdf-term');
    const excerptInput = section.querySelector('#pdf-excerpt');
    const categoryInput = section.querySelector('#pdf-category');
    const source = upload && sources.get(upload);
    const term = termInput?.value.trim();
    const excerpt = excerptInput?.value.trim();
    if (!source || !excerpt) {
      setStatus(section, 'Upload a text-based PDF and check that an excerpt is available.');
      return;
    }
    if (!term) {
      setStatus(section, 'Enter the term you want to index from this PDF.');
      termInput?.focus();
      return;
    }
    if (!Array.isArray(window.db) || typeof window.saveAll !== 'function' || typeof window.render !== 'function') {
      setStatus(section, 'The Lexicon is still loading. Try again in a moment.');
      return;
    }

    const citation = `${source.filename} — pages 1–${source.pages}${source.totalPages > source.pages ? ` (of ${source.totalPages})` : ''}`;
    const existing = window.db.find(item => String(item.words || '').toLocaleLowerCase() === term.toLocaleLowerCase());
    const entry = {
      id: existing?.id || `pdf-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      words: term,
      pos: existing?.pos || '',
      tamil: existing?.tamil || '—',
      tamilVerified: existing?.tamilVerified ?? false,
      tamilSource: existing?.tamilSource || '',
      definitionSource: `User-provided PDF: ${citation}`,
      nuance: existing?.nuance || '',
      eng: excerpt,
      syn: existing?.syn || '—',
      cat: categoryInput.value,
      starred: Boolean(existing?.starred),
      ex1: `Verbatim source excerpt from ${citation}`,
      ex2: existing?.ex2 || '',
      ex3: existing?.ex3 || ''
    };

    if (existing) Object.assign(existing, entry);
    else window.db.push(entry);
    window.saveAll();
    window.render();
    setStatus(section, `Saved “${term}” with its PDF citation. Tamil meaning remains unverified until reviewed.`);
    termInput.value = '';
  });
})();
