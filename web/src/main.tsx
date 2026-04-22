import React from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './styles/tokens.css';
import './styles.css';

const THEME_STORAGE_KEY = 'identrail-theme';

function applyInitialTheme() {
  if (typeof window === 'undefined') {
    return;
  }

  const stored = (() => {
    try {
      return window.localStorage.getItem(THEME_STORAGE_KEY);
    } catch {
      return null;
    }
  })();
  const preferredBySystem =
    typeof window.matchMedia === 'function' && window.matchMedia('(prefers-color-scheme: light)').matches
      ? 'light'
      : 'dark';
  const preferred = stored === 'dark' || stored === 'light' ? stored : preferredBySystem;

  document.documentElement.dataset.theme = preferred;
}

applyInitialTheme();

createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
