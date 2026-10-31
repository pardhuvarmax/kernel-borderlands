# src

The dashboard's React + TypeScript source (Vite): `main.tsx` (entry), `App.tsx` (the application: panels, Isolate / Restore / Kill actions), `App.css` and `index.css` (styles), `assets/`. It talks to `kbd`'s HTTP API on `:8080` (CORS origins via `KB_HTTP_CORS_ORIGIN`); mutating routes need `KB_HTTP_API_TOKEN`. Build and dev commands: [`../README.md`](../README.md).
