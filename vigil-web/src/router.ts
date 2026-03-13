type RouteHandler = (params: Record<string, string>) => Promise<void> | void;

const routes: Array<{ pattern: RegExp; handler: RouteHandler; paramNames: string[] }> = [];

export function route(path: string, handler: RouteHandler) {
  const paramNames: string[] = [];
  const pattern = path.replace(/:(\w+)/g, (_, name) => {
    paramNames.push(name);
    return '([^/]+)';
  });
  routes.push({ pattern: new RegExp(`^${pattern}$`), handler, paramNames });
}

export function navigate(path: string) {
  window.location.hash = `#${path}`;
}

export async function resolve() {
  const hash = window.location.hash.slice(1) || '/login';

  for (const r of routes) {
    const match = hash.match(r.pattern);
    if (match) {
      const params: Record<string, string> = {};
      r.paramNames.forEach((name, i) => {
        params[name] = match[i + 1];
      });
      await r.handler(params);
      return;
    }
  }

  const app = document.getElementById('app')!;
  app.innerHTML = '<div class="loading-page">Page not found</div>';
}

export function start() {
  window.addEventListener('hashchange', () => resolve());
  resolve();
}
