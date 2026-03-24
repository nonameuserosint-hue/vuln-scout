export function renderUser(name: string) {
  const safe = name.replace(/[<>&"]/g, "_");
  return `<div>${safe}</div>`;
}
