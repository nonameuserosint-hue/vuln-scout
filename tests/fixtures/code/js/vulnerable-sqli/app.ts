export async function loadUser(email: string, db: { query(sql: string): Promise<unknown> }) {
  const sql = `SELECT * FROM users WHERE email = '${email}'`;
  return db.query(sql);
}
