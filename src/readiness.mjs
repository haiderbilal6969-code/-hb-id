// Probe the database now, rather than returning the result of process startup.
// Never return database errors or connection details to the caller.
export async function checkReadiness({configured, query}) {
  if (!configured) return false;
  try {
    const result = await query({
      text: 'SELECT EXISTS (SELECT 1 FROM users WHERE is_admin=true) AS ready',
      query_timeout: 3000,
    });
    return result.rows[0]?.ready === true;
  } catch {
    return false;
  }
}
