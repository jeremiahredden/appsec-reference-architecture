/**
 * SQL Injection — vulnerable and secure variants, side by side.
 *
 * Scenario: an authenticated "search my orders" endpoint in a Node.js
 * service using `mysql2`. The endpoint filters the current user's
 * orders by an optional `customer_name` query parameter.
 *
 * The vulnerable version uses a template literal to build the SQL —
 * the pattern that continues to ship to production because "just this
 * one value" feels safer than it is. The secure version uses
 * placeholder-based parameterization, which is what mysql2's
 * `execute()` provides.
 *
 * Run against a throwaway database; the demo at the bottom shows the
 * vulnerable handler leaking every row while the secure handler
 * returns zero rows for the same attacker payload.
 */

const mysql = require("mysql2/promise");

// ---------------------------------------------------------------------------
// VULNERABLE: template-literal interpolation into a raw query.
// ---------------------------------------------------------------------------
async function searchOrdersVulnerable(conn, userId, customerName) {
  // Exploit payloads (sent as the `customer_name` query parameter):
  //
  //   "' OR '1'='1"
  //      → WHERE user_id = 42 AND customer_name = '' OR '1'='1'
  //      → returns every row for every user — tenant isolation broken.
  //
  //   "' UNION SELECT id, email, password_hash FROM users --"
  //      → returns the users table through the orders endpoint.
  //
  //   "'; DROP TABLE orders; --"
  //      → if multi-statement is enabled on the connection, destructive.
  //
  // Bonus: even without single-quote injection, a numeric field
  // would be exploitable the same way with no quotes at all.
  const sql = `
    SELECT id, customer_name, total_cents, created_at
      FROM orders
     WHERE user_id = ${userId}
       AND customer_name = '${customerName}'
  `;
  const [rows] = await conn.query(sql);
  return rows;
}

// ---------------------------------------------------------------------------
// SECURE: parameterized query via execute() + placeholders.
// ---------------------------------------------------------------------------
async function searchOrdersSecure(conn, userId, customerName) {
  // `execute()` uses prepared statements; `?` placeholders are bound
  // as literal values by the driver. The attacker's SQL metacharacters
  // are treated as bytes inside a string, never as SQL syntax.
  //
  // Also: `user_id` is NOT taken from the query string or body. It is
  // taken from the authenticated session. User-supplied IDs in
  // authorization-bearing fields is the other half of this bug class.
  const [rows] = await conn.execute(
    `SELECT id, customer_name, total_cents, created_at
       FROM orders
      WHERE user_id = ?
        AND customer_name = ?`,
    [userId, customerName]
  );
  return rows;
}

// ---------------------------------------------------------------------------
// PREFERRED: use a query builder / ORM that parameterizes by default.
// ---------------------------------------------------------------------------
// Knex:
//   return knex("orders")
//     .where({ user_id: userId, customer_name: customerName })
//     .select("id", "customer_name", "total_cents", "created_at");
//
// Prisma:
//   return prisma.order.findMany({
//     where: { userId, customerName },
//   });
//
// These builders make the parameterization a property of the type
// system. A reviewer sees `.where({ ... })` and can move on; seeing
// `.raw(...)` is the signal to stop and examine the bindings.

// ---------------------------------------------------------------------------
// Demo harness — runs against a disposable MySQL instance. Adjust the
// connection params or delete the block if you do not want to wire it
// up. The point of the demo is to make the failure mode visible.
// ---------------------------------------------------------------------------
async function demo() {
  const conn = await mysql.createConnection({
    host: "127.0.0.1",
    user: "root",
    password: process.env.MYSQL_PWD || "",
    multipleStatements: false,
  });
  await conn.query("CREATE DATABASE IF NOT EXISTS sqli_demo");
  await conn.query("USE sqli_demo");
  await conn.query("DROP TABLE IF EXISTS orders");
  await conn.query(`
    CREATE TABLE orders (
      id INT PRIMARY KEY AUTO_INCREMENT,
      user_id INT NOT NULL,
      customer_name VARCHAR(255) NOT NULL,
      total_cents INT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await conn.query(
    "INSERT INTO orders (user_id, customer_name, total_cents) VALUES (1,'Alice',5000),(1,'Bob',2500),(2,'Eve',9999)"
  );

  const payload = "' OR '1'='1";

  console.log("VULNERABLE:", await searchOrdersVulnerable(conn, 1, payload));
  // → returns all three rows, including user 2's order.

  console.log("SECURE:    ", await searchOrdersSecure(conn, 1, payload));
  // → returns []

  await conn.end();
}

if (require.main === module) {
  demo().catch((err) => { console.error(err); process.exit(1); });
}

module.exports = { searchOrdersVulnerable, searchOrdersSecure };
