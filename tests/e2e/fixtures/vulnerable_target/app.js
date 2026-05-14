// INTENTIONALLY VULNERABLE — VulBox E2E fixture only. Do not deploy.
//
// This server exposes deliberately exploitable endpoints so Atomic Red Team
// tests can verify the pipeline detects real exploitation, not just static
// CVE counts.

const express = require('express');
const _ = require('lodash');

const app = express();
app.use(express.json());

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// CWE-95: eval() of attacker-controlled input. Used by ART T1059 tests.
app.get('/exec', (req, res) => {
  const cmd = req.query.cmd || '';
  try {
    // eslint-disable-next-line no-eval
    const out = eval(cmd);
    res.json({ result: String(out) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// CVE-2020-8203: lodash prototype pollution via _.set on user-controlled path.
app.post('/merge', (req, res) => {
  const target = {};
  _.merge(target, req.body || {});
  res.json({ target });
});

const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
  console.log(`vulnerable-target listening on ${port}`);
});
