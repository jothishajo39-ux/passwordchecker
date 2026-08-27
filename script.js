const pwdInput = document.getElementById('pwd');
const toggleBtn = document.getElementById('toggleVisibility');
const strengthBar = document.getElementById('strengthBar');
const strengthLabel = document.getElementById('strengthLabel');
const ruleItems = document.querySelectorAll('.rules li');
const checkBreachBtn = document.getElementById('checkBreach');
const breachResult = document.getElementById('breachResult');

// ---- Show / hide password ----
toggleBtn.addEventListener('click', () => {
  const isPassword = pwdInput.type === 'password';
  pwdInput.type = isPassword ? 'text' : 'password';
  toggleBtn.textContent = isPassword ? '🙈' : '👁';
});

// ---- Rule checks ----
function evaluateRules(password) {
  return {
    length: password.length >= 8,
    upper: /[A-Z]/.test(password),
    lower: /[a-z]/.test(password),
    number: /[0-9]/.test(password),
    special: /[^A-Za-z0-9]/.test(password)
  };
}

function updateStrengthUI(password) {
  const rules = evaluateRules(password);
  let passedCount = 0;

  ruleItems.forEach(li => {
    const ruleKey = li.dataset.rule;
    const passed = rules[ruleKey];
    li.classList.toggle('passed', passed);
    if (passed) passedCount++;
  });

  const percent = password.length === 0 ? 0 : (passedCount / 5) * 100;
  strengthBar.style.width = percent + '%';

  let label = 'Very Weak';
  let color = 'var(--danger)';

  if (password.length === 0) {
    label = '—';
  } else if (passedCount <= 2) {
    label = 'Weak';
    color = 'var(--danger)';
  } else if (passedCount === 3 || passedCount === 4) {
    label = 'Moderate';
    color = 'var(--warn)';
  } else if (passedCount === 5) {
    label = 'Strong';
    color = 'var(--ok)';
  }

  strengthBar.style.background = color;
  strengthLabel.textContent = `Strength: ${label}`;

  checkBreachBtn.disabled = password.length === 0;
  breachResult.classList.add('hidden');
}

pwdInput.addEventListener('input', (e) => {
  updateStrengthUI(e.target.value);
});

// ---- SHA-1 hashing (Web Crypto API, runs locally in the browser) ----
async function sha1(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// ---- Have I Been Pwned check using k-anonymity ----
// Only the first 5 characters of the SHA-1 hash are sent to the API.
// The full hash (and full password) never leave the browser.
async function checkBreach(password) {
  breachResult.classList.remove('hidden', 'safe', 'danger');
  breachResult.textContent = 'Checking…';

  try {
    const hash = await sha1(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    if (!response.ok) throw new Error('API request failed');

    const text = await response.text();
    const lines = text.split('\n');

    let matchCount = 0;
    for (const line of lines) {
      const [hashSuffix, count] = line.trim().split(':');
      if (hashSuffix === suffix) {
        matchCount = parseInt(count, 10);
        break;
      }
    }

    if (matchCount > 0) {
      breachResult.classList.add('danger');
      breachResult.textContent =
        `⚠ This password has appeared in ${matchCount.toLocaleString()} known data breaches. Avoid using it.`;
    } else {
      breachResult.classList.add('safe');
      breachResult.textContent = '✔ Good news — this password was not found in any known breach.';
    }
  } catch (err) {
    breachResult.classList.add('danger');
    breachResult.textContent = 'Could not reach the breach-check API. Check your internet connection and try again.';
  }
}

checkBreachBtn.addEventListener('click', () => {
  const password = pwdInput.value;
  if (password) checkBreach(password);
});
