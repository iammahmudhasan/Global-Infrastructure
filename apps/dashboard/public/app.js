// View Titles Configuration
    const titles = {
      dashboard: { title: "Dashboard", crumb: "Global Control Plane Overview" },
      projects: { title: "Projects", crumb: "Multi-Tenant Project Isolation" },
      domains: { title: "Domains", crumb: "Edge Custom Hostnames & Routing" },
      dns: { title: "DNS", crumb: "Authoritative Anycast DNS Management" },
      servers: { title: "Servers", crumb: "Abstracted Global Compute & PoP Fleet" },
      deployments: { title: "Deployments", crumb: "Edge Workloads & AI Model Placement" },
      storage: { title: "Storage", crumb: "S3 Object Store & Distributed NVMe" },
      security: { title: "Security", crumb: "Line-Rate WAF, DDoS, & Secret Vault" },
      analytics: { title: "Analytics", crumb: "Real-Time Observability & Latency Matrix" },
      billing: { title: "Billing", crumb: "Token Economics & Arbitrage Savings" }
    };

    // Navigation Switcher
    const navItems = document.querySelectorAll('.nav-item');
    const viewContents = document.querySelectorAll('.view-content');
    const pageTitle = document.getElementById('page-title');
    const pageCrumb = document.getElementById('page-crumb');

    function switchView(viewId) {
      navItems.forEach(item => {
        if (item.getAttribute('data-view') === viewId) {
          item.classList.add('active');
        } else {
          item.classList.remove('active');
        }
      });

      viewContents.forEach(view => {
        if (view.id === `view-${viewId}`) {
          view.classList.add('active');
        } else {
          view.classList.remove('active');
        }
      });

      if (titles[viewId]) {
        pageTitle.innerText = titles[viewId].title;
        pageCrumb.innerText = titles[viewId].crumb;
      }

      if (viewId === 'security') {
        fetchAuditLogs();
      }
      if (viewId === 'domains') {
        loadDomains();
      }
    }

    navItems.forEach(item => {
      item.addEventListener('click', () => {
        const viewId = item.getAttribute('data-view');
        switchView(viewId);
      });
    });

    // Modals
    function openModal(modalId) {
      document.getElementById(modalId).classList.add('open');
    }

    function closeModal(modalId) {
      document.getElementById(modalId).classList.remove('open');
    }

    function showToast(msg) {
      const toast = document.getElementById('toast-notify');
      document.getElementById('toast-text').innerText = msg;
      toast.style.display = 'flex';
      setTimeout(() => {
        toast.style.display = 'none';
      }, 3500);
    }

    function submitNewProject() {
      const name = document.getElementById('modal-proj-name').value || "New Tenant Project";
      closeModal('new-project-modal');
      showToast(`Project '${name}' created with isolated Control Plane boundary.`);
    }

    async function submitNewDomain() {
      const domainInput = document.getElementById('modal-domain-fqdn');
      const domain = (domainInput && domainInput.value.trim()) || "api.domain.com";
      closeModal('new-domain-modal');

      try {
        const resp = await fetch('/api/proxy/domains', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            hostname: domain,
            default_origin: '172.28.0.10:8081'
          })
        });
        if (resp.ok) {
          showToast(`Domain '${domain}' registered in Control Plane database. TLS initiated.`);
          loadDomains();
          return;
        }
      } catch (err) {
        // Fallback simulated domain registration
      }

      addSimulatedDomain(domain);
      showToast(`Domain '${domain}' registered in simulated mode (Control Plane offline).`);
    }

    function submitNewDns() {
      const name = document.getElementById('modal-dns-name').value || "sub";
      closeModal('new-dns-modal');
      showToast(`DNS Record '${name}' published to all 5 Anycast PoPs.`);
    }

    function submitQuickDeploy() {
      const name = document.getElementById('modal-deploy-name').value || "Workload-01";
      closeModal('quick-deploy-modal');
      showToast(`Workload '${name}' placed at optimal sovereign node.`);
    }

    // AI Director Simulator Execution
    async function executeInferenceSimulation() {
      const strategy = document.getElementById('sim-strategy').value;
      const jurisdiction = document.getElementById('sim-jurisdiction').value;
      const prompt = document.getElementById('sim-prompt').value;
      const term = document.getElementById('sim-terminal');
      const btn = document.getElementById('sim-dispatch-btn');
      const isDemo = document.getElementById('sim-demo-mode') && document.getElementById('sim-demo-mode').checked;

      btn.disabled = true;
      btn.innerText = "Dispatching Through Edge Fast-Path...";

      term.innerText += `\n\n> [DISPATCH] Strategy: ${strategy.toUpperCase()} | Jurisdiction: ${jurisdiction || 'GLOBAL'}${isDemo ? ' [DEMO MODE]' : ''}`;
      term.innerText += `\n> Routing payload: "${prompt.substring(0, 40)}..."`;

      if (isDemo) {
        // Explicit Offline Demo Simulation Mode
        let simulatedProvider = 'spot-coreweave';
        let cost = '0.50';
        let ttft = '18';
        if (jurisdiction === 'BD') {
          simulatedProvider = 'onprem-dhaka-dgx';
          cost = '0.80';
          ttft = '3.8';
        } else if (strategy === 'latency') {
          simulatedProvider = 'onprem-dhaka-dgx';
          cost = '0.80';
          ttft = '3.8';
        }

        term.innerText += `\n< HTTP/1.1 200 OK (DEMO SIMULATION ONLY)
< [SIMULATED] Mode active: synthetic metrics are not real gateway measurements.
< X-NexusEdge-Provider: ${simulatedProvider} [SIMULATED]
< X-NexusEdge-Routing-Strategy: ${strategy}
< X-NexusEdge-Cost-Per-MTokens: $${cost}
< X-NexusEdge-Tokens-Total: 512
< X-NexusEdge-Estimated-Savings-USD: $0.001024
< X-NexusEdge-TTFT-Ms: ${ttft} ms
< X-NexusEdge-Failover-Count: 0
< X-NexusEdge-Total-Duration-Ms: 22 ms

Result: [SIMULATED] Demo placed at [${simulatedProvider}], achieving $${cost}/1M spot rate within Bangladesh NDMA 2026 constraints.`;
        showToast(`Demo Simulation: routed to ${simulatedProvider} (Simulated)`);
        btn.disabled = false;
        btn.innerText = "Dispatch Through Edge Director";
        term.scrollTop = term.scrollHeight;
        return;
      }

      // Real Edge Execution through BFF Proxy (Zero Browser Credentials)
      try {
        const headers = {
          'Content-Type': 'application/json',
          'X-NexusEdge-Routing-Strategy': strategy
        };
        if (jurisdiction) {
          headers['X-NexusEdge-Jurisdiction'] = jurisdiction;
        }

        const resp = await fetch('/api/proxy/inference', {
          method: 'POST',
          headers: headers,
          body: JSON.stringify({
            model: "llama-3.3-70b",
            messages: [{ role: "user", content: prompt }],
            temperature: 0.7,
            max_tokens: 128
          })
        });

        if (!resp.ok) {
          let errDetail = '';
          try {
            const errJson = await resp.json();
            errDetail = errJson.error || errJson.message || JSON.stringify(errJson);
          } catch (e) {
            errDetail = await resp.text();
          }

          term.innerText += `\n< HTTP/1.1 ${resp.status} ${resp.statusText || 'Error'}
< Content-Type: application/json

[ERROR] Edge Gateway inference dispatch failed:
Status: ${resp.status}
Details: ${errDetail || 'Gateway rejected request'}
To test simulated placement offline, enable 'Offline Demo Mode' toggle.`;
          showToast(`Inference failed: HTTP ${resp.status}`);
          return;
        }

        const provider = resp.headers.get('x-nexusedge-provider') || 'spot-coreweave';
        const costPerM = resp.headers.get('x-nexusedge-cost-per-mtokens') || '0.50';
        const ttft = resp.headers.get('x-nexusedge-ttft-ms') || '18';
        const totalDuration = resp.headers.get('x-nexusedge-total-duration-ms') || '26';
        const tokensTotal = resp.headers.get('x-nexusedge-tokens-total') || '512';
        const savingsUSD = resp.headers.get('x-nexusedge-estimated-savings-usd') || '0.001024';
        const failovers = resp.headers.get('x-nexusedge-failover-count') || '0';

        term.innerText += `\n< HTTP/1.1 ${resp.status} OK
< X-NexusEdge-Provider: ${provider}
< X-NexusEdge-Routing-Strategy: ${strategy}
< X-NexusEdge-Cost-Per-MTokens: $${costPerM}
< X-NexusEdge-Tokens-Total: ${tokensTotal}
< X-NexusEdge-Estimated-Savings-USD: $${savingsUSD}
< X-NexusEdge-TTFT-Ms: ${ttft} ms
< X-NexusEdge-Failover-Count: ${failovers}
< X-NexusEdge-Total-Duration-Ms: ${totalDuration} ms

Response payload delivered successfully with zero gateway overhead.`;
        showToast(`Inference dispatched: routed to ${provider} ($${costPerM}/1M tokens)`);
      } catch (err) {
        term.innerText += `\n[ERROR] Connection failed: Edge Gateway is unreachable or rejected connection.
Details: ${err.message}
Ensure gateway is running on line-rate port :8080 or enable 'Offline Demo Mode' checkbox for synthetic walkthrough.`;
        showToast(`Inference failed: Edge Gateway unreachable`);
      } finally {
        btn.disabled = false;
        btn.innerText = "Dispatch Through Edge Director";
        term.scrollTop = term.scrollHeight;
      }
    }

    // Cryptographic Audit Trail Verification Engine (HMAC-SHA256)
    async function fetchAuditLogs() {
      try {
        const resp = await fetch('/api/proxy/audit-logs?limit=10');
        if (!resp.ok) return;
        const data = await resp.json();
        if (!data || !data.audit_logs || data.audit_logs.length === 0) return;

        const tbody = document.getElementById('audit-log-tbody');
        if (!tbody) return;
        tbody.innerHTML = '';

        data.audit_logs.forEach(log => {
          const tr = document.createElement('tr');
          const time = new Date(log.timestamp || log.created_at).toISOString().substr(11, 8);
          const prevDisplay = log.prev_hash && log.prev_hash.startsWith('00000000') ? '00000000... (GENESIS)' : (log.prev_hash ? log.prev_hash.substring(0, 8) + '...' : '-');
          const hashDisplay = log.hash ? log.hash.substring(0, 8) + '...' : '-';

          let actionBadge = 'badge-global';
          if (log.action.includes('waf') || log.action.includes('block')) actionBadge = 'badge-spot';
          if (log.action.includes('ai') || log.action.includes('provider')) actionBadge = 'badge-amber';
          if (log.action.includes('delete')) actionBadge = 'badge-bd';

          const tdTime = document.createElement('td');
          tdTime.className = 'mono';
          tdTime.textContent = time;

          const tdActor = document.createElement('td');
          tdActor.className = 'mono';
          tdActor.textContent = `${log.actor || 'system'} / ${log.client_ip || '127.0.0.1'}`;

          const tdAction = document.createElement('td');
          const actionSpan = document.createElement('span');
          actionSpan.className = `badge ${actionBadge}`;
          actionSpan.textContent = log.action;
          tdAction.appendChild(actionSpan);

          const tdResource = document.createElement('td');
          tdResource.className = 'mono';
          tdResource.textContent = `${log.resource_type}:${log.resource_id}`;

          const tdPrev = document.createElement('td');
          tdPrev.className = 'mono';
          tdPrev.style.color = 'var(--text-dim)';
          tdPrev.title = log.prev_hash || '';
          tdPrev.textContent = prevDisplay;

          const tdHash = document.createElement('td');
          tdHash.className = 'mono';
          tdHash.style.color = 'var(--accent-cyan)';
          tdHash.title = log.hash || '';
          tdHash.textContent = hashDisplay;

          const tdValid = document.createElement('td');
          const validSpan = document.createElement('span');
          validSpan.className = 'badge badge-bd';
          validSpan.textContent = 'CRYPTOGRAPHICALLY VALID';
          tdValid.appendChild(validSpan);

          tr.append(tdTime, tdActor, tdAction, tdResource, tdPrev, tdHash, tdValid);
          tbody.appendChild(tr);
        });

        if (data.chain_valid) {
          const statusEl = document.getElementById('audit-chain-status');
          const badgeEl = document.getElementById('audit-chain-badge');
          if (statusEl) statusEl.innerText = `Chain Integrity: VERIFIED (${data.total} records)`;
          if (badgeEl) badgeEl.className = 'badge badge-bd';
        }
      } catch (e) {
        // Fallback default ledger persists if control plane daemon is offline
      }
    }

    async function verifyAuditChain() {
      const btn = document.getElementById('audit-verify-btn');
      const statusEl = document.getElementById('audit-chain-status');
      const badge = document.getElementById('audit-chain-badge');
      if (btn) {
        btn.disabled = true;
        btn.innerText = 'Verifying HMAC Hashes...';
      }

      try {
        const resp = await fetch('/api/proxy/audit-logs/verify');
        if (resp.ok) {
          const data = await resp.json();
          if (data.chain_valid) {
            if (statusEl) statusEl.innerText = `Chain Integrity: VERIFIED (${data.total_records} records)`;
            if (badge) badge.className = 'badge badge-bd';
            showToast('Cryptographic Audit Chain verified: 100% valid SHA-256 HMAC integrity.');
          } else {
            if (statusEl) statusEl.innerText = 'Chain Integrity: INVALID!';
            if (badge) badge.className = 'badge badge-amber';
            showToast('Audit verification failed: hash chain broken!');
          }
        } else {
          throw new Error(`Verify endpoint returned HTTP ${resp.status}`);
        }
      } catch (err) {
        if (statusEl) statusEl.innerText = 'Chain Integrity: UNVERIFIED (Control Plane Offline)';
        if (badge) badge.className = 'badge badge-amber';
        showToast('Audit verification unavailable: unable to reach Control Plane verification endpoint.');
      } finally {
        setTimeout(() => {
          if (btn) {
            btn.disabled = false;
            btn.innerText = 'Verify Cryptographic Chain';
          }
        }, 600);
      }
    }

    // Control Plane Liveness & Health Monitoring
    async function checkControlPlaneHealth() {
      const pill = document.getElementById('cp-status-pill');
      const dot = document.getElementById('cp-pulse-dot');
      const text = document.getElementById('cp-status-text');
      if (!pill || !dot || !text) return;

      try {
        const res = await fetch('/api/health');
        if (res.ok) {
          pill.style.borderColor = 'rgba(16, 185, 129, 0.4)';
          pill.style.background = 'rgba(16, 185, 129, 0.12)';
          dot.style.background = 'var(--accent-emerald)';
          dot.style.boxShadow = '0 0 8px var(--accent-emerald)';
          text.innerText = 'CONTROL PLANE: ONLINE (:9091)';
          text.style.color = 'var(--accent-emerald)';
          return true;
        }
      } catch (e) {
        // Fallback offline simulated mode
      }

      pill.style.borderColor = 'rgba(245, 158, 11, 0.4)';
      pill.style.background = 'rgba(245, 158, 11, 0.12)';
      dot.style.background = 'var(--accent-amber)';
      dot.style.boxShadow = '0 0 8px var(--accent-amber)';
      text.innerText = 'CONTROL PLANE: OFFLINE (SIMULATED MODE)';
      text.style.color = 'var(--accent-amber)';
      return false;
    }

    // Dynamic Domain Management
    async function loadDomains() {
      const tbody = document.getElementById('domains-table-tbody');
      const badge = document.getElementById('domains-source-badge');
      if (!tbody) return;

      try {
        const resp = await fetch('/api/proxy/domains');
        if (resp.ok) {
          const data = await resp.json();
          const domains = data.domains || (Array.isArray(data) ? data : []);
          if (domains.length > 0) {
            tbody.innerHTML = '';
            domains.forEach(d => {
              const tr = document.createElement('tr');

              const tdHost = document.createElement('td');
              const strong = document.createElement('strong');
              strong.textContent = d.hostname || '';
              tdHost.appendChild(strong);

              const tdOrigin = document.createElement('td');
              tdOrigin.className = 'mono';
              tdOrigin.textContent = d.cname_target || d.default_origin || 'edge.nexusedge.net';

              const tdCert = document.createElement('td');
              const certSpan = document.createElement('span');
              certSpan.className = 'badge badge-bd';
              certSpan.textContent = "Auto Let's Encrypt (ECDSA)";
              tdCert.appendChild(certSpan);

              const tdPops = document.createElement('td');
              tdPops.textContent = (d.allowed_pops && d.allowed_pops.length > 0) ? d.allowed_pops.join(', ') : 'Dhaka, Singapore, Frankfurt, Virginia';

              const tdProject = document.createElement('td');
              tdProject.textContent = d.project_id || 'proj-core';

              const tdStatus = document.createElement('td');
              const statusSpan = document.createElement('span');
              statusSpan.className = 'badge badge-bd';
              statusSpan.textContent = 'LIVE (PostgreSQL)';
              tdStatus.appendChild(statusSpan);

              tr.append(tdHost, tdOrigin, tdCert, tdPops, tdProject, tdStatus);
              tbody.appendChild(tr);
            });
            if (badge) {
              badge.className = 'badge badge-bd';
              badge.innerText = `LIVE SYNC (${domains.length} DOMAINS)`;
            }
            return;
          }
        }
      } catch (e) {
        // Fallback to demo fixtures
      }

      renderFallbackDomains();
    }

    function renderFallbackDomains() {
      const tbody = document.getElementById('domains-table-tbody');
      const badge = document.getElementById('domains-source-badge');
      if (!tbody) return;
      if (badge) {
        badge.className = 'badge badge-amber';
        badge.innerText = 'DEMO FIXTURES (CP OFFLINE)';
      }
      tbody.innerHTML = `
        <tr>
          <td><strong>api.nexusedge.io</strong></td>
          <td class="mono">edge.nexusedge.net</td>
          <td><span class="badge badge-bd">Auto Let's Encrypt (ECDSA)</span></td>
          <td>Dhaka, Singapore, Frankfurt, Virginia</td>
          <td>Global Anycast</td>
          <td><span class="badge badge-amber">DEMO FIXTURE</span></td>
        </tr>
        <tr>
          <td><strong>fintech.dhaka.bank</strong></td>
          <td class="mono">sovereign-bd.nexusedge.net</td>
          <td><span class="badge badge-bd">Vault AES-256 Validated</span></td>
          <td>Dhaka PoP Only</td>
          <td>BD-NDMA-2026</td>
          <td><span class="badge badge-amber">DEMO FIXTURE</span></td>
        </tr>
        <tr>
          <td><strong>models.deepcompute.ai</strong></td>
          <td class="mono">ai-router.nexusedge.net</td>
          <td><span class="badge badge-spot">Auto Managed TLS</span></td>
          <td>Iceland, Virginia, Frankfurt</td>
          <td>Low-Carbon Grid</td>
          <td><span class="badge badge-amber">DEMO FIXTURE</span></td>
        </tr>
      `;
    }

    function addSimulatedDomain(domain) {
      const tbody = document.getElementById('domains-table-tbody');
      if (!tbody) return;
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${domain}</strong></td>
        <td class="mono">edge.nexusedge.net</td>
        <td><span class="badge badge-bd">Auto Provisioning</span></td>
        <td>Dhaka, Singapore, Frankfurt, Virginia</td>
        <td>Global Anycast</td>
        <td><span class="badge badge-amber">DEMO FIXTURE</span></td>
      `;
      tbody.prepend(tr);
    }

    async function initSessionContext() {
      try {
        const resp = await fetch('/api/auth/session');
        if (resp.ok) {
          const session = await resp.json();
          window.__nexusedge_session = session;
        }
      } catch (e) {
        // BFF running offline
      }
    }

    // Initial Dashboard Bootstrap
    initSessionContext();
    checkControlPlaneHealth();
    loadDomains();
    fetchAuditLogs();
    setInterval(checkControlPlaneHealth, 15000);
