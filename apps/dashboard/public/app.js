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
      billing: { title: "Billing", crumb: "Token Economics & Arbitrage Savings" },
      developers: { title: "API & SDKs", crumb: "Developer Quickstart & Client Libraries" },
      sovereignty: { title: "Sovereignty & Placement", crumb: "Autonomous Workload Placement & Sovereign Law Enforcement" }
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

      if (viewId === 'developers') {
        populateQuickstartKeySelect();
        renderQuickstartSnippets();
      }
      if (viewId === 'sovereignty') {
        loadSovereigntyData();
      }
      if (viewId === 'security') {
        fetchAuditLogs();
        loadAPIKeys();
      }
      if (viewId === 'domains') {
        loadDomains();
      }
      if (viewId === 'storage') {
        loadStorageBuckets();
      }
      if (viewId === 'servers') {
        loadPoPs();
        loadPoPTelemetry();
        loadSubseaCables();
      }
      if (viewId === 'analytics') {
        loadAnalytics();
        loadLatencyMatrix();
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
      showToast(`[DEMO / PROTOTYPE] Project '${name}' creation previewed. Use 'nexusedge project create' CLI for production provisioning.`);
    }

    async function submitNewDomain() {
      const domainInput = document.getElementById('modal-domain-fqdn');
      const originInput = document.getElementById('modal-domain-origin');
      const portInput = document.getElementById('modal-domain-port');
      const protoSelect = document.getElementById('modal-domain-proto');

      const hostname = (domainInput && domainInput.value.trim()) || '';
      if (!hostname) {
        showToast('Please provide a valid fully qualified domain name (FQDN).');
        return;
      }

      const origin = (originInput && originInput.value.trim()) || '203.0.113.195';
      const port = parseInt((portInput && portInput.value) || '443', 10);
      const proto = (protoSelect && protoSelect.value) || 'https';

      const allowedPops = [];
      ['pop-dhaka', 'pop-singapore', 'pop-frankfurt', 'pop-virginia'].forEach(id => {
        const el = document.getElementById(id);
        if (el && el.checked) allowedPops.push(el.value);
      });
      if (allowedPops.length === 0) {
        allowedPops.push('dhaka', 'singapore');
      }

      closeModal('new-domain-modal');

      try {
        const resp = await fetch('/api/proxy/domains', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            hostname: hostname,
            origin_address: origin,
            origin_port: port,
            origin_protocol: proto,
            allowed_pops: allowedPops
          })
        });

        if (resp.ok) {
          const created = await resp.json();
          showToast(`Domain '${created.hostname || hostname}' onboarded. Configure DNS to activate.`);
          openDomainDnsModal({
            id: created.domain_id || created.id,
            hostname: created.hostname || hostname,
            cname_target: created.cname_target,
            verification_token: created.verification_token,
            status: created.status || 'pending_verification'
          });
          loadDomains();
          return;
        }

        const errData = await resp.json().catch(() => ({}));
        showToast(`Onboarding failed: ${errData.error || resp.statusText}`);
      } catch (err) {
        showToast(`Domain onboarding network error: ${err.message}`);
      }
    }

    function submitNewDns() {
      const name = document.getElementById('modal-dns-name').value || "sub";
      closeModal('new-dns-modal');
      showToast(`[DEMO / PROTOTYPE] DNS record '${name}' propagation simulated. Live BGP sync requires PowerDNS API.`);
    }

    function submitQuickDeploy() {
      const name = document.getElementById('modal-deploy-name').value || "Workload-01";
      closeModal('quick-deploy-modal');
      showToast(`[DEMO / PROTOTYPE] Workload '${name}' placement previewed. Production workloads require gRPC Universal Scheduler.`);
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

        let responseBody = '';
        try {
          const bodyJson = await resp.json();
          if (bodyJson.choices && bodyJson.choices[0] && bodyJson.choices[0].message) {
            responseBody = bodyJson.choices[0].message.content;
          } else {
            responseBody = JSON.stringify(bodyJson, null, 2);
          }
        } catch {
          responseBody = await resp.text();
        }

        const provider = resp.headers.get('x-nexusedge-provider') || 'Not reported';
        const costPerM = resp.headers.get('x-nexusedge-cost-per-mtokens');
        const ttft = resp.headers.get('x-nexusedge-ttft-ms');
        const totalDuration = resp.headers.get('x-nexusedge-total-duration-ms');
        const tokensTotal = resp.headers.get('x-nexusedge-tokens-total');
        const savingsUSD = resp.headers.get('x-nexusedge-estimated-savings-usd');
        const failovers = resp.headers.get('x-nexusedge-failover-count');

        term.innerText += `\n< HTTP/1.1 ${resp.status} OK
< X-NexusEdge-Provider: ${provider}
< X-NexusEdge-Routing-Strategy: ${strategy}
< X-NexusEdge-Cost-Per-MTokens: ${costPerM ? '$' + costPerM : 'Unavailable'}
< X-NexusEdge-Tokens-Total: ${tokensTotal || 'Unavailable'}
< X-NexusEdge-Estimated-Savings-USD: ${savingsUSD ? '$' + savingsUSD : 'Unavailable'}
< X-NexusEdge-TTFT-Ms: ${ttft ? ttft + ' ms' : 'Unavailable'}
< X-NexusEdge-Failover-Count: ${failovers || '0'}
< X-NexusEdge-Total-Duration-Ms: ${totalDuration ? totalDuration + ' ms' : 'Unavailable'}

[LIVE INFERENCE RESPONSE]
${responseBody || '(Empty response payload)'}`;
        showToast(`Inference dispatched: routed to ${provider}`);
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
          validSpan.className = 'badge badge-dim';
          validSpan.dataset.auditRowBadge = 'true';
          validSpan.textContent = 'UNVERIFIED';
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
          const rowBadges = document.querySelectorAll('[data-audit-row-badge="true"]');
          if (data.chain_valid) {
            if (statusEl) statusEl.innerText = `Chain Integrity: VERIFIED (${data.total_records || data.total || 0} records)`;
            if (badge) badge.className = 'badge badge-bd';
            rowBadges.forEach(b => {
              b.className = 'badge badge-bd';
              b.textContent = 'CRYPTOGRAPHICALLY VALID';
            });
            showToast('Cryptographic Audit Chain verified: 100% valid SHA-256 HMAC integrity.');
          } else {
            if (statusEl) statusEl.innerText = 'Chain Integrity: INVALID / VERIFICATION FAILED!';
            if (badge) badge.className = 'badge badge-amber';
            rowBadges.forEach(b => {
              b.className = 'badge badge-amber';
              b.textContent = 'VERIFICATION FAILED';
            });
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

    // Dynamic Domain Management & DNS Verification Wizard
    let currentWizardDomain = null;

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

              const tdStatus = document.createElement('td');
              const statusSpan = document.createElement('span');
              const isVerified = (d.status === 'active' || d.status === 'verified');
              if (isVerified) {
                statusSpan.className = 'badge badge-bd';
                statusSpan.textContent = 'ACTIVE (VERIFIED)';
              } else {
                statusSpan.className = 'badge badge-amber';
                statusSpan.textContent = 'PENDING DNS';
              }
              tdStatus.appendChild(statusSpan);

              const tdPops = document.createElement('td');
              tdPops.textContent = (d.allowed_pops && d.allowed_pops.length > 0)
                ? d.allowed_pops.join(', ')
                : 'Dhaka, Singapore, Frankfurt, Virginia';

              const tdProject = document.createElement('td');
              tdProject.textContent = d.project_id || 'proj-core';

              const tdActions = document.createElement('td');
              tdActions.style.display = 'flex';
              tdActions.style.gap = '0.4rem';
              tdActions.style.alignItems = 'center';

              if (!isVerified) {
                const verifyBtn = document.createElement('button');
                verifyBtn.className = 'btn btn-primary btn-sm';
                verifyBtn.textContent = 'Verify DNS';
                verifyBtn.onclick = () => verifyDomain(d.id, d.hostname);

                const setupBtn = document.createElement('button');
                setupBtn.className = 'btn btn-secondary btn-sm';
                setupBtn.textContent = 'DNS Setup';
                setupBtn.onclick = () => openDomainDnsModal(d);

                tdActions.append(verifyBtn, setupBtn);
              }

              const deleteBtn = document.createElement('button');
              deleteBtn.className = 'btn btn-secondary btn-sm';
              deleteBtn.textContent = 'Delete';
              deleteBtn.onclick = () => deleteDomain(d.id, d.hostname);
              tdActions.appendChild(deleteBtn);

              tr.append(tdHost, tdOrigin, tdStatus, tdPops, tdProject, tdActions);
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
          <td><span class="badge badge-bd">ACTIVE (VERIFIED)</span></td>
          <td>Dhaka, Singapore, Frankfurt, Virginia</td>
          <td>Global Anycast</td>
          <td><button class="btn btn-secondary btn-sm" onclick="showToast('Demo domain is managed by root operator')">Details</button></td>
        </tr>
        <tr>
          <td><strong>fintech.dhaka.bank</strong></td>
          <td class="mono">sovereign-bd.nexusedge.net</td>
          <td><span class="badge badge-bd">ACTIVE (VERIFIED)</span></td>
          <td>Dhaka PoP Only</td>
          <td>BD-NDMA-2026</td>
          <td><button class="btn btn-secondary btn-sm" onclick="showToast('Demo domain is managed by root operator')">Details</button></td>
        </tr>
        <tr>
          <td><strong>models.deepcompute.ai</strong></td>
          <td class="mono">ai-router.nexusedge.net</td>
          <td><span class="badge badge-amber">PENDING DNS</span></td>
          <td>Iceland, Virginia, Frankfurt</td>
          <td>Low-Carbon Grid</td>
          <td><button class="btn btn-primary btn-sm" onclick="openDomainDnsModal({ id: 'dom-demo-ai', hostname: 'models.deepcompute.ai', cname_target: 'ai-router.nexusedge.net', verification_token: 'nke-verify-ai-demo-token', status: 'pending_verification' })">DNS Setup</button></td>
        </tr>
      `;
    }

    function openDomainDnsModal(domain) {
      if (!domain) return;
      currentWizardDomain = domain;

      const hostInput = document.getElementById('dns-wizard-cname-host');
      const targetInput = document.getElementById('dns-wizard-cname-target');
      const txtNameInput = document.getElementById('dns-wizard-txt-name');
      const txtTokenInput = document.getElementById('dns-wizard-txt-token');
      const statusBox = document.getElementById('dns-wizard-status-box');
      const verifyBtn = document.getElementById('btn-wizard-verify-now');

      const hostname = domain.hostname || '';
      const domainId = domain.id || domain.domain_id || 'dom';
      const cnameTarget = domain.cname_target || `${domainId}.edge.nexusedge.net`;
      const txtName = `_nexusedge-challenge.${hostname}`;
      const txtToken = domain.verification_token || `nke-challenge-${domainId}`;

      if (hostInput) hostInput.value = hostname;
      if (targetInput) targetInput.value = cnameTarget;
      if (txtNameInput) txtNameInput.value = txtName;
      if (txtTokenInput) txtTokenInput.value = txtToken;

      if (statusBox) {
        if (domain.status === 'active' || domain.status === 'verified') {
          statusBox.style.display = 'block';
          statusBox.style.background = 'rgba(16, 185, 129, 0.15)';
          statusBox.style.color = 'var(--accent-emerald)';
          statusBox.innerText = 'Domain Active: DNS verified and live on Anycast Edge.';
          if (verifyBtn) {
            verifyBtn.disabled = true;
            verifyBtn.innerText = 'Verified';
          }
        } else {
          statusBox.style.display = 'none';
          if (verifyBtn) {
            verifyBtn.disabled = false;
            verifyBtn.innerText = 'Verify DNS Now';
          }
        }
      }

      openModal('modal-domain-dns-instructions');
    }

    function copyDnsWizardTarget() {
      const targetInput = document.getElementById('dns-wizard-cname-target');
      if (targetInput && targetInput.value) {
        navigator.clipboard.writeText(targetInput.value);
        showToast('CNAME target copied to clipboard.');
      }
    }

    function copyDnsWizardToken() {
      const tokenInput = document.getElementById('dns-wizard-txt-token');
      if (tokenInput && tokenInput.value) {
        navigator.clipboard.writeText(tokenInput.value);
        showToast('TXT challenge token copied to clipboard.');
      }
    }

    async function triggerWizardVerify() {
      if (!currentWizardDomain) return;
      const domainId = currentWizardDomain.id || currentWizardDomain.domain_id;
      const hostname = currentWizardDomain.hostname;
      await verifyDomain(domainId, hostname, true);
    }

    async function verifyDomain(domainId, hostname, fromWizard = false) {
      if (!domainId) return;
      const statusBox = document.getElementById('dns-wizard-status-box');
      const verifyBtn = document.getElementById('btn-wizard-verify-now');

      if (fromWizard && verifyBtn) {
        verifyBtn.disabled = true;
        verifyBtn.innerText = 'Checking DNS...';
      }

      try {
        const resp = await fetch(`/api/proxy/domains/${encodeURIComponent(domainId)}/verify`, {
          method: 'POST'
        });

        if (resp.ok) {
          const data = await resp.json();
          showToast(`Domain '${hostname}' verified! Edge route is now active.`);
          if (statusBox) {
            statusBox.style.display = 'block';
            statusBox.style.background = 'rgba(16, 185, 129, 0.15)';
            statusBox.style.color = 'var(--accent-emerald)';
            statusBox.innerText = `Verified: ${data.message || 'Domain active on edge proxy'}`;
          }
          if (verifyBtn) {
            verifyBtn.disabled = true;
            verifyBtn.innerText = 'Verified';
          }
          loadDomains();
          return;
        }

        const errData = await resp.json().catch(() => ({}));
        const errMsg = errData.error || `Verification returned HTTP ${resp.status}`;
        showToast(`Verification check: ${errMsg}`);
        if (statusBox) {
          statusBox.style.display = 'block';
          statusBox.style.background = 'rgba(239, 68, 68, 0.15)';
          statusBox.style.color = 'var(--accent-rose)';
          statusBox.innerText = `DNS Resolution Pending: ${errMsg}`;
        }
        if (verifyBtn) {
          verifyBtn.disabled = false;
          verifyBtn.innerText = 'Retry Verification';
        }
      } catch (err) {
        showToast(`Network error during DNS verification: ${err.message}`);
        if (verifyBtn) {
          verifyBtn.disabled = false;
          verifyBtn.innerText = 'Retry Verification';
        }
      }
    }

    async function deleteDomain(domainId, hostname) {
      if (!domainId) return;
      if (!confirm(`Are you sure you want to remove domain '${hostname}' from NexusEdge edge routes?`)) {
        return;
      }

      try {
        const resp = await fetch(`/api/proxy/domains/${encodeURIComponent(domainId)}`, {
          method: 'DELETE'
        });

        if (resp.ok) {
          showToast(`Domain '${hostname}' successfully removed.`);
          loadDomains();
          return;
        }

        const errData = await resp.json().catch(() => ({}));
        showToast(`Delete failed: ${errData.error || resp.statusText}`);
      } catch (err) {
        showToast(`Network error while deleting domain: ${err.message}`);
      }
    }

    // Edge PoPs & Multi-PoP Global Topology
    // Edge PoPs & Multi-PoP Global Topology
    async function loadPoPs() {
      const tbody = document.getElementById('pops-table-tbody');
      const badge = document.getElementById('pops-source-badge');
      if (!tbody) return;

      try {
        const resp = await fetch('/api/proxy/pops');
        if (resp.ok) {
          const data = await resp.json();
          const pops = data.pops || [];
          if (pops.length > 0) {
            tbody.innerHTML = '';
            let hasSimulated = false;

            pops.forEach(pop => {
              const isSimulated = pop.is_simulated || pop.mode === 'SIMULATION' || pop.source === 'SIMULATED';
              if (isSimulated) hasSimulated = true;
              const tr = document.createElement('tr');

              // 1. PoP ID / Region
              const tdId = document.createElement('td');
              tdId.className = 'mono';
              const strongId = document.createElement('strong');
              strongId.textContent = pop.id;
              const br1 = document.createElement('br');
              const spanReg = document.createElement('span');
              spanReg.style.fontSize = '0.75rem';
              spanReg.style.color = 'var(--text-muted)';
              spanReg.textContent = pop.region || '';
              tdId.append(strongId, br1, spanReg);

              // 2. City / Location
              const tdLoc = document.createElement('td');
              const strongCity = document.createElement('strong');
              strongCity.textContent = pop.city || '';
              const textCountry = document.createTextNode(`, ${pop.country || ''}`);
              const br2 = document.createElement('br');
              const spanName = document.createElement('span');
              spanName.style.fontSize = '0.75rem';
              spanName.style.color = 'var(--text-muted)';
              spanName.textContent = pop.name || '';
              tdLoc.append(strongCity, textCountry, br2, spanName);

              // 3. Anycast Routing (Explicitly distinguish RFC Testbed vs. Unicast Host)
              const tdAnycast = document.createElement('td');
              tdAnycast.className = 'mono';
              const spanIp = document.createElement('span');
              spanIp.className = 'badge badge-subtle';
              const isSingaporeHost = pop.id === 'singapore';
              const ipLabel = pop.anycast_ipv4 || (isSingaporeHost ? '80.225.241.129' : '198.51.100.1');
              spanIp.textContent = isSimulated
                ? (isSingaporeHost ? `${ipLabel} (Host)` : `${ipLabel} (RFC 5737)`)
                : ipLabel;
              const br3 = document.createElement('br');
              const spanAsn = document.createElement('span');
              spanAsn.style.fontSize = '0.72rem';
              spanAsn.style.color = 'var(--text-muted)';
              spanAsn.textContent = isSimulated ? `AS${pop.asn || 64512} (RFC 6996)` : `AS${pop.asn || 64512}`;
              tdAnycast.append(spanIp, br3, spanAsn);

              // 4. Target Peering / SLA / Topology Truthfulness
              const tdPeering = document.createElement('td');
              let peeringText = 'Global Anycast';
              let slaText = 'Subsea Transit';
              if (pop.id === 'dhaka') {
                peeringText = 'BDIX Peering (167 ISPs)';
                slaText = isSimulated ? 'Testbed Target (< 10 ms BD-NDMA 2026)' : '< 10 ms (Domestic BD-NDMA 2026)';
              } else if (pop.id === 'singapore') {
                peeringText = 'Equinix SG1 / SMW6 Direct';
                slaText = isSimulated ? 'Single-PoP Host Anchor (Simulation)' : 'Active Live Production Anchor';
              } else if (pop.id === 'frankfurt') {
                peeringText = 'DE-CIX Frankfurt Peering';
                slaText = isSimulated ? 'Testbed Target (14 ms EU GDPR)' : '14 ms (EU GDPR Sovereign)';
              } else if (pop.id === 'virginia') {
                peeringText = 'Equinix Ashburn DC2';
                slaText = isSimulated ? 'Testbed Target (22 ms US East)' : '22 ms (Lowest Cost US)';
              }
              const strongPeer = document.createElement('strong');
              strongPeer.textContent = peeringText;
              const br4 = document.createElement('br');
              const spanSla = document.createElement('span');
              spanSla.className = isSimulated ? 'text-amber' : 'text-emerald';
              spanSla.style.fontSize = '0.75rem';
              spanSla.textContent = slaText;
              tdPeering.append(strongPeer, br4, spanSla);

              // 5. BGP Route State
              const tdBgp = document.createElement('td');
              const isAnnounced = pop.bgp_state === 'ANNOUNCED';
              const spanBgp = document.createElement('span');
              spanBgp.className = `badge ${isAnnounced ? (isSimulated ? 'badge-amber' : 'badge-bd') : 'badge-subtle'}`;
              spanBgp.textContent = isSimulated ? `SIMULATED_${pop.bgp_state || 'STANDBY'}` : (pop.bgp_state || 'UNKNOWN');
              const br5 = document.createElement('br');
              const spanStatus = document.createElement('span');
              spanStatus.style.fontSize = '0.72rem';
              spanStatus.style.color = 'var(--text-muted)';
              const nodeInfo = (pop.node_count !== undefined) ? `${pop.node_count} Nodes` : '';
              spanStatus.textContent = `${pop.status || ''} ${nodeInfo}`.trim();
              tdBgp.append(spanBgp, br5, spanStatus);

              // 6. Actions (Reflect simulation boundaries clearly)
              const tdActions = document.createElement('td');
              const isOperator = window.__nexusedge_session && window.__nexusedge_session.role === 'PLATFORM_OPERATOR';
              if (isOperator) {
                const btn = document.createElement('button');
                btn.className = `btn btn-sm ${isAnnounced ? 'btn-danger' : 'btn-primary'}`;
                btn.style.fontSize = '0.72rem';
                btn.style.padding = '0.2rem 0.5rem';
                btn.textContent = isSimulated
                  ? (isAnnounced ? 'Simulate Drain' : 'Simulate Announce')
                  : (isAnnounced ? 'Drain (Withdraw)' : 'Announce Anycast');
                btn.onclick = () => togglePoPBGP(pop.id, isAnnounced ? 'withdraw' : 'announce');
                tdActions.appendChild(btn);
              } else {
                const spanIngress = document.createElement('span');
                spanIngress.style.fontSize = '0.75rem';
                spanIngress.style.color = 'var(--text-muted)';
                spanIngress.textContent = isSimulated ? 'Simulated Route' : (isSingaporeHost ? 'Primary Gateway' : 'Active Ingress');
                tdActions.appendChild(spanIngress);
              }

              tr.append(tdId, tdLoc, tdAnycast, tdPeering, tdBgp, tdActions);
              tbody.appendChild(tr);
            });

            if (badge) {
              if (hasSimulated) {
                badge.className = 'badge badge-amber';
                badge.innerText = `SIMULATED TESTBED (${pops.length} POPS IN-MEMORY)`;
              } else {
                badge.className = 'badge badge-bd';
                badge.innerText = `LIVE MULTI-POP FLEET (${pops.length} POPS SYNCHRONIZED)`;
              }
            }
            return;
          }
        }
      } catch (err) {
        if (badge) {
          badge.className = 'badge badge-rose';
          badge.innerText = 'TOPOLOGY CONTROL PLANE OFFLINE';
        }
      }
    }

    async function togglePoPBGP(popId, action) {
      try {
        const resp = await fetch(`/api/proxy/pops/${encodeURIComponent(popId)}/bgp/${encodeURIComponent(action)}`, {
          method: 'POST'
        });
        if (resp.ok) {
          const data = await resp.json();
          showToast(`PoP '${popId}' simulated BGP state updated to ${data.bgp_state} (${data.status}). External BGP speaker integration required for physical routing.`);
          loadPoPs();
          return;
        }
        const err = await resp.json();
        showToast(`Error updating PoP BGP: ${err.error || 'Request failed'}`);
      } catch (e) {
        showToast(`Failed to update PoP BGP: ${e.message}`);
      }
    }

    function selectMapPoP(popId) {
      const pops = ['dhaka', 'singapore', 'frankfurt', 'virginia'];
      pops.forEach(p => {
        const hud = document.getElementById(`hud-${p}`);
        const svgNode = document.getElementById(`svg-node-${p}`);
        if (hud) {
          if (p === popId) {
            hud.classList.add('selected');
          } else {
            hud.classList.remove('selected');
          }
        }
        if (svgNode) {
          if (p === popId) {
            svgNode.classList.add('active-pop');
          } else {
            svgNode.classList.remove('active-pop');
          }
        }
      });
    }
    window.selectMapPoP = selectMapPoP;

    async function loadPoPTelemetry() {
      const probeStatus = document.getElementById('probe-status-text');
      const badge = document.getElementById('pop-telemetry-badge');
      const mapSyncBadge = document.getElementById('map-sync-badge');
      const mapProbeStatus = document.getElementById('map-probe-status');
      const routesBadge = document.getElementById('pop-routes-badge');
      const routesTbody = document.getElementById('pop-routes-tbody');
      const btnProbes = document.getElementById('btn-trigger-probes');
      const mapProbeBtn = document.getElementById('map-probe-btn');

      const isOperator = window.__nexusedge_session && window.__nexusedge_session.role === 'PLATFORM_OPERATOR';
      if (btnProbes) {
        if (!isOperator) {
          btnProbes.title = 'PLATFORM_OPERATOR role required to trigger synthetic probes';
          btnProbes.style.opacity = '0.6';
        } else {
          btnProbes.title = 'Run live synthetic probe cycle across all PoPs';
          btnProbes.style.opacity = '1.0';
        }
      }
      if (mapProbeBtn) {
        if (!isOperator) {
          mapProbeBtn.title = 'PLATFORM_OPERATOR role required to trigger synthetic probes';
          mapProbeBtn.style.opacity = '0.6';
        } else {
          mapProbeBtn.title = 'Run live synthetic probe cycle across all PoPs';
          mapProbeBtn.style.opacity = '1.0';
        }
      }

      // 1. Fetch live PoP health states
      try {
        const respHealth = await fetch('/api/proxy/pops/health');
        if (respHealth.ok) {
          const healthData = await respHealth.json();
          const pops = healthData.pops || [];
          if (badge) {
            badge.innerText = `${pops.length} POPS SYNCHRONIZED`;
          }
          if (mapSyncBadge) {
            mapSyncBadge.innerText = `${pops.length} POPS SYNCHRONIZED`;
          }
          pops.forEach(pop => {
            const ewmaElem = document.getElementById(`ewma-${pop.pop_id}`);
            const lossElem = document.getElementById(`loss-${pop.pop_id}`);
            const badgeElem = document.getElementById(`badge-status-${pop.pop_id}`);

            const rtt = pop.ewma_latency_ms !== undefined ? pop.ewma_latency_ms.toFixed(1) : (pop.last_rtt_ms !== undefined ? pop.last_rtt_ms.toFixed(1) : '-');
            const loss = pop.packet_loss_percent !== undefined ? pop.packet_loss_percent.toFixed(1) : '0.0';
            const st = (pop.status || 'OPTIMAL').toUpperCase();

            if (ewmaElem) {
              ewmaElem.textContent = `${rtt} ms`;
            }
            if (lossElem) {
              lossElem.textContent = `${loss}%`;
            }
            if (badgeElem) {
              badgeElem.textContent = st;
              if (st === 'OPTIMAL' || st === 'ACTIVE') {
                badgeElem.className = 'badge badge-emerald';
              } else if (st === 'FAILOVER_ENGAGED' || st === 'DEGRADED') {
                badgeElem.className = 'badge badge-amber';
              } else {
                badgeElem.className = 'badge badge-rose';
              }
            }

            // Update SVG map node badge
            const mapRttElem = document.getElementById(`map-rtt-${pop.pop_id}`);
            if (mapRttElem) {
              const regionLabels = {
                dhaka: 'BD-NDMA 2026',
                singapore: 'SMW6 Anchor',
                frankfurt: 'EU GDPR',
                virginia: 'Ashburn DC2'
              };
              const regLabel = regionLabels[pop.pop_id] || pop.region || 'Edge';
              mapRttElem.textContent = `${rtt} ms \u2022 ${regLabel}`;
            }

            // Update HUD card values
            const hudRttElem = document.getElementById(`hud-rtt-val-${pop.pop_id}`);
            if (hudRttElem) {
              hudRttElem.textContent = `${rtt} ms`;
            }
            const hudBadgeElem = document.getElementById(`hud-badge-${pop.pop_id}`);
            if (hudBadgeElem) {
              hudBadgeElem.textContent = st;
              if (st === 'OPTIMAL' || st === 'ACTIVE') {
                hudBadgeElem.className = 'badge badge-emerald';
              } else if (st === 'FAILOVER_ENGAGED' || st === 'DEGRADED') {
                hudBadgeElem.className = 'badge badge-amber';
              } else {
                hudBadgeElem.className = 'badge badge-rose';
              }
            }
          });
          if (healthData.timestamp) {
            const d = new Date(healthData.timestamp);
            const timeStr = `Last Probed: ${d.toLocaleTimeString()}`;
            if (probeStatus) probeStatus.textContent = timeStr;
            if (mapProbeStatus) mapProbeStatus.textContent = timeStr;
          }
        }
      } catch (err) {
        if (probeStatus) probeStatus.textContent = 'Telemetry Sync Error';
        if (mapProbeStatus) mapProbeStatus.textContent = 'Telemetry Sync Error';
      }

      // 2. Fetch multi-PoP failover routes
      try {
        const respRoutes = await fetch('/api/proxy/pops/routes');
        if (respRoutes.ok) {
          const routesData = await respRoutes.json();
          const routes = routesData.routes || [];
          if (routesBadge) {
            routesBadge.innerText = `${routes.length} DYNAMIC PATHS VERIFIED`;
          }
          if (routesTbody && routes.length > 0) {
            routesTbody.innerHTML = '';
            routes.forEach(r => {
              const tr = document.createElement('tr');

              // Origin PoP
              const tdOrigin = document.createElement('td');
              tdOrigin.className = 'mono';
              const strongOrigin = document.createElement('strong');
              strongOrigin.textContent = r.pop_id;
              const br1 = document.createElement('br');
              const spanReg = document.createElement('span');
              spanReg.style.fontSize = '0.72rem';
              spanReg.style.color = 'var(--text-muted)';
              spanReg.textContent = r.region || '';
              tdOrigin.append(strongOrigin, br1, spanReg);

              // Primary Target
              const tdPrimary = document.createElement('td');
              tdPrimary.textContent = `${r.primary_target} (${r.primary_rtt_ms !== undefined ? r.primary_rtt_ms.toFixed(1) : '-'} ms)`;

              // Active Target
              const tdActive = document.createElement('td');
              const spanActive = document.createElement('span');
              const isLocal = r.active_target === r.pop_id;
              spanActive.className = isLocal ? 'badge badge-emerald' : 'badge badge-amber';
              spanActive.textContent = isLocal ? `${r.active_target} (LOCAL)` : `${r.active_target} (FAILOVER)`;
              tdActive.appendChild(spanActive);

              // Failover Hops
              const tdHops = document.createElement('td');
              if (r.failover_targets && r.failover_targets.length > 0) {
                r.failover_targets.forEach((hop, idx) => {
                  if (idx > 0) tdHops.appendChild(document.createElement('br'));
                  const spanHop = document.createElement('span');
                  spanHop.className = hop.status === 'ACTIVE_FAILOVER' ? 'badge badge-amber' : 'badge badge-subtle';
                  spanHop.textContent = `${hop.subsea_cable || 'Fiber'} → ${hop.target_pop} (${hop.sla_rtt_ms} ms)`;
                  tdHops.appendChild(spanHop);
                  if (hop.sovereignty_restricted) {
                    const brSov = document.createElement('br');
                    const spanSov = document.createElement('span');
                    spanSov.style.fontSize = '0.72rem';
                    spanSov.style.color = 'var(--accent-purple)';
                    spanSov.textContent = 'Strict Sovereign Invariant (Fail-Closed)';
                    tdHops.append(brSov, spanSov);
                  }
                });
              } else {
                tdHops.textContent = 'None (Direct Ingress Only)';
              }

              // Route Status
              const tdStatus = document.createElement('td');
              const spanStatus = document.createElement('span');
              const st = (r.status || 'OPTIMAL').toUpperCase();
              spanStatus.className = st === 'OPTIMAL' ? 'badge badge-emerald' : (st === 'FAILOVER_ENGAGED' ? 'badge badge-amber' : 'badge badge-rose');
              spanStatus.textContent = st;
              tdStatus.appendChild(spanStatus);

              tr.append(tdOrigin, tdPrimary, tdActive, tdHops, tdStatus);
              routesTbody.appendChild(tr);
            });
          }
        }
      } catch (err) {
        // BFF routes offline
      }
    }

    async function triggerPoPProbes() {
      const probeStatus = document.getElementById('probe-status-text');
      const mapProbeStatus = document.getElementById('map-probe-status');
      const isOperator = window.__nexusedge_session && window.__nexusedge_session.role === 'PLATFORM_OPERATOR';
      if (!isOperator) {
        showToast('Forbidden: PLATFORM_OPERATOR role required to trigger synthetic probes');
        return;
      }
      if (probeStatus) probeStatus.textContent = 'Probing Global PoPs...';
      if (mapProbeStatus) mapProbeStatus.textContent = 'Probing Global PoPs...';
      try {
        const resp = await fetch('/api/proxy/pops/health/probe', {
          method: 'POST'
        });
        if (resp.ok) {
          const data = await resp.json();
          showToast(`Synthetic probe cycle complete across ${data.total_probed || 4} PoPs.`);
          await loadPoPTelemetry();
          return;
        }
        const err = await resp.json();
        showToast(`Probe execution failed: ${err.error || 'Request rejected'}`);
        if (probeStatus) probeStatus.textContent = 'Probe Failed';
        if (mapProbeStatus) mapProbeStatus.textContent = 'Probe Failed';
      } catch (e) {
        showToast(`Probe network error: ${e.message}`);
        if (probeStatus) probeStatus.textContent = 'Probe Error';
        if (mapProbeStatus) mapProbeStatus.textContent = 'Probe Error';
      }
    }

    async function loadAnalytics() {
      try {
        const resp = await fetch('/api/proxy/analytics/summary');
        if (!resp.ok) {
          return;
        }
        const data = await resp.json();

        // Total requests & Success rate
        const totalReqEl = document.getElementById('analytics-total-requests');
        const successRateEl = document.getElementById('analytics-success-rate');
        if (totalReqEl) totalReqEl.textContent = Number(data.total_requests || 0).toLocaleString();
        if (successRateEl) {
          const pct = ((data.success_rate !== undefined ? data.success_rate : 1.0) * 100).toFixed(1);
          const successCount = Number((data.status_distribution && data.status_distribution['2xx']) || 0);
          successRateEl.textContent = `Success: ${pct}% (${successCount.toLocaleString()} req)`;
        }

        // Latencies
        const p50El = document.getElementById('analytics-latency-p50');
        const p99El = document.getElementById('analytics-latency-p99');
        if (p50El) p50El.textContent = `${Number(data.p50_latency_ms || 0).toFixed(1)} ms`;
        if (p99El) p99El.textContent = `P95: ${Number(data.p95_latency_ms || 0).toFixed(1)} ms | P99: ${Number(data.p99_latency_ms || 0).toFixed(1)} ms`;

        // Cache Hit Ratio
        const cacheEl = document.getElementById('analytics-cache-hit-ratio');
        if (cacheEl) {
          const ratioPct = ((data.cache_hit_ratio !== undefined ? data.cache_hit_ratio : 1.0) * 100).toFixed(1);
          cacheEl.textContent = `${ratioPct}%`;
        }

        // Threat Blocks
        const threatEl = document.getElementById('analytics-threat-blocks');
        if (threatEl) threatEl.textContent = Number(data.threat_blocks || 0).toLocaleString();

        // Status code distribution
        const s2 = Number((data.status_distribution && data.status_distribution['2xx']) || 0);
        const s4 = Number((data.status_distribution && data.status_distribution['4xx']) || 0);
        const s5 = Number((data.status_distribution && data.status_distribution['5xx']) || 0);
        const total = Math.max(1, s2 + s4 + s5);

        const s2Pct = ((s2 / total) * 100).toFixed(1);
        const s4Pct = ((s4 / total) * 100).toFixed(1);
        const s5Pct = ((s5 / total) * 100).toFixed(1);

        const el2 = document.getElementById('analytics-status-2xx');
        const el4 = document.getElementById('analytics-status-4xx');
        const el5 = document.getElementById('analytics-status-5xx');
        if (el2) el2.textContent = `${s2.toLocaleString()} req (${s2Pct}%)`;
        if (el4) el4.textContent = `${s4.toLocaleString()} req (${s4Pct}%)`;
        if (el5) el5.textContent = `${s5.toLocaleString()} req (${s5Pct}%)`;

        const bar2 = document.getElementById('analytics-bar-2xx');
        const bar4 = document.getElementById('analytics-bar-4xx');
        const bar5 = document.getElementById('analytics-bar-5xx');
        if (bar2) bar2.style.width = `${s2Pct}%`;
        if (bar4) bar4.style.width = `${s4Pct}%`;
        if (bar5) bar5.style.width = `${s5Pct}%`;

        // PoP distribution
        const popDist = data.pop_distribution || {};
        const popTotal = Math.max(1, Object.values(popDist).reduce((sum, v) => sum + Number(v), 0));
        ['dhaka', 'singapore', 'frankfurt', 'virginia'].forEach(region => {
          const cell = document.getElementById(`pop-traffic-${region}`);
          if (cell) {
            const count = Number(popDist[region] || 0);
            const pct = ((count / popTotal) * 100).toFixed(1);
            cell.textContent = `${count.toLocaleString()} req (${pct}%)`;
          }
        });
      } catch (err) {
        console.error('Failed to load telemetry summary:', err);
      }
    }

    async function loadLatencyMatrix() {
      const tbody = document.getElementById('matrix-table-tbody');
      const badge = document.getElementById('matrix-source-badge');
      try {
        const resp = await fetch('/api/proxy/pops/matrix');
        if (resp.ok) {
          const data = await resp.json();
          const routes = data.routes || [];
          if (routes.length > 0) {
            if (tbody) {
              // Extract distinct PoPs dynamically from routes
              const popSet = new Set();
              routes.forEach(r => {
                if (r.from_pop) popSet.add(r.from_pop);
                const target = r.to_pop || r.to_target;
                if (target) popSet.add(target);
              });
              const popList = Array.from(popSet);
              const matrixMap = {};
              routes.forEach(r => {
                const target = r.to_pop || r.to_target;
                if (!matrixMap[r.from_pop]) matrixMap[r.from_pop] = {};
                matrixMap[r.from_pop][target] = r.latency_ms;
              });

              tbody.innerHTML = '';
              popList.forEach(fromPop => {
                const tr = document.createElement('tr');
                const tdHeader = document.createElement('td');
                const strongFrom = document.createElement('strong');
                strongFrom.textContent = fromPop.charAt(0).toUpperCase() + fromPop.slice(1);
                tdHeader.appendChild(strongFrom);
                tr.appendChild(tdHeader);

                popList.forEach(toPop => {
                  const td = document.createElement('td');
                  if (fromPop === toPop) {
                    td.className = 'text-emerald';
                    const strongZero = document.createElement('strong');
                    strongZero.textContent = '0 ms';
                    td.appendChild(strongZero);
                  } else {
                    const lat = (matrixMap[fromPop] && matrixMap[fromPop][toPop] !== undefined)
                      ? matrixMap[fromPop][toPop]
                      : '-';
                    td.textContent = typeof lat === 'number' ? `${lat} ms` : lat;
                  }
                  tr.appendChild(td);
                });
                tbody.appendChild(tr);
              });
            }

            if (badge) {
              if (data.is_simulated) {
                badge.className = 'badge badge-amber';
                badge.innerText = `SIMULATED FIBER TRANSIT (${routes.length} PATHS ESTIMATED)`;
              } else {
                badge.className = 'badge badge-bd';
                badge.innerText = `LIVE SUBSEA TRANSIT (${routes.length} MATRIX PATHS VERIFIED)`;
              }
            }
            return;
          }
        }
      } catch (err) {
        if (badge) {
          badge.className = 'badge badge-rose';
          badge.innerText = 'TRANSIT METRICS UNAVAILABLE';
        }
      }
    }

    async function initSessionContext() {
      try {
        const resp = await fetch('/api/auth/session');
        if (resp.ok) {
          const session = await resp.json();
          window.__nexusedge_session = session;
          loadPoPs(); // Re-render with operator action buttons if operator
          loadPoPTelemetry();
          loadAPIKeys();
        }
      } catch (e) {
        // BFF running offline
      }
    }

    // --- Developer API Key Vault Operations ---

    function openNewKeyModal() {
      const isOperatorOrAdmin = window.__nexusedge_session &&
        (window.__nexusedge_session.role === 'PLATFORM_OPERATOR' || window.__nexusedge_session.role === 'TENANT_ADMIN');
      if (!isOperatorOrAdmin) {
        showToast('Forbidden: PLATFORM_OPERATOR or TENANT_ADMIN role required to generate API keys');
        return;
      }
      openModal('modal-new-api-key');
    }
    window.openNewKeyModal = openNewKeyModal;

    async function loadAPIKeys() {
      const tbody = document.getElementById('api-keys-tbody');
      const badge = document.getElementById('api-keys-count-badge');
      if (!tbody) return;

      try {
        const resp = await fetch('/api/proxy/api-keys');
        if (resp.ok) {
          const data = await resp.json();
          const keys = data.keys || [];
          window.__loaded_api_keys = keys;
          populateQuickstartKeySelect();
          if (badge) {
            const activeCount = keys.filter(k => k.status === 'ACTIVE').length;
            badge.innerText = `${activeCount} ACTIVE KEYS`;
          }
          if (keys.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 2rem;">No API keys generated yet. Click \'+ Generate API Key\' to create a token for programmatic access.</td></tr>';
            return;
          }

          tbody.innerHTML = '';
          const isOperatorOrAdmin = window.__nexusedge_session &&
            (window.__nexusedge_session.role === 'PLATFORM_OPERATOR' || window.__nexusedge_session.role === 'TENANT_ADMIN');

          keys.forEach(k => {
            const tr = document.createElement('tr');

            // Name
            const tdName = document.createElement('td');
            const strongName = document.createElement('strong');
            strongName.textContent = k.name;
            tdName.appendChild(strongName);

            // Prefix
            const tdPrefix = document.createElement('td');
            tdPrefix.className = 'mono';
            tdPrefix.style.color = 'var(--accent-cyan)';
            tdPrefix.textContent = k.prefix || '-';

            // Role
            const tdRole = document.createElement('td');
            const spanRole = document.createElement('span');
            spanRole.className = k.role === 'PLATFORM_OPERATOR' ? 'badge badge-rose' : (k.role === 'TENANT_ADMIN' ? 'badge badge-amber' : 'badge badge-indigo');
            spanRole.textContent = k.role || 'DEVELOPER';
            tdRole.appendChild(spanRole);

            // Created At
            const tdCreated = document.createElement('td');
            tdCreated.className = 'mono';
            tdCreated.style.fontSize = '0.78rem';
            tdCreated.textContent = k.created_at ? new Date(k.created_at).toLocaleString() : '-';

            // Last Used
            const tdLastUsed = document.createElement('td');
            tdLastUsed.className = 'mono';
            tdLastUsed.style.fontSize = '0.78rem';
            tdLastUsed.textContent = k.last_used_at ? new Date(k.last_used_at).toLocaleString() : 'Never';

            // Status
            const tdStatus = document.createElement('td');
            const spanStatus = document.createElement('span');
            spanStatus.className = k.status === 'ACTIVE' ? 'badge badge-emerald' : 'badge badge-rose';
            spanStatus.textContent = k.status || 'ACTIVE';
            tdStatus.appendChild(spanStatus);

            // Actions
            const tdActions = document.createElement('td');
            if (k.status === 'ACTIVE' && isOperatorOrAdmin) {
              const btnRevoke = document.createElement('button');
              btnRevoke.className = 'btn btn-secondary btn-sm';
              btnRevoke.style.color = 'var(--accent-rose)';
              btnRevoke.style.borderColor = 'rgba(244, 63, 94, 0.4)';
              btnRevoke.textContent = 'Revoke';
              btnRevoke.onclick = () => revokeAPIKey(k.id);
              tdActions.appendChild(btnRevoke);
            } else {
              tdActions.textContent = '-';
            }

            tr.append(tdName, tdPrefix, tdRole, tdCreated, tdLastUsed, tdStatus, tdActions);
            tbody.appendChild(tr);
          });
          return;
        }
      } catch (err) {
        // BFF offline
      }
    }
    window.loadAPIKeys = loadAPIKeys;

    async function submitNewAPIKey() {
      const nameInput = document.getElementById('modal-key-name');
      const roleSelect = document.getElementById('modal-key-role');
      const name = (nameInput && nameInput.value.trim()) || 'Production API Key';
      const role = (roleSelect && roleSelect.value) || 'DEVELOPER';

      try {
        const resp = await fetch('/api/proxy/api-keys', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, role })
        });
        if (resp.ok) {
          const data = await resp.json();
          closeModal('modal-new-api-key');
          if (nameInput) nameInput.value = '';

          // Show revealed key modal
          const keyInput = document.getElementById('revealed-secret-key');
          if (keyInput) keyInput.value = data.secret_key;
          window.__last_generated_api_key = data.secret_key;
          openModal('modal-key-revealed');
          loadAPIKeys();
          populateQuickstartKeySelect();
          return;
        }
        const err = await resp.json();
        showToast(`Failed to generate key: ${err.error || 'Request rejected'}`);
      } catch (e) {
        showToast(`Network error generating key: ${e.message}`);
      }
    }
    window.submitNewAPIKey = submitNewAPIKey;

    function copyRevealedSecretKey() {
      const keyInput = document.getElementById('revealed-secret-key');
      if (keyInput && keyInput.value) {
        navigator.clipboard.writeText(keyInput.value).then(() => {
          showToast('API Secret Key copied to clipboard!');
        }).catch(() => {
          keyInput.select();
          document.execCommand('copy');
          showToast('API Secret Key copied to clipboard!');
        });
      }
    }
    window.copyRevealedSecretKey = copyRevealedSecretKey;

    async function revokeAPIKey(keyId) {
      if (!confirm('Are you sure you want to revoke this API key? Any applications using this key will immediately lose access.')) {
        return;
      }
      try {
        const resp = await fetch(`/api/proxy/api-keys/${encodeURIComponent(keyId)}`, {
          method: 'DELETE'
        });
        if (resp.ok) {
          showToast('API Key revoked successfully. Subsequent requests will be blocked.');
          loadAPIKeys();
          return;
        }
        const err = await resp.json();
        showToast(`Revocation failed: ${err.error || 'Request rejected'}`);
      } catch (e) {
        showToast(`Network error revoking key: ${e.message}`);
      }
    }
    window.revokeAPIKey = revokeAPIKey;

    // Developer Quickstart & Code Generator
    let activeQuickstartTab = 'curl';

    function switchQuickstartTab(lang) {
      activeQuickstartTab = lang;
      ['curl', 'ts', 'python'].forEach(tab => {
        const btn = document.getElementById(`qs-tab-${tab}`);
        if (btn) {
          if (tab === lang) {
            btn.classList.add('active');
          } else {
            btn.classList.remove('active');
          }
        }
      });
      renderQuickstartSnippets();
    }
    window.switchQuickstartTab = switchQuickstartTab;

    function populateQuickstartKeySelect() {
      const select = document.getElementById('qs-key-select');
      if (!select) return;

      const previousVal = select.value;
      select.innerHTML = '';

      if (window.__last_generated_api_key) {
        const opt = document.createElement('option');
        opt.value = window.__last_generated_api_key;
        opt.textContent = `${window.__last_generated_api_key.substring(0, 16)}... (Newly Generated Key)`;
        opt.selected = true;
        select.appendChild(opt);
      }

      if (window.__loaded_api_keys && window.__loaded_api_keys.length > 0) {
        window.__loaded_api_keys.forEach(k => {
          if (window.__last_generated_api_key && k.prefix && window.__last_generated_api_key.startsWith(k.prefix)) {
            return;
          }
          const opt = document.createElement('option');
          opt.value = `${k.prefix || 'nke_live'}...`;
          opt.textContent = `${k.name} (${k.prefix || 'key'}...) [${k.role}]`;
          select.appendChild(opt);
        });
      }

      if (select.children.length === 0) {
        const opt = document.createElement('option');
        opt.value = 'nke_live_your_api_key_here';
        opt.textContent = 'nke_live_your_api_key_here (Placeholder)';
        select.appendChild(opt);
      }

      if (previousVal && Array.from(select.options).some(o => o.value === previousVal)) {
        select.value = previousVal;
      }
    }
    window.populateQuickstartKeySelect = populateQuickstartKeySelect;

    function renderQuickstartSnippets() {
      const outputElem = document.getElementById('qs-code-output');
      if (!outputElem) return;

      const keySelect = document.getElementById('qs-key-select');
      const modelSelect = document.getElementById('qs-model-select');
      const stratSelect = document.getElementById('qs-strategy-select');
      const jurSelect = document.getElementById('qs-jurisdiction-select');

      const apiKey = (keySelect && keySelect.value) || 'nke_live_your_api_key_here';
      const model = (modelSelect && modelSelect.value) || 'meta-llama/Llama-3.3-70B-Instruct';
      const strategy = (stratSelect && stratSelect.value) || 'LATENCY_OPTIMAL';
      const jurisdiction = (jurSelect && jurSelect.value) || 'BD';
      const baseUrl = window.location.origin.includes('localhost') ? window.location.origin : 'https://dashboard.aeitron.com';

      let code = '';
      if (activeQuickstartTab === 'curl') {
        code = `# 1. Multi-Objective AI Inference (Zero-Cold-Start Ingress)
curl -X POST "${baseUrl}/api/proxy/inference" \\
  -H "Authorization: Bearer ${apiKey}" \\
  -H "Content-Type: application/json" \\
  -H "X-NexusEdge-Routing-Strategy: ${strategy}" \\
  -H "X-NexusEdge-Jurisdiction: ${jurisdiction}" \\
  -d '{
    "model": "${model}",
    "messages": [
      {"role": "system", "content": "You are a low-latency sovereign edge assistant."},
      {"role": "user", "content": "What is the optimal compute route for my request?"}
    ],
    "temperature": 0.7,
    "max_tokens": 512
  }'

# 2. Real-Time Telemetry & Rate Limit Inspection
curl -s "${baseUrl}/api/proxy/analytics/summary" \\
  -H "Authorization: Bearer ${apiKey}"`;
      } else if (activeQuickstartTab === 'ts') {
        code = `import { NexusEdgeClient } from '@nexusedge/api-client';

// Initialize zero-dependency strictly typed client
const client = new NexusEdgeClient({
  apiKey: '${apiKey}',
  baseUrl: '${baseUrl}',
  timeoutMs: 30000
});

async function run() {
  // 1. Multi-Objective AI Inference Placement
  const completion = await client.inference.createCompletion({
    model: '${model}',
    messages: [
      { role: 'system', content: 'You are a low-latency sovereign edge assistant.' },
      { role: 'user', content: 'What is the optimal compute route for my request?' }
    ],
    routingStrategy: '${strategy}',
    jurisdiction: '${jurisdiction}',
    temperature: 0.7,
    maxTokens: 512
  });

  console.log('Response Content:', completion.choices[0]?.message.content);
  console.log('Provider:', completion.telemetry.provider);
  console.log('TTFT:', completion.telemetry.ttftMs, 'ms');
  console.log('Cost: $' + completion.telemetry.cost);

  // 2. Query Real-Time Edge Telemetry
  const telemetry = await client.telemetry.getSummary();
  console.log('P99 Latency:', telemetry.p99_latency_ms, 'ms');
  console.log('Cache Hit Ratio:', (telemetry.cache_hit_ratio * 100).toFixed(1) + '%');
}

run().catch(console.error);`;
      } else if (activeQuickstartTab === 'python') {
        code = `from nexusedge import NexusEdgeClient

# Initialize zero-dependency standard-library client
client = NexusEdgeClient(
    api_key="${apiKey}",
    base_url="${baseUrl}",
    timeout_seconds=30.0
)

# 1. Multi-Objective AI Inference Placement
response = client.inference.create_completion(
    model="${model}",
    messages=[
        {"role": "system", "content": "You are a low-latency sovereign edge assistant."},
        {"role": "user", "content": "What is the optimal compute route for my request?"}
    ],
    routing_strategy="${strategy}",
    jurisdiction="${jurisdiction}",
    temperature=0.7,
    max_tokens=512
)

print("Response Content:", response.choices[0].message.content)
print(f"Provider: {response.telemetry.provider}")
print(f"TTFT: {response.telemetry.ttft_ms} ms")
print(f"Cost: \${response.telemetry.cost:.6f}")

# 2. Query Real-Time Edge Telemetry
telemetry = client.telemetry.get_summary()
print(f"P99 Latency: {telemetry.p99_latency_ms} ms")
print(f"Cache Hit Ratio: {telemetry.cache_hit_ratio * 100:.1f}%")`;
      }

      outputElem.textContent = code;
    }
    window.renderQuickstartSnippets = renderQuickstartSnippets;

    function copyQuickstartSnippet() {
      const outputElem = document.getElementById('qs-code-output');
      const btnText = document.getElementById('qs-copy-btn-text');
      if (!outputElem) return;

      const text = outputElem.textContent;
      navigator.clipboard.writeText(text).then(() => {
        if (btnText) btnText.textContent = 'COPIED!';
        showToast('Code snippet copied to clipboard');
        setTimeout(() => {
          if (btnText) btnText.textContent = 'Copy Code';
        }, 2000);
      }).catch(() => {
        showToast('Code snippet copied');
      });
    }
    window.copyQuickstartSnippet = copyQuickstartSnippet;

    async function runQuickstartTest() {
      const liveBox = document.getElementById('qs-live-box');
      const liveOutput = document.getElementById('qs-live-output');
      const liveBadges = document.getElementById('qs-live-badges');
      const modelSelect = document.getElementById('qs-model-select');
      const stratSelect = document.getElementById('qs-strategy-select');
      const jurSelect = document.getElementById('qs-jurisdiction-select');
      const runBtn = document.getElementById('qs-run-btn');

      if (!liveBox || !liveOutput) return;

      liveBox.style.display = 'block';
      liveOutput.textContent = 'Connecting to NexusEdge Global Gateway via /api/proxy/inference...\\nStreaming headers and payload...';
      if (liveBadges) liveBadges.innerHTML = '<span class="badge badge-bd">PROBING INGRESS...</span>';
      if (runBtn) runBtn.disabled = true;

      const startTime = performance.now();
      const model = (modelSelect && modelSelect.value) || 'meta-llama/Llama-3.3-70B-Instruct';
      const strategy = (stratSelect && stratSelect.value) || 'LATENCY_OPTIMAL';
      const jurisdiction = (jurSelect && jurSelect.value) || 'BD';

      try {
        const resp = await fetch('/api/proxy/inference', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-NexusEdge-Routing-Strategy': strategy,
            'X-NexusEdge-Jurisdiction': jurisdiction
          },
          body: JSON.stringify({
            model: model,
            messages: [
              { role: 'system', content: 'You are an edge inference testing probe.' },
              { role: 'user', content: 'Hello NexusEdge Edge Gateway! Verify routing.' }
            ],
            temperature: 0.7,
            max_tokens: 256
          })
        });

        const rtt = Math.round(performance.now() - startTime);
        const data = await resp.json();

        const provider = resp.headers.get('x-nexusedge-provider') || 'Autonomous Edge';
        const cost = resp.headers.get('x-nexusedge-cost') || '0.000000';
        const ttft = resp.headers.get('x-nexusedge-ttft-ms') || rtt;
        const region = resp.headers.get('x-nexusedge-region') || 'dhaka-bdix';

        if (liveBadges) {
          liveBadges.innerHTML = `
            <span class="badge badge-bd">\${region.toUpperCase()}</span>
            <span class="badge" style="background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald); border-color: rgba(16, 185, 129, 0.3);">\${resp.status} OK</span>
            <span class="badge" style="background: rgba(6, 182, 212, 0.15); color: var(--accent-cyan); border-color: rgba(6, 182, 212, 0.3);">\${rtt} ms RTT</span>
          `;
        }

        const out = {
          status: resp.status,
          rtt_ms: rtt,
          model: data.model || model,
          routing_telemetry: {
            provider: provider,
            region: region,
            ttft_ms: Number(ttft),
            estimated_cost_usd: Number(cost)
          },
          completion: data.choices?.[0]?.message?.content || data.message || '(No content returned)'
        };

        liveOutput.textContent = JSON.stringify(out, null, 2);
      } catch (err) {
        liveOutput.textContent = \`Request failed: \${err.message}\`;
        if (liveBadges) {
          liveBadges.innerHTML = '<span class="badge" style="background: rgba(244, 63, 94, 0.2); color: var(--accent-rose);">ERROR</span>';
        }
      } finally {
        if (runBtn) runBtn.disabled = false;
      }
    }
    window.runQuickstartTest = runQuickstartTest;

    // --- Engine 2 & 4: Sovereignty & Universal Workload Placement Engine ---
    async function loadSovereigntyData() {
      try {
        const res = await fetch('/api/proxy/workloads/nodes');
        if (!res.ok) return;
        const data = await res.json();
        const nodes = data.nodes || [];
        const tbody = document.getElementById('table-compute-nodes-body');
        if (tbody && nodes.length > 0) {
          tbody.innerHTML = '';
          nodes.forEach(n => {
            const tr = document.createElement('tr');

            const tdId = document.createElement('td');
            const codeId = document.createElement('code');
            codeId.textContent = n.node_id;
            tdId.appendChild(codeId);

            const tdProv = document.createElement('td');
            tdProv.textContent = n.provider;

            const tdReg = document.createElement('td');
            tdReg.textContent = n.region;

            const tdJuris = document.createElement('td');
            const spanJuris = document.createElement('span');
            spanJuris.className = n.jurisdiction === 'BD' ? 'badge badge-bd' : 'badge';
            spanJuris.textContent = n.jurisdiction;
            tdJuris.appendChild(spanJuris);

            const tdGpu = document.createElement('td');
            tdGpu.textContent = n.gpu_type;

            const tdCap = document.createElement('td');
            const spanCap = document.createElement('span');
            spanCap.className = 'text-emerald';
            spanCap.textContent = `${n.available_gpus} / ${n.total_gpus} GPUs`;
            tdCap.appendChild(spanCap);

            const tdCost = document.createElement('td');
            tdCost.textContent = `$${Number(n.cost_per_gpu_hour).toFixed(2)}`;

            const tdCarbon = document.createElement('td');
            if (n.carbon_intensity < 50) {
              const spanCarbon = document.createElement('span');
              spanCarbon.className = 'text-emerald';
              spanCarbon.textContent = `${n.carbon_intensity} gCO2/kWh (100% Green)`;
              tdCarbon.appendChild(spanCarbon);
            } else {
              tdCarbon.textContent = `${n.carbon_intensity} gCO2/kWh`;
            }

            tr.appendChild(tdId);
            tr.appendChild(tdProv);
            tr.appendChild(tdReg);
            tr.appendChild(tdJuris);
            tr.appendChild(tdGpu);
            tr.appendChild(tdCap);
            tr.appendChild(tdCost);
            tr.appendChild(tdCarbon);

            tbody.appendChild(tr);
          });
        }
        const totalNodesEl = document.getElementById('sov-total-nodes');
        if (totalNodesEl && nodes.length > 0) {
          const totalGPUs = nodes.reduce((sum, n) => sum + (n.total_gpus || 0), 0);
          totalNodesEl.textContent = `${nodes.length} Nodes / ${totalGPUs} GPUs`;
        }
      } catch (err) {
        console.warn('Failed to load compute nodes:', err);
      }
    }
    window.loadSovereigntyData = loadSovereigntyData;

    async function simulateWorkloadPlacement() {
      const btn = document.getElementById('btn-simulate-placement');
      const resultBox = document.getElementById('sim-result-box');
      if (btn) btn.disabled = true;

      const origin = document.getElementById('sim-client-origin')?.value || 'dhaka';
      const workloadType = document.getElementById('sim-workload-type')?.value || 'BANKING_API';
      const classification = document.getElementById('sim-classification')?.value || 'CII';
      const jurisdiction = document.getElementById('sim-jurisdiction')?.value || 'BD';
      const maxLatency = parseInt(document.getElementById('sim-max-latency')?.value || '150', 10);
      const gpus = parseInt(document.getElementById('sim-gpus')?.value || '1', 10);
      const strictSovereignty = document.getElementById('sim-strict-sovereignty')?.checked ?? true;
      const greenEnergy = document.getElementById('sim-green-energy')?.checked ?? false;

      const payload = {
        tenant_id: 'tenant-simulator',
        project_id: currentProjectId || 'proj-core',
        workload_id: `sim-${Date.now()}`,
        workload_type: workloadType,
        client_origin: origin,
        required_jurisdiction: jurisdiction === 'GLOBAL' ? '' : jurisdiction,
        strict_sovereignty: strictSovereignty,
        data_classification: classification,
        max_latency_p95_ms: maxLatency,
        max_cost_per_hour: 20.0,
        gpus_requested: gpus,
        prioritize_green_energy: greenEnergy
      };

      try {
        const res = await fetch('/api/proxy/workloads/schedule', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        const decision = await res.json();
        if (resultBox) {
          resultBox.style.display = 'block';

          const badgeEl = document.getElementById('sim-res-badge');
          const nodeEl = document.getElementById('sim-res-node');
          const certEl = document.getElementById('sim-res-cert');
          const rttEl = document.getElementById('sim-res-rtt');
          const costEl = document.getElementById('sim-res-cost');
          const carbonEl = document.getElementById('sim-res-carbon');
          const jurisEl = document.getElementById('sim-res-jurisdiction');
          const reasonEl = document.getElementById('sim-res-reason');

          if (decision.status === 'SCHEDULED') {
            if (badgeEl) {
              badgeEl.className = 'badge';
              badgeEl.style.background = 'rgba(16, 185, 129, 0.2)';
              badgeEl.style.color = 'var(--accent-emerald)';
              badgeEl.textContent = 'SCHEDULED';
            }
            if (nodeEl) nodeEl.textContent = decision.assigned_node || 'Assigned';
            if (certEl) {
              if (decision.jurisdiction === 'BD') {
                certEl.className = 'badge badge-bd';
                certEl.textContent = 'BD-CII SOVEREIGN PINNED';
              } else if (decision.jurisdiction === 'EU' || decision.jurisdiction === 'IS') {
                certEl.className = 'badge';
                certEl.style.background = 'rgba(59, 130, 246, 0.2)';
                certEl.style.color = 'var(--accent-cyan)';
                certEl.textContent = 'EU-GDPR COMPLIANT';
              } else {
                certEl.className = 'badge';
                certEl.style.background = 'rgba(148, 163, 184, 0.2)';
                certEl.style.color = 'var(--text-muted)';
                certEl.textContent = `${decision.jurisdiction || 'GLOBAL'} ANYCAST`;
              }
            }
            if (rttEl) rttEl.textContent = `${decision.measured_rtt_ms || 0} ms`;
            if (costEl) costEl.textContent = `$${Number(decision.hourly_cost || 0).toFixed(2)} / h`;
            if (carbonEl) carbonEl.textContent = `${decision.carbon_gco2_kwh || 0} gCO2/kWh (${decision.carbon_classification || 'GRID'})`;
            if (jurisEl) jurisEl.textContent = `${decision.jurisdiction || 'GLOBAL'} (${decision.region || 'Anycast'})`;
            if (reasonEl) reasonEl.textContent = decision.reason || 'Placement calculated successfully.';
          } else {
            if (badgeEl) {
              badgeEl.className = 'badge';
              badgeEl.style.background = 'rgba(244, 63, 94, 0.2)';
              badgeEl.style.color = 'var(--accent-rose)';
              badgeEl.textContent = 'UNSCHEDULABLE';
            }
            if (nodeEl) nodeEl.textContent = 'NO NODE AVAILABLE';
            if (certEl) {
              certEl.className = 'badge';
              certEl.style.background = 'rgba(244, 63, 94, 0.2)';
              certEl.style.color = 'var(--accent-rose)';
              certEl.textContent = 'SLA / SOVEREIGNTY BREACH';
            }
            if (rttEl) rttEl.textContent = 'FAIL';
            if (costEl) costEl.textContent = 'N/A';
            if (carbonEl) carbonEl.textContent = 'N/A';
            if (jurisEl) jurisEl.textContent = 'REJECTED';
            if (reasonEl) reasonEl.textContent = decision.reason || decision.error || 'No available compute node satisfies constraints or capacity exhausted.';
          }
        }
      } catch (err) {
        showToast(`Simulation error: ${err.message}`);
      } finally {
        if (btn) btn.disabled = false;
      }
    }
    window.simulateWorkloadPlacement = simulateWorkloadPlacement;

    window.openDomainDnsModal = openDomainDnsModal;
    window.copyDnsWizardTarget = copyDnsWizardTarget;
    window.copyDnsWizardToken = copyDnsWizardToken;
    window.triggerWizardVerify = triggerWizardVerify;
    window.verifyDomain = verifyDomain;
    window.deleteDomain = deleteDomain;
    window.loadAnalytics = loadAnalytics;

    // --- Sovereign S3 Object Storage Management ---
    async function loadStorageBuckets() {
      const tbody = document.getElementById('storage-buckets-tbody');
      if (!tbody) return;

      try {
        const res = await fetch('/api/proxy/storage/buckets');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const buckets = data.buckets || [];

        const totalVolEl = document.getElementById('storage-total-volume');
        const activeBucketsEl = document.getElementById('storage-active-buckets');
        if (activeBucketsEl) activeBucketsEl.textContent = buckets.length;

        let totalBytes = 0;
        buckets.forEach(b => { totalBytes += (b.stored_bytes || 0); });
        if (totalVolEl) {
          if (totalBytes > 1073741824) {
            totalVolEl.textContent = (totalBytes / 1073741824).toFixed(2) + ' GB';
          } else {
            totalVolEl.textContent = (totalBytes / 1048576).toFixed(1) + ' MB';
          }
        }

        if (buckets.length === 0) {
          tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">No storage buckets provisioned. Click "+ New Bucket" to create an S3 bucket.</td></tr>';
          return;
        }

        tbody.innerHTML = buckets.map(b => {
          let badgeClass = 'badge-emerald';
          if (b.sovereignty_policy === 'BD_ONLY') badgeClass = 'badge-amber';
          else if (b.sovereignty_policy === 'EU_ONLY') badgeClass = 'badge-cyan';

          const storedFormatted = b.stored_bytes > 1073741824 
            ? (b.stored_bytes / 1073741824).toFixed(2) + ' GB' 
            : (b.stored_bytes / 1048576).toFixed(1) + ' MB';

          return `
            <tr>
              <td class="mono"><strong>${escapeHtml(b.name)}</strong></td>
              <td>${escapeHtml(b.primary_region)}</td>
              <td>${escapeHtml(b.replication_topology)}</td>
              <td><span class="badge ${badgeClass}">${escapeHtml(b.sovereignty_policy)}</span></td>
              <td>${storedFormatted} (${b.object_count || 0} objects)</td>
              <td><span class="badge badge-emerald">${escapeHtml(b.status || 'ACTIVE')}</span></td>
              <td>
                <button class="btn btn-secondary btn-sm" onclick="deleteStorageBucket('${escapeHtml(b.name)}')">Delete</button>
              </td>
            </tr>
          `;
        }).join('');
      } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--accent-rose); padding: 20px;">Failed to load storage buckets: ${escapeHtml(err.message)}</td></tr>`;
      }
    }
    window.loadStorageBuckets = loadStorageBuckets;

    async function submitCreateStorageBucket() {
      const nameInput = document.getElementById('new-bucket-name');
      const sovInput = document.getElementById('new-bucket-sovereignty');
      const topInput = document.getElementById('new-bucket-topology');
      const regInput = document.getElementById('new-bucket-region');
      const quotaInput = document.getElementById('new-bucket-quota');
      const errBanner = document.getElementById('new-bucket-error');
      const submitBtn = document.getElementById('btn-create-bucket-submit');

      const name = nameInput ? nameInput.value.trim() : '';
      if (!name) {
        if (errBanner) {
          errBanner.textContent = 'Bucket name is required';
          errBanner.style.display = 'block';
        }
        return;
      }

      if (errBanner) errBanner.style.display = 'none';
      if (submitBtn) submitBtn.disabled = true;

      try {
        const quotaGB = quotaInput ? parseInt(quotaInput.value, 10) || 50 : 50;
        const res = await fetch('/api/proxy/storage/buckets', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: name,
            sovereignty_policy: sovInput ? sovInput.value : 'GLOBAL_REDUNDANT',
            replication_topology: topInput ? topInput.value : 'SINGLE_REGION_NVME',
            primary_region: regInput ? regInput.value : 'ap-south-2',
            max_size_bytes: quotaGB * 1024 * 1024 * 1024,
          })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to create bucket');

        closeModal('modal-new-bucket');
        if (nameInput) nameInput.value = '';
        showToast(`Bucket "${data.name}" provisioned at ${data.primary_region} successfully.`);
        loadStorageBuckets();
      } catch (err) {
        if (errBanner) {
          errBanner.textContent = err.message;
          errBanner.style.display = 'block';
        }
      } finally {
        if (submitBtn) submitBtn.disabled = false;
      }
    }
    window.submitCreateStorageBucket = submitCreateStorageBucket;

    async function deleteStorageBucket(name) {
      if (!confirm(`Are you sure you want to delete bucket "${name}"? This action cannot be undone.`)) {
        return;
      }

      try {
        const res = await fetch(`/api/proxy/storage/buckets/${encodeURIComponent(name)}`, {
          method: 'DELETE'
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to delete bucket');

        showToast(`Bucket "${name}" deleted.`);
        loadStorageBuckets();
      } catch (err) {
        showToast(`Delete failed: ${err.message}`);
      }
    }
    window.deleteStorageBucket = deleteStorageBucket;

    // --- Subsea Cable Telemetry & BGP Steering ---
    async function loadSubseaCables() {
      const tbody = document.getElementById('subsea-cables-tbody');
      const badge = document.getElementById('cables-active-badge');
      if (!tbody) return;

      try {
        const res = await fetch('/api/proxy/network/cables');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const cables = data.cables || [];

        let offlineCount = 0;
        cables.forEach(c => {
          if (c.status !== 'ONLINE') offlineCount++;
        });

        if (badge) {
          if (offlineCount === 0) {
            badge.className = 'badge badge-emerald';
            badge.textContent = `${cables.length}/${cables.length} FIBER RINGS NOMINAL`;
          } else {
            badge.className = 'badge badge-rose';
            badge.textContent = `${offlineCount} CABLE SEVERED (BGP REROUTED)`;
          }
        }

        if (cables.length === 0) {
          tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 20px;">No cables monitored.</td></tr>';
          return;
        }

        tbody.innerHTML = cables.map(c => {
          const isOnline = c.status === 'ONLINE';
          const statusBadge = isOnline 
            ? '<span class="badge badge-emerald">ONLINE</span>' 
            : '<span class="badge badge-rose">SEVERED</span>';

          const landingPointsStr = (c.landing_points || []).join(' &harr; ');
          const latencyDisplay = isOnline
            ? `<span class="text-emerald">${c.current_latency_ms.toFixed(1)} ms</span>`
            : `<span class="text-rose font-bold">${c.current_latency_ms.toFixed(1)} ms</span>`;

          const actionBtn = isOnline
            ? `<button class="btn btn-secondary btn-sm" onclick="simulateCableAction('${c.id}', 'cut')">Simulate Fiber Break</button>`
            : `<button class="btn btn-primary btn-sm" onclick="simulateCableAction('${c.id}', 'restore')">Restore Nominal</button>`;

          return `
            <tr>
              <td class="mono"><strong>${escapeHtml(c.name)}</strong><br><span style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(c.id)}</span></td>
              <td>${landingPointsStr}</td>
              <td class="mono">${(c.capacity_gbps / 1000).toFixed(0)} Tbps</td>
              <td>${c.normal_latency_ms.toFixed(1)} ms</td>
              <td>${latencyDisplay}</td>
              <td><span class="badge badge-subtle">${c.active_bgp_paths} paths</span></td>
              <td><span style="font-size: 0.78rem; color: var(--accent-amber);">${escapeHtml(c.alternate_route)}</span></td>
              <td>${statusBadge}</td>
              <td>${actionBtn}</td>
            </tr>
          `;
        }).join('');
      } catch (err) {
        tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--accent-rose); padding: 20px;">Failed to load cables: ${escapeHtml(err.message)}</td></tr>`;
      }
    }
    window.loadSubseaCables = loadSubseaCables;

    async function simulateCableAction(cableId, action) {
      try {
        const res = await fetch(`/api/proxy/network/cables/${encodeURIComponent(cableId)}/${action}`, {
          method: 'POST'
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `Failed to ${action} cable`);

        showToast(data.message || `Cable ${cableId} ${action} executed.`);
        loadSubseaCables();
        loadPoPTelemetry();
      } catch (err) {
        showToast(`Cable action failed: ${err.message}`);
      }
    }
    window.simulateCableAction = simulateCableAction;

    // Initial Dashboard Bootstrap
    initSessionContext();
    checkControlPlaneHealth();
    loadDomains();
    loadPoPs();
    loadPoPTelemetry();
    loadSubseaCables();
    loadLatencyMatrix();
    loadAnalytics();
    fetchAuditLogs();
    loadAPIKeys();
    loadStorageBuckets();
    setInterval(checkControlPlaneHealth, 15000);
