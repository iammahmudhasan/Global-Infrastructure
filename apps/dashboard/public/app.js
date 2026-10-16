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
        loadAPIKeys();
      }
      if (viewId === 'domains') {
        loadDomains();
      }
      if (viewId === 'servers') {
        loadPoPs();
        loadPoPTelemetry();
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
          openModal('modal-key-revealed');
          loadAPIKeys();
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

    window.openDomainDnsModal = openDomainDnsModal;
    window.copyDnsWizardTarget = copyDnsWizardTarget;
    window.copyDnsWizardToken = copyDnsWizardToken;
    window.triggerWizardVerify = triggerWizardVerify;
    window.verifyDomain = verifyDomain;
    window.deleteDomain = deleteDomain;
    window.loadAnalytics = loadAnalytics;

    // Initial Dashboard Bootstrap
    initSessionContext();
    checkControlPlaneHealth();
    loadDomains();
    loadPoPs();
    loadPoPTelemetry();
    loadLatencyMatrix();
    loadAnalytics();
    fetchAuditLogs();
    loadAPIKeys();
    setInterval(checkControlPlaneHealth, 15000);
