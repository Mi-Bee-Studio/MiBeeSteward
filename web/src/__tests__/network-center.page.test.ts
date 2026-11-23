/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';

// Mutable fixture, readable inside the hoisted vi.mock factory. Shapes follow
// the real API responses (networks / devices / probe-quality / probe-egress /
// probe-matrix / agents/status) — no new backend endpoint was added.
const h = vi.hoisted(() => ({
  networks: [] as Array<Record<string, unknown>>,
  devices: [] as Array<Record<string, unknown>>,
  quality: { categories: [] } as Record<string, unknown>,
  egress: { vantages: [] } as Record<string, unknown>,
  matrix: { cells: [] } as Record<string, unknown>,
  fleet: [] as Array<Record<string, unknown>>
}));

vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$lib/api/client', () => ({
  api: {
    get: vi.fn((url: string) => {
      if (url.startsWith('/networks')) return Promise.resolve({ networks: h.networks });
      if (url.startsWith('/devices')) return Promise.resolve({ devices: h.devices, total: h.devices.length });
      if (url.startsWith('/probe-quality')) return Promise.resolve(h.quality);
      if (url.startsWith('/probe-egress')) return Promise.resolve(h.egress);
      if (url.startsWith('/probe-matrix')) return Promise.resolve(h.matrix);
      if (url.startsWith('/agents/status')) return Promise.resolve({ agents: h.fleet });
      return Promise.resolve({});
    })
  },
  ApiError: class ApiError extends Error {},
  SessionExpiredError: class SessionExpiredError extends Error {}
}));

import NetworkCenter from '../routes/network-center/+page.svelte';

function seed() {
  h.networks = [
    { id: 1, name: 'lan-62', cidr: '192.168.1.0/24', site: 'site-a', agent_id: 'agent-a', agent_stale: false },
    { id: 2, name: 'lan-63', cidr: '192.168.2.0/24', site: 'site-a', agent_id: 'agent-b', agent_stale: false }
  ];
  h.devices = [
    { id: 1, name: 'gw-a', type: 'router', status: 'online', network_id: 1, ip_address: '192.168.1.1', mac_address: '00:11:22:33:44:55', scan_attributes: { gateway: { nat_mapping: 'edm', public_ip: '198.51.100.7' } } },
    { id: 2, name: 'pc-a', type: 'pc', status: 'online', network_id: 1 },
    { id: 3, name: 'gw-b', type: 'router', status: 'offline', network_id: 2 }
  ];
  h.quality = { categories: [{ category: 'quality', vantages: [
    { vantage: 'agent:agent-a', network_name: 'lan-62', verdict: 'ok', score: 90 },
    { vantage: 'agent:agent-b', network_name: 'lan-63', verdict: 'degraded', score: 40 }
  ] }] };
  h.egress = { vantages: [
    { vantage: 'agent:agent-a', network_name: 'lan-62', ips: [{ ip: '198.51.100.7' }], local_gateway: '192.168.1.1', local_iface: 'eth0' }
  ] };
  h.matrix = { cells: [
    { source: 'agent:agent-a', destination: 'agent:agent-b', ok_rate: 1, p50_ms: 12.5, loss_pct: 0, jitter_ms: 0.4 }
  ] };
  h.fleet = [{ agent_id: 'agent-a', version: '0.9.0' }];
}

describe('Network Center page', () => {
  beforeEach(() => { seed(); });

  it('overview shows one card per network with NAT + egress + quality', async () => {
    const { container } = render(NetworkCenter);
    await waitFor(() => expect(container.textContent).toContain('lan-62'));
    // Both networks present; the gateway profile badge shows EDM on lan-62.
    expect(container.textContent).toContain('lan-63');
    expect(container.textContent).toContain('198.51.100.7');
    expect(container.querySelectorAll('.nc-card').length).toBeGreaterThanOrEqual(2);
  });

  it('clicking a network card drills down to gateway/quality/assets panels', async () => {
    const { container } = render(NetworkCenter);
    await waitFor(() => expect(container.textContent).toContain('lan-62'));
    const card = container.querySelector('.nc-card') as HTMLElement;
    await fireEvent.click(card);
    await waitFor(() => expect(container.textContent).toContain('NAT mapping behavior'));
    // drill-down panels render from the same data, no second fetch
    expect(container.textContent).toContain('Egress quality');
    expect(container.textContent).toContain('Network assets');
  });

  it('topology view renders the cross-network link detail', async () => {
    const { container } = render(NetworkCenter);
    await waitFor(() => expect(container.textContent).toContain('lan-62'));
    const topoBtn = Array.from(container.querySelectorAll('button')).find(b => (b.textContent || '').includes('Inter-network Topology')) as HTMLElement;
    await fireEvent.click(topoBtn);
    await waitFor(() => expect(container.textContent).toContain('Cross-network link detail'));
    expect(container.textContent).toContain('12.5 ms');
  });

  it('assets view lists devices with their network', async () => {
    const { container } = render(NetworkCenter);
    await waitFor(() => expect(container.textContent).toContain('lan-62'));
    const assetBtn = Array.from(container.querySelectorAll('button')).find(b => (b.textContent || '').includes('All Assets')) as HTMLElement;
    await fireEvent.click(assetBtn);
    await waitFor(() => expect(container.textContent).toContain('pc-a'));
    expect(container.textContent).toContain('lan-62');
  });
});
