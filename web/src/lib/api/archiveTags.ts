/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later; see LICENSE for the full text. A commercial
 * license is available for use cases the AGPL does not accommodate; see
 * LICENSE-COMMERCIAL.md.
 */

import { api } from './client';

// --- Asset archive (#663/#666) ---

export interface ArchiveItem {
	id: number;
	name: string;
	type: string;
	brand: string;
	model: string;
	ip_address: string;
	mac_address: string;
	status: string;
	archived_at: string;
	archive_pin: string;
	online_since?: string | null;
	offline_since?: string | null;
	periodic: boolean;
	periodic_cycle_days?: number;
	scan_source: string;
	network_id?: number | null;
	network_name?: string;
	created_at: string;
}

export interface DossierEntry {
	kind: 'archive_event' | 'change' | 'config' | 'cert' | 'document' | 'sighting';
	occurred_at: string;
	summary: string;
	data?: Record<string, unknown>;
}

export function listArchive(limit: number, offset: number) {
	return api.get<{ devices: ArchiveItem[]; total: number; limit: number; offset: number }>(
		`/archive?limit=${limit}&offset=${offset}`
	);
}

export function getDossier(id: number, limit = 150) {
	return api.get<{ entries: DossierEntry[] }>(`/archive/${id}/dossier?limit=${limit}`);
}

export function archiveDevice(id: number, reason = '') {
	return api.post<{ ok: boolean }>(`/devices/${id}/archive`, reason ? { reason } : {});
}

export function restoreDevice(id: number, force = false) {
	return api.post<{ ok: boolean }>(`/devices/${id}/restore`, { force });
}

export function putArchiveSettings(
	id: number,
	body: { pin?: string; offline_days_override?: number }
) {
	return api.put<{ ok: boolean }>(`/devices/${id}/archive-settings`, body);
}

// --- Tag dictionary (#665) ---

export interface Tag {
	id: number;
	key: string;
	name: string;
	color: string;
	description: string;
	builtin: number;
	sort_order: number;
	created_at: string;
	updated_at: string;
}

export interface TagBrief {
	id: number;
	key: string;
	name: string;
	color: string;
	builtin: boolean;
}

export function listTags() {
	return api.get<{ tags: Tag[] }>('/tags');
}

export function createTag(body: { key: string; name: string; color?: string; description?: string }) {
	return api.post<Tag>('/tags', body);
}

export function updateTag(id: number, body: { name: string; color?: string; description?: string; sort_order?: number }) {
	return api.put<Tag>(`/tags/${id}`, body);
}

export function deleteTag(id: number) {
	return api.delete<void>(`/tags/${id}`);
}

export function bulkAssignTag(tagID: number, deviceIDs: number[]) {
	return api.post<{ applied: number }>(`/tags/${tagID}/devices`, { device_ids: deviceIDs });
}

export function replaceDeviceTags(deviceID: number, tagIDs: number[]) {
	return api.put<{ ok: boolean }>(`/devices/${deviceID}/tags`, { tag_ids: tagIDs });
}
