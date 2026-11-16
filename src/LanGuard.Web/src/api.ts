export type Session = { login: string; role: string; demo: boolean };
export type Overview = { devices: number; online: number; unverified: number; detections: number; active: number; eventsToday: number };
export type Page<T> = { total: number; items: T[] };
export type Evidence = {
  observation: { kind: string; name: string; path?: string; publisher?: string; version?: string };
  matchedFields: string[];
};
export type Detection = {
  familyId: string;
  productFamily: string;
  category: string;
  confidence: string;
  currentlyRunning: boolean | null;
  version?: string;
  lastSeen: string;
  evidence: Evidence[];
};
export type Device = {
  id: string;
  hostname: string;
  addresses: string[];
  os: string;
  hasAgent: boolean;
  online: boolean;
  auditStatus: string;
  result: string;
  lastHeartbeat: string | null;
  lastScanAt: string | null;
  detections: Detection[];
};
export type DetectionRow = { id: string; hostname: string; detection: Detection };
export type History = { id: string; deviceId: string; familyId: string | null; type: string; occurredAt: string };
export type Detail = {
  device: Device;
  agentVersion: string;
  coverage: { source: string; status: string; entries: number; reason?: string }[];
  events: History[];
};

export class ApiError extends Error {
  constructor(readonly status: number) {
    super(status === 429 ? 'Слишком много запросов. Повторите через минуту.' :
      status === 401 ? 'Требуется вход в систему.' : 'Запрос не выполнен. Попробуйте ещё раз.');
  }
}

export async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch('/api/v1' + path, { ...options, credentials: 'same-origin' });
  if (!response.ok) throw new ApiError(response.status);
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export async function mutate<T>(path: string, payload: object = {}): Promise<T> {
  const { token } = await api<{ token: string }>('/auth/csrf');
  return api<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
    body: JSON.stringify(payload),
  });
}
