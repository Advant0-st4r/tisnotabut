export interface User {
  id: string;
  email: string;
  role: string;
}

export interface Capability {
  id: string;
  name: string;
  domain: string;
  maturity_level: number;
}

export interface Metric {
  name: string;
  value: number;
  unit: string;
  trend: 'up' | 'down' | 'stable';
}

export interface InteractionEvent {
  userId: string;
  eventType: string;
  entityType: string;
  entityId: string;
  metadata: any;
}