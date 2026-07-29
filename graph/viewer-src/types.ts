/** Defines the validated payload, derived graph indexes, and mutable state shared by the viewer modules. */

export type NodeId = string;
export type ViewerMode = "static" | "live";
export type Theme = "system" | "light" | "dark";

export interface Point {
  x: number;
  y: number;
}

export interface GraphNodeInput {
  id: string;
  kind: string;
  label?: string;
  x?: number;
  y?: number;
  properties?: Record<string, unknown>;
}

export interface ViewerNode extends GraphNodeInput {
  x: number;
  y: number;
  properties: Record<string, unknown>;
}

export interface GraphEdge {
  source: NodeId;
  target: NodeId;
  kind: string;
  properties?: Record<string, unknown>;
}

export interface GraphPayload {
  metadata?: Record<string, unknown>;
  graph: {
    nodes: GraphNodeInput[];
    edges: GraphEdge[];
  };
}

export interface ViewerOptions {
  mode?: ViewerMode;
  apiBaseUrl?: string;
}

export interface KindMeta {
  color: string;
  count: number;
  label: string;
}

export interface EdgeMeta {
  count: number;
  label: string;
  traversable: boolean;
}

export interface OutgoingEdge {
  target: NodeId;
  edge: GraphEdge;
}

export interface IncomingEdge {
  source: NodeId;
  edge: GraphEdge;
}

/** Holds normalized graph data plus the indexes that keep rendering and traversal consistent. */
export interface GraphModel {
  payload: GraphPayload;
  nodes: ViewerNode[];
  edges: GraphEdge[];
  links: GraphEdge[];
  nodeById: Map<NodeId, ViewerNode>;
  degreeById: Map<NodeId, number>;
  searchTextById: Map<NodeId, string>;
  kindMeta: Map<string, KindMeta>;
  edgeMeta: Map<string, EdgeMeta>;
  outgoing: Map<NodeId, OutgoingEdge[]>;
  incoming: Map<NodeId, IncomingEdge[]>;
}

/** Represents one directed traversal result in both set and ordered forms for rendering. */
export interface PathResult {
  nodeIds: Set<NodeId>;
  linkKeys: Set<string>;
  orderedNodeIds: NodeId[];
}

export interface VisibilityResult {
  nodeIds: Set<NodeId>;
  linkIndexes: Set<number>;
}

/** Owns all mutable viewer state so actions can update the UI through one model. */
export interface ViewerState {
  graph: GraphModel;
  filters: {
    activeNodeKinds: Set<string>;
    activeEdgeKinds: Set<string>;
    searchTerm: string;
    attackPathsOnly: boolean;
    vulnerabilitiesOnly: boolean;
  };
  selection: {
    selectedId: NodeId | null;
    hoveredId: NodeId | null;
    pinnedId: NodeId | null;
    focusedId: NodeId | null;
    path: {
      active: boolean;
      sourceId: NodeId | null;
      targetId: NodeId | null;
      result: PathResult | null;
    };
    clustered: boolean;
    showLabels: boolean;
  };
  viewport: {
    transform: {x: number; y: number; k: number};
    width: number;
    height: number;
    devicePixelRatio: number;
  };
  pointer: {
    draggedId: NodeId | null;
    dragOffset: Point;
    panning: boolean;
    panStart: Point;
    mouseDown: Point;
    didDrag: boolean;
    suppressClick: boolean;
  };
  render: {
    dirty: boolean;
    frameRequested: boolean;
    visibleNodeIds: Set<NodeId>;
    visibleLinkIndexes: Set<number>;
  };
  live: {
    enabled: boolean;
    apiBaseUrl: string;
    refreshGeneration: number;
  };
}

export interface QueryDescriptor {
  id: string;
  name: string;
  purpose: string;
  category: string;
  severity: string;
}

export interface QueryResult {
  rows: Record<string, unknown>[];
  columns: string[];
  count: number;
  truncated: boolean;
}

export interface TierResponse {
  tier0: number;
  tier1: number;
  tier2: number;
  total: number;
}

export interface OwnedItem {
  name: string;
}

export interface OwnedListResponse {
  owned: OwnedItem[];
  count: number;
}
