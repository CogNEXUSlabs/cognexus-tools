declare module "n8n-workflow" {
  export const NodeConnectionTypes: { readonly Main: "main" };

  export class NodeOperationError extends Error {
    constructor(node: unknown, error: unknown, extra?: object);
  }

  export interface IDataObject {
    [key: string]: unknown;
  }

  export interface INodeExecutionData {
    json: IDataObject;
    pairedItem?: { item: number };
    error?: unknown;
  }

  export interface IExecuteFunctions {
    getInputData(): INodeExecutionData[];
    getNodeParameter(name: string, itemIndex: number, fallback?: unknown): unknown;
    getCredentials(name: string): Promise<Record<string, string>>;
    continueOnFail(): boolean;
    getNode(): unknown;
    /** Present on every current n8n; optional here so callers guard it. */
    getExecutionId?(): string;
  }

  export interface INodeType {
    description: INodeTypeDescription;
    execute?(this: IExecuteFunctions): Promise<INodeExecutionData[][]>;
  }

  export interface INodeTypeDescription {
    displayName: string;
    name: string;
    icon?: unknown;
    group: string[];
    version: number;
    description: string;
    defaults: { name: string };
    inputs: unknown;
    outputs: unknown;
    outputNames?: string[];
    credentials?: Array<{ name: string; required?: boolean }>;
    properties: INodeProperties[];
    usableAsTool?: boolean;
  }

  export interface INodeProperties {
    displayName: string;
    name: string;
    type: string;
    default: unknown;
    [key: string]: unknown;
  }

  export interface ICredentialType {
    name: string;
    displayName: string;
    documentationUrl?: string;
    properties: INodeProperties[];
    authenticate?: unknown;
    test?: unknown;
  }
}
