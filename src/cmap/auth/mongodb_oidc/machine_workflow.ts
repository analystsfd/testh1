import { type Document } from 'bson';

import { ns } from '../../../utils';
import type { Connection } from '../../connection';
import type { MongoCredentials } from '../mongo_credentials';
import type { Workflow } from '../mongodb_oidc';
import { finishCommandDocument } from './command_builders';

/**
 * Common behaviour for OIDC machine workflows.
 * @internal
 */
export abstract class MachineWorkflow implements Workflow {
  /**
   * Execute the workflow. Gets the token from the subclass implementation.
   */
  async execute(connection: Connection, credentials: MongoCredentials): Promise<Document> {
    const token = await this.getToken(credentials);
    const command = finishCommandDocument(token);
    return connection.commandAsync(ns(credentials.source), command, undefined);
  }

  /**
   * Reauthenticate on a machine workflow just grabs the token again since the server
   * has said the current access token is invalid or expired.
   */
  async reauthenticate(connection: Connection, credentials: MongoCredentials): Promise<Document> {
    return this.execute(connection, credentials);
  }

  /**
   * Get the document to add for speculative authentication.
   */
  async speculativeAuth(credentials: MongoCredentials): Promise<Document> {
    const token = await this.getToken(credentials);
    const document = finishCommandDocument(token);
    document.db = credentials.source;
    return { speculativeAuthenticate: document };
  }

  /**
   * Get the token from the environment or endpoint.
   */
  abstract getToken(credentials: MongoCredentials): Promise<string>;
}
