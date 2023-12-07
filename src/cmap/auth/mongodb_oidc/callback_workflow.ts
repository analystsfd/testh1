import { BSON, type Document } from 'bson';

import { MongoMissingCredentialsError } from '../../../error';
import { ns } from '../../../utils';
import type { Connection } from '../../connection';
import type { MongoCredentials } from '../mongo_credentials';
import type {
  IdPServerInfo,
  IdPServerResponse,
  OIDCRequestFunction,
  OIDCTokenParams,
  Workflow
} from '../mongodb_oidc';
import { finishCommandDocument, startCommandDocument } from './command_builders';

/** The current version of OIDC implementation. */
const OIDC_VERSION = 1;

/** 5 minutes in seconds */
const TIMEOUT_S = 300;

/** Properties allowed on results of callbacks. */
const RESULT_PROPERTIES = ['accessToken', 'expiresInSeconds', 'refreshToken'];

/** Error message when the callback result is invalid. */
const CALLBACK_RESULT_ERROR =
  'User provided OIDC callbacks must return a valid object with an accessToken.';

const NO_REQUEST_CALLBACK = 'No OIDC_TOKEN_CALLBACK provided for callback workflow.';

/**
 * OIDC implementation of a callback based workflow.
 * @internal
 */
export class CallbackWorkflow implements Workflow {
  /**
   * Get the document to add for speculative authentication. This also needs
   * to add a db field from the credentials source.
   */
  async speculativeAuth(credentials: MongoCredentials): Promise<Document> {
    const document = startCommandDocument(credentials);
    document.db = credentials.source;
    return { speculativeAuthenticate: document };
  }

  /**
   * Reauthenticate the callback workflow.
   * For reauthentication:
   * - Check if the connection's accessToken is not equal to the token manager's.
   *   - If they are different, use the token from the manager and set it on the connection and finish auth.
   *     - On success return, on error continue.
   * - start auth to update the IDP information
   *   - If the idp info has changed, clear access token and refresh token.
   *   - If the idp info has not changed, attempt to use the refresh token.
   * - if there's still a refresh token at this point, attempt to finish auth with that.
   * - Attempt the full auth run, on error, raise to user.
   */
  async reauthenticate(connection: Connection, credentials: MongoCredentials): Promise<Document> {
    return this.execute(connection, credentials);
  }

  /**
   * Execute the OIDC callback workflow.
   */
  async execute(
    connection: Connection,
    credentials: MongoCredentials,
    response?: Document
  ): Promise<Document> {
    const requestCallback = credentials.mechanismProperties.OIDC_TOKEN_CALLBACK;
    if (!requestCallback) {
      throw new MongoMissingCredentialsError(NO_REQUEST_CALLBACK);
    }
    const startDocument = await this.startAuthentication(connection, credentials, response);
    const conversationId = startDocument.conversationId;
    const serverResult = BSON.deserialize(startDocument.payload.buffer) as IdPServerInfo;
    const tokenResult = await this.fetchAccessToken(
      connection,
      credentials,
      serverResult,
      requestCallback
    );
    const result = await this.finishAuthentication(
      connection,
      credentials,
      tokenResult,
      conversationId
    );
    return result;
  }

  /**
   * Starts the callback authentication process. If there is a speculative
   * authentication document from the initial handshake, then we will use that
   * value to get the issuer, otherwise we will send the saslStart command.
   */
  private async startAuthentication(
    connection: Connection,
    credentials: MongoCredentials,
    response?: Document
  ): Promise<Document> {
    let result;
    if (response?.speculativeAuthenticate) {
      result = response.speculativeAuthenticate;
    } else {
      result = await connection.commandAsync(
        ns(credentials.source),
        startCommandDocument(credentials),
        undefined
      );
    }
    return result;
  }

  /**
   * Finishes the callback authentication process.
   */
  private async finishAuthentication(
    connection: Connection,
    credentials: MongoCredentials,
    tokenResult: IdPServerResponse,
    conversationId?: number
  ): Promise<Document> {
    const result = await connection.commandAsync(
      ns(credentials.source),
      finishCommandDocument(tokenResult.accessToken, conversationId),
      undefined
    );
    return result;
  }

  /**
   * Fetches an access token using either the request or refresh callbacks and
   * puts it in the cache.
   */
  private async fetchAccessToken(
    connection: Connection,
    credentials: MongoCredentials,
    serverInfo: IdPServerInfo,
    requestCallback: OIDCRequestFunction
  ): Promise<IdPServerResponse> {
    const params: OIDCTokenParams = {
      timeoutContext: AbortSignal.timeout(TIMEOUT_S),
      version: OIDC_VERSION
    };
    // With no token in the cache we use the request callback.
    const result = await requestCallback(params);
    // Validate that the result returned by the callback is acceptable. If it is not
    // we must clear the token result from the cache.
    if (isCallbackResultInvalid(result)) {
      throw new MongoMissingCredentialsError(CALLBACK_RESULT_ERROR);
    }
    return result;
  }
}

/**
 * Determines if a result returned from a request or refresh callback
 * function is invalid. This means the result is nullish, doesn't contain
 * the accessToken required field, and does not contain extra fields.
 */
function isCallbackResultInvalid(tokenResult: unknown): boolean {
  if (tokenResult == null || typeof tokenResult !== 'object') return true;
  if (!('accessToken' in tokenResult)) return true;
  return !Object.getOwnPropertyNames(tokenResult).every(prop => RESULT_PROPERTIES.includes(prop));
}
