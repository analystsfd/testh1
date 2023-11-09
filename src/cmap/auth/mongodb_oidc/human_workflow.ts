import { Binary, BSON, type Document } from 'bson';

import { MongoMissingCredentialsError } from '../../../error';
import { ns } from '../../../utils';
import type { Connection } from '../../connection';
import type { MongoCredentials } from '../mongo_credentials';
import type {
  IdPServerInfo,
  IdPServerResponse,
  OIDCCallbackContext,
  OIDCRequestFunction,
  Workflow
} from '../mongodb_oidc';
import { AuthMechanism } from '../providers';

/** The current version of OIDC implementation. */
const OIDC_VERSION = 0;

/** 5 minutes in seconds */
const TIMEOUT_S = 300;

/** Properties allowed on results of callbacks. */
const RESULT_PROPERTIES = ['accessToken', 'expiresInSeconds', 'refreshToken'];

/** Error message when the callback result is invalid. */
const CALLBACK_RESULT_ERROR =
  'User provided OIDC callbacks must return a valid object with an accessToken.';

const NO_REQUEST_CALLBACK = 'No REQUEST_TOKEN_CALLBACK provided for callback workflow.';

/**
 * OIDC implementation of a callback based workflow.
 * @internal
 */
export class HumanWorkflow implements Workflow {
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
   * Execute the OIDC callback workflow.
   */
  async execute(
    connection: Connection,
    credentials: MongoCredentials,
    reauthenticating: boolean,
    response?: Document
  ): Promise<Document> {
    const requestCallback = credentials.mechanismProperties.REQUEST_TOKEN_CALLBACK;
    if (!requestCallback) {
      throw new MongoMissingCredentialsError(NO_REQUEST_CALLBACK);
    }
    // No entry in the cache requires us to do all authentication steps
    // from start to finish, including getting a fresh token for the cache.
    const startDocument = await this.startAuthentication(
      connection,
      credentials,
      reauthenticating,
      response
    );
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
    reauthenticating: boolean,
    response?: Document
  ): Promise<Document> {
    let result;
    if (!reauthenticating && response?.speculativeAuthenticate) {
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
    const context: OIDCCallbackContext = { timeoutSeconds: TIMEOUT_S, version: OIDC_VERSION };
    // With no token in the cache we use the request callback.
    const result = await requestCallback(serverInfo, context);
    // Validate that the result returned by the callback is acceptable. If it is not
    // we must clear the token result from the cache.
    if (isCallbackResultInvalid(result)) {
      throw new MongoMissingCredentialsError(CALLBACK_RESULT_ERROR);
    }
    return result;
  }
}

/**
 * Generate the finishing command document for authentication. Will be a
 * saslStart or saslContinue depending on the presence of a conversation id.
 */
function finishCommandDocument(token: string, conversationId?: number): Document {
  if (conversationId != null && typeof conversationId === 'number') {
    return {
      saslContinue: 1,
      conversationId: conversationId,
      payload: new Binary(BSON.serialize({ jwt: token }))
    };
  }
  // saslContinue requires a conversationId in the command to be valid so in this
  // case the server allows "step two" to actually be a saslStart with the token
  // as the jwt since the use of the cached value has no correlating conversating
  // on the particular connection.
  return {
    saslStart: 1,
    mechanism: AuthMechanism.MONGODB_OIDC,
    payload: new Binary(BSON.serialize({ jwt: token }))
  };
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

/**
 * Generate the saslStart command document.
 */
function startCommandDocument(credentials: MongoCredentials): Document {
  const payload: Document = {};
  if (credentials.username) {
    payload.n = credentials.username;
  }
  return {
    saslStart: 1,
    autoAuthorize: 1,
    mechanism: AuthMechanism.MONGODB_OIDC,
    payload: new Binary(BSON.serialize(payload))
  };
}
