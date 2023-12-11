import { expect } from 'chai';
import ConnectionString from 'mongodb-connection-string-url';
import * as qs from 'querystring';
import * as url from 'url';

import {
  type AuthMechanism,
  HostAddress,
  ModernConnection,
  MongoClient,
  type ServerApi,
  TopologyType,
  type WriteConcernSettings
} from '../../mongodb';
import { getEnvironmentalOptions } from '../utils';

interface ProxyParams {
  proxyHost?: string;
  proxyPort?: number;
  proxyUsername?: string;
  proxyPassword?: string;
}

interface UrlOptions {
  /** name of the default db */
  db?: string;
  /** replSet name */
  replicaSet?: string;
  /** Username to authenticate with */
  username?: string;
  /** Password to authenticate with */
  password?: string;
  /** Name of the auth mechanism to use */
  authMechanism?: AuthMechanism;
  /** Additional properties used by the mechanism */
  authMechanismProperties?: Record<string, any>;
  /** The database to specify as the authentication source */
  authSource?: string;
  /** If set will use concatenate all known HostAddresses in URI */
  useMultipleMongoses?: boolean;
  /** Parameters for configuring a proxy connection */
  proxyURIParams?: ProxyParams;
}

function convertToConnStringMap(obj: Record<string, any>) {
  const result = [];
  Object.keys(obj).forEach(key => {
    result.push(`${key}:${obj[key]}`);
  });

  return result.join(',');
}

export class TestConfiguration {
  version: string;
  clientSideEncryption: Record<string, any>;
  parameters: Record<string, any>;
  singleMongosLoadBalancerUri: string;
  multiMongosLoadBalancerUri: string;
  isServerless: boolean;
  topologyType: TopologyType;
  buildInfo: Record<string, any>;
  options: {
    hosts?: string[];
    hostAddresses: HostAddress[];
    hostAddress?: HostAddress;
    host?: string;
    port?: number;
    db?: string;
    replicaSet?: string;
    authMechanism?: string;
    authMechanismProperties?: Record<string, any>;
    auth?: { username: string; password: string; authSource?: string };
    proxyURIParams?: ProxyParams;
  };
  serverApi: ServerApi;

  constructor(private uri: string, private context: Record<string, any>) {
    const url = new ConnectionString(uri);
    const { hosts } = url;
    const hostAddresses = hosts.map(HostAddress.fromString);
    this.version = context.version;
    this.clientSideEncryption = context.clientSideEncryption;
    this.parameters = { ...context.parameters };
    this.singleMongosLoadBalancerUri = context.singleMongosLoadBalancerUri;
    this.multiMongosLoadBalancerUri = context.multiMongosLoadBalancerUri;
    this.isServerless = !!process.env.SERVERLESS;
    this.topologyType = this.isLoadBalanced ? TopologyType.LoadBalanced : context.topologyType;
    this.buildInfo = context.buildInfo;
    this.serverApi = context.serverApi;
    this.options = {
      hosts,
      hostAddresses,
      hostAddress: hostAddresses[0],
      host: hostAddresses[0].host,
      port:
        typeof hostAddresses[0].host === 'string' && !this.isServerless
          ? hostAddresses[0].port
          : undefined,
      db: url.pathname.slice(1) ? url.pathname.slice(1) : 'integration_tests',
      replicaSet: url.searchParams.get('replicaSet'),
      proxyURIParams: url.searchParams.get('proxyHost')
        ? {
            proxyHost: url.searchParams.get('proxyHost'),
            proxyPort: Number(url.searchParams.get('proxyPort')),
            proxyUsername: url.searchParams.get('proxyUsername'),
            proxyPassword: url.searchParams.get('proxyPassword')
          }
        : undefined
    };
    if (url.username) {
      this.options.auth = {
        username: url.username,
        password: url.password
      };
    }
    if (context.serverlessCredentials) {
      const { username, password } = context.serverlessCredentials;
      this.options.auth = { username, password, authSource: 'admin' };
    }
  }

  get isLoadBalanced() {
    return (
      !!this.singleMongosLoadBalancerUri && !!this.multiMongosLoadBalancerUri && !this.isServerless
    );
  }

  writeConcern() {
    return { writeConcern: { w: 1 } };
  }

  get host() {
    return this.options.host;
  }

  get port() {
    return this.options.port;
  }

  set db(_db) {
    this.options.db = _db;
  }

  get db() {
    return this.options.db;
  }

  // legacy accessors, consider for removal
  get replicasetName() {
    return this.options.replicaSet;
  }

  get setName() {
    return this.options.replicaSet;
  }

  isAzureOIDC(uri: string): boolean {
    return uri.indexOf('MONGODB-OIDC') > -1 && uri.indexOf('PROVIDER_NAME:azure') > -1;
  }

  newClient(dbOptions?: string | Record<string, any>, serverOptions?: Record<string, any>) {
    serverOptions = Object.assign({}, getEnvironmentalOptions(), serverOptions);

    // support MongoClient constructor form (url, options) for `newClient`
    if (typeof dbOptions === 'string') {
      return new MongoClient(dbOptions, serverOptions);
    }

    dbOptions = dbOptions || {};
    // Fall back
    let dbHost = (serverOptions && serverOptions.host) || this.options.host;
    const dbPort = (serverOptions && serverOptions.port) || this.options.port;
    if (dbHost.indexOf('.sock') !== -1) {
      dbHost = qs.escape(dbHost);
    }

    if (this.options.authMechanism) {
      Object.assign(dbOptions, {
        authMechanism: this.options.authMechanism
      });
    }

    if (this.options.authMechanismProperties) {
      Object.assign(dbOptions, {
        authMechanismProperties: convertToConnStringMap(this.options.authMechanismProperties)
      });
    }

    if (this.options.replicaSet) {
      Object.assign(dbOptions, { replicaSet: this.options.replicaSet });
    }

    if (this.options.proxyURIParams) {
      for (const [name, value] of Object.entries(this.options.proxyURIParams)) {
        if (value) {
          dbOptions[name] = value;
        }
      }
    }

    // Flatten any options nested under `writeConcern` before we make the connection string
    if (dbOptions.writeConcern) {
      Object.assign(dbOptions, dbOptions.writeConcern);
      delete dbOptions.writeConcern;
    }

    if (this.topologyType === TopologyType.LoadBalanced && !this.isServerless) {
      dbOptions.loadBalanced = true;
    }

    const urlOptions: url.UrlObject = {
      protocol: this.isServerless ? 'mongodb+srv' : 'mongodb',
      slashes: true,
      hostname: dbHost,
      port: this.isServerless ? null : dbPort,
      query: dbOptions,
      pathname: '/'
    };

    if (this.options.auth) {
      const { username, password } = this.options.auth;
      if (username) {
        urlOptions.auth = `${encodeURIComponent(username)}:${encodeURIComponent(password)}`;
      }
    }

    if (dbOptions.auth) {
      const { username, password } = dbOptions.auth;
      if (username) {
        urlOptions.auth = `${encodeURIComponent(username)}:${encodeURIComponent(password)}`;
      }
    }

    if (typeof urlOptions.query === 'object') {
      // Auth goes at the top of the uri, not in the searchParams
      delete urlOptions.query.auth;
    }

    const connectionString = url.format(urlOptions);
    if (Reflect.has(serverOptions, 'host') || Reflect.has(serverOptions, 'port')) {
      throw new Error(`Cannot use options to specify host/port, must be in ${connectionString}`);
    }

    if (process.env.MONGODB_NEW_CONNECTION === 'true') {
      serverOptions.ConnectionType = ModernConnection;
    }

    return new MongoClient(connectionString, serverOptions);
  }

  /**
   * Construct a connection URL using nodejs's whatwg URL similar to how connection_string.ts
   * works
   *
   * @param options - overrides and settings for URI generation
   */
  url(options?: UrlOptions) {
    options = {
      db: this.options.db,
      replicaSet: this.options.replicaSet,
      proxyURIParams: this.options.proxyURIParams,
      ...options
    };

    const FILLER_HOST = 'fillerHost';

    const protocol = this.isServerless ? 'mongodb+srv' : 'mongodb';
    const url = new URL(`${protocol}://${FILLER_HOST}`);

    if (options.replicaSet) {
      url.searchParams.append('replicaSet', options.replicaSet);
    }

    if (options.proxyURIParams) {
      for (const [name, value] of Object.entries(options.proxyURIParams)) {
        if (value) {
          url.searchParams.append(name, value);
        }
      }
    }

    url.pathname = `/${options.db}`;

    const username = this.options.username || (this.options.auth && this.options.auth.username);
    const password = this.options.password || (this.options.auth && this.options.auth.password);

    if (username) {
      url.username = username;
    }

    if (password) {
      url.password = password;
    }

    if (this.isLoadBalanced && !this.isServerless) {
      url.searchParams.append('loadBalanced', 'true');
    }

    if (username || password) {
      if (options.authMechanism) {
        url.searchParams.append('authMechanism', options.authMechanism);
      }

      if (options.authMechanismProperties) {
        url.searchParams.append(
          'authMechanismProperties',
          convertToConnStringMap(options.authMechanismProperties)
        );
      }

      if (options.authSource) {
        url.searchParams.append('authSource', options.authSource);
      }
    } else if (this.isServerless) {
      url.searchParams.append('ssl', 'true');
      url.searchParams.append('authSource', 'admin');
    }

    let actualHostsString;
    // Ignore multi mongos options in serverless testing.
    if (options.useMultipleMongoses && !this.isServerless) {
      if (this.isLoadBalanced) {
        const multiUri = new ConnectionString(this.multiMongosLoadBalancerUri);
        if (multiUri.isSRV) {
          throw new Error('You cannot pass an SRV connection string to multiMongosLoadBalancerUri');
        }
        actualHostsString = multiUri.hosts[0].toString();
      } else {
        expect(this.options.hostAddresses).to.have.length.greaterThan(1);
        actualHostsString = this.options.hostAddresses.map(ha => ha.toString()).join(',');
      }
    } else {
      if (this.isLoadBalanced || this.isServerless) {
        const singleUri = new ConnectionString(this.singleMongosLoadBalancerUri);
        actualHostsString = singleUri.hosts[0].toString();
      } else {
        // For OIDC we need to get the URI to the dedicated clusters.
        if (this.uri.includes('MONGODB-OIDC')) {
          actualHostsString = process.env.MONGODB_URI;
        } else {
          actualHostsString = this.options.hostAddresses[0].toString();
        }
      }
    }

    if (!options.authSource) {
      url.searchParams.append('authSource', 'admin');
    }

    if (this.uri.includes('MONGODB-OIDC')) {
      return process.env.MONGODB_URI;
    }

    const connectionString = url.toString().replace(FILLER_HOST, actualHostsString);

    return connectionString;
  }

  writeConcernMax(): { writeConcern: WriteConcernSettings } {
    if (this.topologyType !== TopologyType.Single) {
      return { writeConcern: { w: 'majority', wtimeoutMS: 30000 } };
    }

    return { writeConcern: { w: 1 } };
  }

  kmsProviders(localKey): Record<string, any> {
    return { local: { key: localKey } };
  }

  makeAtlasTestConfiguration(): AtlasTestConfiguration {
    return new AtlasTestConfiguration(this.uri, this.context);
  }
}

/**
 * A specialized configuration used to connect to Atlas for testing.
 *
 * This class requires that the Atlas srv URI is set as the `MONGODB_URI` in the environment.
 */
export class AtlasTestConfiguration extends TestConfiguration {
  override newClient(): MongoClient {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return new MongoClient(process.env.MONGODB_URI!);
  }

  override url(): string {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return process.env.MONGODB_URI!;
  }
}

/**
 * Test configuration specific to Astrolabe testing.
 */
export class AstrolabeTestConfiguration extends TestConfiguration {
  override newClient(): MongoClient {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return new MongoClient(process.env.DRIVERS_ATLAS_TESTING_URI!);
  }

  override url(): string {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return process.env.DRIVERS_ATLAS_TESTING_URI!;
  }
}
