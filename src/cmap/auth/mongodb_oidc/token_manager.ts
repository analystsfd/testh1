import { type IdPServerInfo, type IdPServerResponse } from '../mongodb_oidc';

const kGeneration = Symbol('generation');
const kIdpInfo = Symbol('idpInfo');
const kIdpResponse = Symbol('idpResponse');

/** @internal */
export class TokenManager {
  [kGeneration] = 0;
  [kIdpInfo]: IdPServerInfo;
  [kIdpResponse]: IdPServerResponse;

  constructor(idpInfo: IdPServerInfo, idpResponse: IdPServerResponse) {
    this[kIdpInfo] = idpInfo;
    this[kIdpResponse] = idpResponse;
  }

  set idpInfo(value: IdPServerInfo) {
    this[kIdpInfo] = value;
    this[kGeneration] += 1;
  }

  get idpInfo() {
    return this[kIdpInfo];
  }
}
