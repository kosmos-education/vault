/**
 * Copyright IBM Corp. 2016, 2025
 * SPDX-License-Identifier: BUSL-1.1
 */
import Route from '@ember/routing/route';
import { service } from '@ember/service';

export default class SecretsRedirectPathRoute extends Route {
  @service router;

  beforeModel(transition) {
    const { path } = transition.to.params;
    const { cluster_name } = this.paramsFor('vault.cluster');
    this.router.replaceWith(`/${cluster_name}/secrets-engines/${path}`);
  }
}
