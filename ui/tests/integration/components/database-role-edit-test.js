/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: BUSL-1.1
 */

import { module, test } from 'qunit';
import { setupRenderingTest } from 'ember-qunit';
import { render } from '@ember/test-helpers';
import { hbs } from 'ember-cli-htmlbars';
import { setupMirage } from 'ember-cli-mirage/test-support';
import { capabilitiesStub } from 'vault/tests/helpers/stubs';
import { click, fillIn } from '@ember/test-helpers';

module('Integration | Component | database-role-edit', function (hooks) {
  setupRenderingTest(hooks);
  setupMirage(hooks);

  hooks.beforeEach(function () {
    this.store = this.owner.lookup('service:store');
    this.store.pushPayload('database-role', {
      modelName: 'database/role',
      database: ['my-mongodb-database'],
      backend: 'database',
      username: 'staticTestUser',
      type: 'static',
      name: 'my-static-role',
      id: 'my-static-role',
    });
    this.store.pushPayload('database-role', {
      modelName: 'database/role',
      database: ['my-mongodb-database'],
      backend: 'database',
      type: 'dynamic',
      name: 'my-dynamic-role',
      id: 'my-dynamic-role',
    });
    this.modelStatic = this.store.peekRecord('database/role', 'my-static-role');
    this.modelDynamic = this.store.peekRecord('database/role', 'my-dynamic-role');
  });

  test('it should let user edit a static role when given update capability', async function (assert) {
    this.server.post('/sys/capabilities-self', capabilitiesStub('database/static-creds/my-role', ['update']));

    this.server.post(`/database/static-roles/my-static-role`, (schema, req) => {
      assert.true(true, 'request made to update static role');
      assert.propEqual(
        JSON.parse(req.requestBody),
        {
          username: 'staticTestUser',
          rotation_period: '1728000s', // 20 days in seconds
        },
        'it updates static role with correct payload'
      );
    });

    await render(hbs`<DatabaseRoleEdit @model={{this.modelStatic}} @mode="edit"/>`);
    await fillIn('[data-test-ttl-value="Rotation period"]', '20');
    await click('[data-test-secret-save]');
  });

  test('it should show Get credentials button when a user has the correct policy', async function (assert) {
    this.server.post('/sys/capabilities-self', capabilitiesStub('database/static-creds/my-role', ['read']));
    await render(hbs`<DatabaseRoleEdit @model={{this.modelStatic}} @mode="show"/>`);
    assert.dom('[data-test-database-role-creds="static"]').exists('Get credentials button exists');
  });

  test('it should show Generate credentials button when a user has the correct policy', async function (assert) {
    this.server.post('/sys/capabilities-self', capabilitiesStub('database/creds/my-role', ['read']));
    await render(hbs`<DatabaseRoleEdit @model={{this.modelDynamic}} @mode="show"/>`);
    assert.dom('[data-test-database-role-creds="dynamic"]').exists('Generate credentials button exists');
  });
});
