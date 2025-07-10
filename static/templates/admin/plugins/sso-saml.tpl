<div class="row">
  <div class="col-sm-12">
    <form role="form" class="sso-saml-settings">
      <div class="panel panel-default">
        <div class="panel-heading">SAML SSO Settings</div>
        <div class="panel-body">
          
          <div class="form-group">
            <label for="spCert">Service Provider Certificate</label>
            <textarea id="spCert" name="spCert" class="form-control" rows="4" placeholder="-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----" data-field="spCert"></textarea>
          </div>

          <div class="form-group">
            <label for="spKey">Service Provider Private Key</label>
            <textarea id="spKey" name="spKey" class="form-control" rows="4" placeholder="-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----" data-field="spKey"></textarea>
          </div>

          <div class="form-group">
            <label for="idpCert">Identity Provider Certificate</label>
            <textarea id="idpCert" name="idpCert" class="form-control" rows="4" placeholder="-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----" data-field="idpCert"></textarea>
          </div>

          <div class="form-group">
            <label for="ssoLoginUrl">SSO Login URL</label>
            <input type="text" id="ssoLoginUrl" name="ssoLoginUrl" class="form-control" placeholder="https://your-idp.com/sso" data-field="ssoLoginUrl" />
          </div>

          <div class="form-group">
            <label for="ssoLogoutUrl">SSO Logout URL</label>
            <input type="text" id="ssoLogoutUrl" name="ssoLogoutUrl" class="form-control" placeholder="https://your-idp.com/slo" data-field="ssoLogoutUrl" />
          </div>

          <div class="form-group">
            <label for="entityId">SP Entity ID</label>
            <input type="text" id="entityId" name="entityId" class="form-control" placeholder="https://nodebb.yourdomain.com" data-field="entityId" />
          </div>

          <div class="form-group">
            <label for="assertEndpoint">SP Assertion Endpoint</label>
            <input type="text" id="assertEndpoint" name="assertEndpoint" class="form-control" placeholder="/auth/saml/callback" data-field="assertEndpoint" />
          </div>

          <div class="form-group">
            <label for="loginSuccessRedirectUrl">Login Success Redirect URL</label>
            <input type="text" id="loginSuccessRedirectUrl" name="loginSuccessRedirectUrl" class="form-control" placeholder="/" data-field="loginSuccessRedirectUrl" />
          </div>
        </div>
      </div>
    </form>

      <button type="button" class="btn btn-primary" id="save">Save Settings</button>
  </div>
</div>
