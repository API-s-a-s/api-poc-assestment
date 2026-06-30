/**
 * Diccionario centralizado de valores por defecto de fábrica de Google Workspace.
 * Se utiliza para hidratar el JSON de políticas cuando Google omite configuraciones
 * porque están en su estado predeterminado.
 * Referencia: Cloud Identity Policy API v1 (https://cloud.google.com/identity/docs/reference/rest/v1/policies)
 */
class DefaultPolicyValuesRegistry {
  /**
   * Retorna las políticas por defecto de Google Workspace cuando la API viene vacía ("empty").
   * @param {string} settingType 
   */
  static getDefaults(settingType) {
    const registry = {
      "security.password": {
        enforceStrongPassword: false
      },
      "security.lessSecureApps": {
        allowLessSecureApps: false
      },
      // NUEVO: Valores de fábrica de Google Workspace para Recuperación
      "security.super_admin_account_recovery": {
        enableAccountRecovery: false
      },
      "security.user_account_recovery": {
        enableAccountRecovery: false
      }
    };
    return registry[settingType] || null;
  }
}

/**
 * Extrae las políticas de los usuarios de la OU raíz [fetchTree]
 * y lo mantiene en la memoria RAM del script.
 */
class GlobalPolicyExtractor {
  constructor(authService, customerId) {
    this.auth = authService;
    this.customerId = customerId;
    this.rawPolicies = []; 
  }

fetchTree() {
    Logger.log("[POLICY QUERY] Extracción global masiva in-memory...");
    let pageToken = "";
    const filter = `customer=="customers/${this.customerId}"`;
    const baseUrl = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&pageSize=100`;
    
    const adminEmail = this.auth.getCurrentUserEmail(); 
    const privilegedHeader = this.auth.getPrivilegedAuthHeader(adminEmail, [
      "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
    ]);

    // Adaptador nativo simplificado (el Backoff complejo vive en ApiStrategy, 
    // aquí lo aplicamos nativamente para la descarga global)
    do {
      let url = baseUrl;
      if (pageToken) url += `&pageToken=${pageToken}`;
      url += `&t=${new Date().getTime()}`;
      const config = {
        method: "get",
        headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
        muteHttpExceptions: true
      };

      let success = false, retries = 0;
      while (!success && retries < 5) {
        const response = UrlFetchApp.fetch(url, config);
        const code = response.getResponseCode();

        if (code === 429 || code >= 500) {
          retries++;
          Utilities.sleep(Math.pow(2, retries) * 1000 + Math.floor(Math.random() * 500));
        } else {
          const json = JSON.parse(response.getContentText());
          if (!json.error && json.policies) {
            const hydratedPolicies = json.policies.map(policy => this._hydratePolicy(policy));
            this.rawPolicies = this.rawPolicies.concat(hydratedPolicies);
          }
          pageToken = json.nextPageToken;
          success = true;
        }
      }
    } while (pageToken);

    return this.rawPolicies;
  }

  getPolicies() { return this.rawPolicies; }

  _hydratePolicy(policy) {
    if (!policy || !policy.setting || !policy.setting.type) return policy;
    let settingType = policy.setting.type;
    const defaultValues = DefaultPolicyValuesRegistry.getDefaults(settingType);

    if (defaultValues) {
      policy.setting.value = { ...defaultValues, ...(policy.setting.value || {}) };
    }
    return policy;
  }
}