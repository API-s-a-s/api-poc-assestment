/**
 * Se encarga de proveer y gestionar la identidad, permisos y tokens de acceso.
 * Centraliza el token interactivo y el token DWD.
 * Referencia: Google Cloud IAM & DWD (https://developers.google.com/workspace/guides/create-credentials)
 */
class AuthService {
  constructor() {
    this.cache = CacheService.getScriptCache();    
  }
  /**
   * Token interactivo estándar de Apps Script (Contexto de usuario ejecutor)
   */
  getToken() {
    return ScriptApp.getOAuthToken();
  }

  getAuthHeader() {
    return { "Authorization": "Bearer " + this.getToken() };
  }

  /**
   * Obtiene de forma segura las credenciales de la Cuenta de Servicio desde GCP Secret Manager.
   * Cuenta con almacenamiento en caché para evitar la sobrecarga de latencia y costo de la API de Secrets.
   * @return {Object} Credenciales parseadas del archivo JSON de la Cuenta de Servicio.
   */
  _getSaCredentials() {
    if (this._saCredentials) {
      return this._saCredentials;
    }

    const cacheKey = "SA_CREDENTIALS_JSON";
    const cached = this.cache.get(cacheKey);
    if (cached) {
      try {
        this._saCredentials = JSON.parse(cached);
        return this._saCredentials;
      } catch (e) {
        Logger.log("[AUTH] Caché de credenciales corrupta o inválida. Reintentando consulta a Secret Manager.");
      }
    }

    Logger.log("[AUTH] Obteniendo credenciales de la Cuenta de Servicio desde GCP Secret Manager...");
    
    // Obtener la configuración o usar valores por defecto del entorno
    const props = PropertiesService.getScriptProperties();
    const projectId = props.getProperty("GCP_PROJECT_ID") || "poc2-495720";
    const secretName = props.getProperty("SA_SECRET_NAME") || "service-account-credentials";
    const version = "latest";
    
    const url = `https://secretmanager.googleapis.com/v1/projects/${projectId}/secrets/${secretName}/versions/${version}:access`;

    try {
      const response = UrlFetchApp.fetch(url, {
        method: "get",
        headers: {
          "Authorization": "Bearer " + this.getToken(),
          "Accept": "application/json"
        },
        muteHttpExceptions: true
      });

      const responseCode = response.getResponseCode();
      const content = response.getContentText();

      if (responseCode !== 200) {
        throw new Error(`Código de respuesta HTTP ${responseCode}: ${content}`);
      }

      const resJson = JSON.parse(content);
      if (!resJson.payload || !resJson.payload.data) {
        throw new Error("El secreto no contiene un payload de datos válido.");
      }

      // El payload de Secret Manager viene codificado en Base64 estándar
      const base64Data = resJson.payload.data;
      const decodedPayload = Utilities.newBlob(Utilities.base64Decode(base64Data)).getDataAsString();
      
      const credentials = JSON.parse(decodedPayload);
      if (!credentials.private_key || !credentials.client_email) {
        throw new Error("El JSON de credenciales de la Cuenta de Servicio está incompleto (faltan campos críticos como private_key o client_email).");
      }

      this._saCredentials = credentials;
      // Almacenar en caché durante 1 hora (3600 segundos)
      this.cache.put(cacheKey, decodedPayload, 3600);
      return this._saCredentials;

    } catch (e) {
      Logger.log(`[CRÍTICO - AUTH] No se pudieron obtener las credenciales desde Secret Manager: ${e.message}`);
      throw new Error(`Error de Autenticación: Falló la obtención de la Cuenta de Servicio desde Secret Manager. Detalle: ${e.message}`);
    }
  }

  /**
   * Genera u obtiene del caché un token firmado por Cuenta de Servicio
   * aplicando Delegación de Dominio Completo (DWD) para suplantar a un Súper Admin.
   * * @param {string} adminEmail Correo electrónico del Súper Administrador a suplantar.
   * @return {Object} Cabecera de autenticación estructurada para UrlFetchApp.
   */
  getPrivilegedAuthHeader(adminEmail, scopes = ["https://www.googleapis.com/auth/cloud-identity.policies.readonly"]) {
    // PASO 1: Clave estática determinista. Que destruía la utilidad de la caché y generaba saturación de tokens.
    const cacheKey = "SA_TOKEN_DWD_" + adminEmail.replace(/[^a-zA-Z0-9]/g, "");
    let token = this.cache.get(cacheKey);

    if (token) {
      return { "Authorization": "Bearer " + token };
    }

    Logger.log(`[AUTH] Generando nuevo token de acceso privilegiado vía DWD para: ${adminEmail}`);
    
    const saCreds = this._getSaCredentials();
    const jwtHeader = JSON.stringify({ alg: "RS256", typ: "JWT" });
    const now = Math.floor(Date.now() / 1000);
    const jwtClaim = JSON.stringify({
      iss: saCreds.client_email,
      sub: adminEmail, 
      scope: scopes.join(" "),
      aud: saCreds.token_uri || "https://oauth2.googleapis.com/token",
      exp: now + 3600, 
      iat: now
    }
  );
const base64Header = Utilities.base64EncodeWebSafe(jwtHeader).replace(/=+$/, '');
    const base64Claim = Utilities.base64EncodeWebSafe(jwtClaim).replace(/=+$/, '');
    const signatureInput = base64Header + "." + base64Claim;

    const signatureBytes = Utilities.computeRsaSha256Signature(signatureInput, saCreds.private_key);
    const base64Signature = Utilities.base64EncodeWebSafe(signatureBytes).replace(/=+$/, '');
    const jwtAssertion = signatureInput + "." + base64Signature;

    const options = {
      method: "post",
      contentType: "application/x-www-form-urlencoded",
      payload: { grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: jwtAssertion },
      muteHttpExceptions: true
    };

    try {
      const response = UrlFetchApp.fetch(saCreds.token_uri || "https://oauth2.googleapis.com/token", options);
      const resJson = JSON.parse(response.getContentText());

      if (resJson.error) throw new Error(`Google OAuth rechazó el JWT: ${resJson.error_description || resJson.error}`);

      token = resJson.access_token;
      this.cache.put(cacheKey, token, 3300); 
      
      return { "Authorization": "Bearer " + token };

    } catch (e) {
      Logger.log(`[CRÍTICO - AUTH] Error en intercambio criptográfico: ${e.message}`);
      throw e;
    }
  }

  getDomain() { return "test.apisas.com"; }
  getCurrentUserEmail() { return Session.getActiveUser().getEmail(); }
  getZeroTrustPolicyId() { return "accessPolicies/1028743991591"; }
  getCustomerId() { return "my_customer"; }
  getGcpProjectId() { return this._getSaCredentials().project_id; }
  getGcpServiceAccountEmail() { return this._getSaCredentials().client_email; }

  // =====================================================================
  // Resolución dinámica de roleId desde AdminDirectory.Roles.list()
  // Se resuelve una sola vez y se cachea en CacheService por 25 minutos.
  // Esto reemplaza los placeholders estáticos que nunca coincidían con
  // los IDs numéricos reales que devuelve la API de Directory.
  // =====================================================================
  _resolveRoleMap() {
    if (this._roleMap) return this._roleMap;

    // Intentar recuperar del caché efímero
    const cacheKey = "AUTH_ROLE_MAP";
    const cached = this.cache.get(cacheKey);
    if (cached) {
      try {
        this._roleMap = JSON.parse(cached);
        Logger.log(`[AUTH] Mapa de roles recuperado de caché: ${Object.keys(this._roleMap).length} roles`);
        return this._roleMap;
      } catch (e) { /* caché corrupta, reconstruimos */ }
    }

    // Consulta a la API de Directory para construir el diccionario roleName → roleId
    Logger.log("[AUTH] Construyendo mapa dinámico de roleId desde AdminDirectory.Roles.list()...");
    const map = {};
    const customerId = this.getCustomerId();

    try {
      let pageToken = null;
      do {
        const response = AdminDirectory.Roles.list(customerId, { maxResults: 100, pageToken: pageToken });
        const roles = response.items || [];
        roles.forEach(role => {
          // Usamos el roleName del sistema como clave (ej: "_SUPER_ADMIN_ROLE")
          map[role.roleName] = role.roleId;
          Logger.log(`[AUTH] Rol resuelto: ${role.roleName} → ${role.roleId}`);
        });
        pageToken = response.nextPageToken;
      } while (pageToken);
    } catch (e) {
      Logger.log(`[AUTH][ERROR] Fallo al resolver roles dinámicamente: ${e.message}. Se usarán los nombres del sistema como fallback.`);
    }

    this._roleMap = map;
    // Persistir en caché por 25 minutos (mismo TTL que el censo)
    this.cache.put(cacheKey, JSON.stringify(map), 1500);
    return this._roleMap;
  }

  /**
   * Busca el roleId numérico real para un nombre de rol del sistema.
   * Si la resolución dinámica falla, devuelve el nombre del sistema como fallback
   * (los scripts ya tienen fallback por roleName para este caso).
   */
  _getRoleIdBySystemName(systemRoleName) {
    const map = this._resolveRoleMap();
    return map[systemRoleName] || systemRoleName;
  }

  // Getters de roles — ahora devuelven IDs numéricos reales
  getSuperAdminRoleId()   { return this._getRoleIdBySystemName("_SUPER_ADMIN_ROLE"); }
  getGroupsAdminRoleId()  { return this._getRoleIdBySystemName("_GROUPS_ADMIN_ROLE"); }
  getUserAdminRoleId()    { return this._getRoleIdBySystemName("_USER_MANAGEMENT_ADMIN_ROLE"); }
  getHelpDeskAdminRoleId(){ return this._getRoleIdBySystemName("_HELP_DESK_ADMIN_ROLE"); }
  getAndroidAdminRoleId() { return this._getRoleIdBySystemName("_MOBILE_ADMIN_ROLE"); }
  getVoiceAdminRoleId()   { return this._getRoleIdBySystemName("_GOOGLE_VOICE_ADMIN_ROLE"); }
  getMobileAdminRoleId()  { return this._getRoleIdBySystemName("_MOBILE_ADMIN_ROLE"); }
  getServicesAdminRoleId(){ return this._getRoleIdBySystemName("_SERVICES_ADMIN_ROLE"); }
}