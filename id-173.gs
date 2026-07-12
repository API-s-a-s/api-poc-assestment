/**
 * ID Evaluado: ID-173
 * Configuración Evaluada: Gestión de Chrome para usuarios con sesión iniciada (habilitado por defecto)
 * Filtro de Esquema / Búsqueda: chrome.users.SyncSettingsCbcm
 * Variables de Configuración Real API: syncTypeCbcm y profileReauthPrompt (Confirmado en Logs)
 */
class ChromeSyncSettingsCbcmStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-173",
        valueKey: "valorPrincipal",
        noteKey: "comentario173",
        riskKey: "riesgo173",
        scoreKey: "score173"
      }
    ];

    super("Chrome CBCM Profile Sync Settings Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Gestión de navegadores";
  }

  /**
   * Evalúa la política 'chrome.users.SyncSettingsCbcm' en la raíz del dominio.
   * @param {Object} globalContext Contexto global de ejecución.
   */
  evaluateInMemory(globalContext) {
    const auth = globalContext.auth || new AuthService();
    const adminEmail = auth.getCurrentUserEmail();

    Logger.log("========== INICIO DIAGNÓSTICO ID-173 (SYNC SETTINGS CBCM) ==========");

    // 1. Obtener Token DWD
    let dwdHeader = null;
    try {
      dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/chrome.management.policy.readonly"
      ]);
      Logger.log("[ID-173] Token DWD generado con éxito para Chrome Policy API.");
    } catch (e) {
      Logger.log(`[ID-173 - ERROR] No se pudo obtener el token DWD: ${e.message}`);
      return this._buildErrorResponse(`Fallo al generar token DWD: ${e.message}`);
    }

    // 2. Mapeo Robusto de la OU raíz (Para evitar Error 404 de la API)
    let rootOuId = "";
    try {
      const response = AdminDirectory.Orgunits.list(this.customerId, { type: "all" });
      const orgUnits = response.organizationUnits || [];
      
      const childOfRoot = orgUnits.find(ou => ou.parentOrgUnitPath === "/");
      if (childOfRoot && childOfRoot.parentOrgUnitId) {
        rootOuId = childOfRoot.parentOrgUnitId.replace(/^id:/, "");
        Logger.log(`[ID-173] Raíz resuelta por hija directa: ${rootOuId}`);
      } else if (orgUnits.length > 0) {
        const anyOuWithParent = orgUnits.find(ou => ou.parentOrgUnitId);
        if (anyOuWithParent) {
          rootOuId = anyOuWithParent.parentOrgUnitId.replace(/^id:/, "");
          Logger.log(`[ID-173] Raíz resuelta por OU genérica: ${rootOuId}`);
        }
      }
    } catch (e) {
      Logger.log(`[ID-173 - WARN] No se pudo mapear la raíz vía AdminDirectory: ${e.message}`);
    }

    if (!rootOuId && this.customerId && this.customerId !== "my_customer") {
      rootOuId = this.customerId;
    }

    // Bloqueo preventivo de 404
    if (!rootOuId || rootOuId === "my_customer") {
      Logger.log("[ID-173 - ERROR CRÍTICO] No se pudo obtener el ID real de la OU.");
      return this._buildErrorResponse("No se pudo resolver el ID de la OU raíz (Se bloqueó la petición para evitar Error 404).");
    }

    const targetResource = `orgunits/${rootOuId}`;
    Logger.log(`[ID-173] Target Resource definitivo para la API: ${targetResource}`);

    let syncTypeCbcmValue = null;
    let profileReauthPromptValue = null;
    let anyFound = false;

    // 3. Preparar la llamada a la Chrome Policy API
    const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;
    const payload = {
      policyTargetKey: {
        targetResource: targetResource
      },
      policySchemaFilter: "chrome.users.SyncSettingsCbcm",
      pageSize: 100
    };

    const options = {
      method: "post",
      headers: {
        ...dwdHeader,
        "Content-Type": "application/json",
        "Cache-Control": "no-cache"
      },
      payload: JSON.stringify(payload),
      muteHttpExceptions: true
    };

    Logger.log("[ID-173] Solicitando política chrome.users.SyncSettingsCbcm...");
    try {
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      const text = response.getContentText();
      
      Logger.log(`[ID-173 - DETALLE API] HTTP Code: ${code}`);
      Logger.log(`[ID-173 - DETALLE API] RAW JSON: ${text}`);

      if (code === 200) {
        const json = JSON.parse(text);
        const resolvedPolicies = json.resolvedPolicies || [];
        
        if (resolvedPolicies.length > 0) {
          anyFound = true;
          resolvedPolicies.forEach((policy) => {
            const val = policy.value && policy.value.value;
            if (val) {
              if (val.syncTypeCbcm !== undefined) {
                syncTypeCbcmValue = val.syncTypeCbcm;
              }
              if (val.profileReauthPrompt !== undefined) {
                profileReauthPromptValue = val.profileReauthPrompt;
              }
              Logger.log(`[ID-173 - PARSEO] Detectados en JSON -> syncTypeCbcm: ${syncTypeCbcmValue} | profileReauthPrompt: ${profileReauthPromptValue}`);
            }
          });
        } else {
          Logger.log("[ID-173 - INFO] La API no devolvió configuraciones explícitas en la raíz. Chrome aplicará los controles de sincronización de perfiles por defecto.");
        }
      } else {
        Logger.log(`[ID-173 - ERROR] Petición fallida a la API con HTTP ${code}`);
      }
    } catch (e) {
      Logger.log(`[ID-173 - ERROR EXCEPCIÓN] Fallo de red: ${e.message}`);
    }

    // 4. Lógica de Riesgos y Construcción de la Respuesta
    // Valores conocidos observados en tus logs:
    // - "SYNC_TYPE_PROTO_ENUM_SYNC_CLOUD_DEFAULT_VALUE" (Uso nativo de la nube)
    // - "SYNC_TYPE_PROTO_ENUM_SYNC_DISABLED" (Sincronización explícitamente bloqueada)
    
    let riesgo173, comentario173, valorPrincipal;

    if (!anyFound || syncTypeCbcmValue === null) {
      riesgo173 = "Medio";
      valorPrincipal = "No Configurado (Por Defecto)";
      comentario173 = "La gestión de sincronización de perfiles en la nube (CBCM) no está configurada explícitamente en la raíz del dominio. Si bien Chrome asume la bajada básica de políticas, carecer de una directiva restrictiva unificada impide asegurar controles granulares sobre qué datos de los usuarios se resguardan de forma centralizada.";
    } else {
      const syncStr = syncTypeCbcmValue.toString();

      if (syncStr.includes("DISABLED")) {
        riesgo173 = "Alto";
        valorPrincipal = "Sincronización Deshabilitada";
        comentario173 = "La sincronización basada en la nube (CBCM) está explícitamente DESACTIVADA. Los usuarios autenticados no sincronizarán marcadores, contraseñas autorizadas ni configuraciones corporativas uniformes, fragmentando los controles de auditoría del navegador.";
      } else if (syncStr.includes("DEFAULT_VALUE") || syncStr.includes("ENABLED")) {
        riesgo173 = "Bajo";
        valorPrincipal = "Sincronización en la Nube Activa";
        comentario173 = `La gestión de perfiles de Chrome para usuarios autenticados está configurada correctamente (${syncStr}). Esto asegura el aprovisionamiento automatizado y uniforme de las políticas corporativas en el perfil del empleado.`;
        
        if (profileReauthPromptValue) {
          comentario173 += ` Adicionalmente, se detectó el parámetro de reautenticación del perfil: ${profileReauthPromptValue}.`;
        }
      } else {
        riesgo173 = "Medio";
        valorPrincipal = `Configuración Alternativa (${syncStr})`;
        comentario173 = `Se detectó un comportamiento personalizado para la sincronización de perfiles (${syncStr}). Se aconseja validar que esta directiva no esté interfiriendo con la correcta distribución de extensiones o políticas DLP.`;
      }
    }

    Logger.log(`[ID-173] Diagnóstico Terminado. syncType: ${syncTypeCbcmValue} | Riesgo: ${riesgo173}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-173 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario173: comentario173,
      riesgo173: riesgo173,
      score173: this.calcularScoreDeRiesgo(riesgo173)
    };
  }

  /**
   * Mapeo de puntajes estándar.
   */
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  /**
   * Manejador de fallos de API.
   */
  _buildErrorResponse(msg) {
    Logger.log(`[ID-173] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario173: `Ocurrió un error inesperado al procesar la API: ${msg}`,
      riesgo173: "Medio",
      score173: 2
    };
  }
}