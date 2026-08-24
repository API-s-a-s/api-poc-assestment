/**
 * ID Evaluado: ID-173
 * Configuración Evaluada: Gestión de Chrome para usuarios con sesión iniciada (habilitado por defecto)
 * Filtro de Esquema / Búsqueda: chrome.users.SyncSettingsCbcm
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
    let syncDisabledValue = null;
    let syncSettingsValue = null;
    let anyFound = false;

    // 3. Consultar múltiples esquemas relacionados con la sincronización de Chrome
    //    La configuración de gestión para usuarios con sesión iniciada puede estar en:
    //    - chrome.users.SyncSettingsCbcm: Configuración específica de CBCM (sincronización de perfiles)
    //    - chrome.users.SyncDisabled: Toggle global que deshabilita toda sincronización
    //    - chrome.users.SyncSettings: Configuración granular de qué tipos de datos sincronizar
    const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;
    
    const schemas = [
      "chrome.users.SyncSettingsCbcm",
      "chrome.users.SyncDisabled",
      "chrome.users.SyncSettings"
    ];

    for (const schema of schemas) {
      const payload = {
        policyTargetKey: {
          targetResource: targetResource
        },
        policySchemaFilter: schema,
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

      Logger.log(`[ID-173] Solicitando política ${schema}...`);
      try {
        const response = UrlFetchApp.fetch(url, options);
        const code = response.getResponseCode();
        const text = response.getContentText();
        
        Logger.log(`[ID-173 - DETALLE API] HTTP Code: ${code} para ${schema}`);
        Logger.log(`[ID-173 - DETALLE API] RAW JSON: ${text}`);

        if (code === 200) {
          const json = JSON.parse(text);
          const resolvedPolicies = json.resolvedPolicies || [];
          
          if (resolvedPolicies.length > 0) {
            anyFound = true;
            resolvedPolicies.forEach((policy) => {
              const val = policy.value && policy.value.value;
              if (val) {
                // SyncSettingsCbcm
                if (val.syncTypeCbcm !== undefined) {
                  syncTypeCbcmValue = val.syncTypeCbcm;
                  Logger.log(`[ID-173 - PARSEO] syncTypeCbcm: ${syncTypeCbcmValue}`);
                }
                if (val.profileReauthPrompt !== undefined) {
                  profileReauthPromptValue = val.profileReauthPrompt;
                  Logger.log(`[ID-173 - PARSEO] profileReauthPrompt: ${profileReauthPromptValue}`);
                }
                // SyncDisabled
                if (val.syncDisabled !== undefined) {
                  syncDisabledValue = val.syncDisabled;
                  Logger.log(`[ID-173 - PARSEO] syncDisabled: ${syncDisabledValue}`);
                }
                // SyncSettings (puede tener syncDisabled dentro o tipos de sincronización)
                if (val.syncDisabledDataTypes !== undefined) {
                  syncSettingsValue = val.syncDisabledDataTypes;
                  Logger.log(`[ID-173 - PARSEO] syncDisabledDataTypes: ${JSON.stringify(syncSettingsValue)}`);
                }
              }
            });
          } else {
            Logger.log(`[ID-173 - INFO] La API no devolvió configuraciones explícitas para ${schema}.`);
          }
        } else if (code === 404) {
          Logger.log(`[ID-173 - WARN] Esquema ${schema} no encontrado (HTTP 404). Saltando...`);
        } else {
          Logger.log(`[ID-173 - ERROR] Petición fallida a la API con HTTP ${code} para ${schema}`);
        }
      } catch (e) {
        Logger.log(`[ID-173 - ERROR EXCEPCIÓN] Fallo de red al consultar ${schema}: ${e.message}`);
      }
    }

    // 4. Lógica de Riesgos y Construcción de la Respuesta
    // Valores conocidos observados para syncTypeCbcm:
    // - "SYNC_TYPE_PROTO_ENUM_SYNC_CLOUD_DEFAULT_VALUE" (Uso nativo de la nube)
    // - "SYNC_TYPE_PROTO_ENUM_SYNC_DISABLED" (Sincronización explícitamente bloqueada)
    // - "SYNC_TYPE_PROTO_ENUM_ROAMING_PROFILE_DISABLED_WITH_SYNC" (Perfil local con sync)
    
    let riesgo173, comentario173, valorPrincipal;

    // Caso 1: Se encontró información explícita de sincronización CBCM
    if (syncTypeCbcmValue !== null) {
      const syncStr = syncTypeCbcmValue.toString();

      if (syncStr.includes("DISABLED")) {
        riesgo173 = "Alto";
        valorPrincipal = "Sincronización Deshabilitada";
        comentario173 = `La sincronización basada en la nube (CBCM) está explícitamente DESACTIVADA (${syncStr}). Los usuarios autenticados no sincronizarán marcadores, contraseñas autorizadas ni configuraciones corporativas uniformes, fragmentando los controles de auditoría del navegador.`;
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
    // Caso 2: Se encontró la flag SyncDisabled explícita
    else if (syncDisabledValue !== null) {
      if (syncDisabledValue === true) {
        riesgo173 = "Alto";
        valorPrincipal = "Sincronización Deshabilitada (SyncDisabled)";
        comentario173 = "La sincronización de Chrome está explícitamente deshabilitada mediante la política SyncDisabled. Los perfiles de usuario no sincronizarán datos con la nube de Google, impidiendo la gestión centralizada de extensiones, marcadores y configuraciones corporativas.";
      } else {
        riesgo173 = "Bajo";
        valorPrincipal = "Sincronización Habilitada (SyncDisabled=false)";
        comentario173 = "La política SyncDisabled está explícitamente configurada como false, confirmando que la sincronización de Chrome está activa. Los perfiles de usuario sincronizarán datos con la nube de Google, permitiendo la gestión centralizada.";
      }
    }
    // Caso 3: No se encontró ninguna política explícita en ninguno de los esquemas
    else if (!anyFound) {
      riesgo173 = "Bajo";
      valorPrincipal = "Habilitado por defecto (Sin política explícita)";
      comentario173 = "No se detectaron políticas explícitas de sincronización en la Chrome Policy API para la OU raíz (SyncSettingsCbcm, SyncDisabled, SyncSettings). Chrome aplica por defecto la gestión de perfiles de usuario con sesión iniciada, lo que permite la bajada básica de políticas y sincronización nativa. Si bien funciona correctamente, se recomienda configurar explícitamente la política para evitar modificaciones locales no autorizadas.";
    }
    // Caso 4: Se encontraron datos pero no las variables específicas esperadas
    else {
      riesgo173 = "Medio";
      valorPrincipal = "Sin Configurar (Hereda por defecto)";
      comentario173 = "La Chrome Policy API respondió exitosamente pero las variables específicas de sincronización (syncTypeCbcm, syncDisabled) no fueron encontradas en los datos devueltos. Chrome asumirá el comportamiento por defecto. Se recomienda revisar la configuración en la consola de administración.";
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
      riesgo173: "",
      score173: 0
    };
  }
}