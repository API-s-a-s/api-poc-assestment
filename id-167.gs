/**
 * para proteger a los usuarios contra sitios web, descargas y extensiones peligrosas.
 * Configuración Evaluada: Navegación segura de Chrome
 * Filtro de Esquema / Búsqueda: chrome.users.SafeBrowsingProtectionLevel
 */
class ChromeSafeBrowsingLevelStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-167",
        valueKey: "valorPrincipal",
        noteKey: "comentario167",
        riskKey: "riesgo167",
        scoreKey: "score167"
      }
    ];

    super("Chrome Safe Browsing Protection Level Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Gestión de navegadores";
  }

  /**
   * Evalúa la política 'chrome.users.SafeBrowsingProtectionLevel' en la raíz del dominio.
   * @param {Object} globalContext Contexto global de ejecución.
   */
  evaluateInMemory(globalContext) {
    const auth = globalContext.auth || new AuthService();
    const adminEmail = auth.getCurrentUserEmail();

    Logger.log("========== INICIO DIAGNÓSTICO ID-167 (SAFE BROWSING LEVEL) ==========");

    // 1. Obtener Token DWD
    let dwdHeader = null;
    try {
      dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/chrome.management.policy.readonly"
      ]);
      Logger.log("[ID-167] Token DWD generado con éxito para Chrome Policy API.");
    } catch (e) {
      Logger.log(`[ID-167 - ERROR] No se pudo obtener el token DWD: ${e.message}`);
      return this._buildErrorResponse(`Fallo al generar token DWD: ${e.message}`);
    }

    // 2. Mapeo Robusto de la OU raíz (Para evitar Error 404)
    let rootOuId = "";
    try {
      const response = AdminDirectory.Orgunits.list(this.customerId, { type: "all" });
      const orgUnits = response.organizationUnits || [];
      
      const childOfRoot = orgUnits.find(ou => ou.parentOrgUnitPath === "/");
      if (childOfRoot && childOfRoot.parentOrgUnitId) {
        rootOuId = childOfRoot.parentOrgUnitId.replace(/^id:/, "");
        Logger.log(`[ID-167] Raíz resuelta por hija directa: ${rootOuId}`);
      } else if (orgUnits.length > 0) {
        const anyOuWithParent = orgUnits.find(ou => ou.parentOrgUnitId);
        if (anyOuWithParent) {
          rootOuId = anyOuWithParent.parentOrgUnitId.replace(/^id:/, "");
          Logger.log(`[ID-167] Raíz resuelta por UO genérica: ${rootOuId}`);
        }
      }
    } catch (e) {
      Logger.log(`[ID-167 - WARN] No se pudo mapear la raíz vía AdminDirectory: ${e.message}`);
    }

    if (!rootOuId && this.customerId && this.customerId !== "my_customer") {
      rootOuId = this.customerId;
    }

    // Bloqueo preventivo de 404
    if (!rootOuId || rootOuId === "my_customer") {
      Logger.log("[ID-167 - ERROR CRÍTICO] No se pudo obtener el ID real de la OU.");
      return this._buildErrorResponse("No se pudo resolver el ID de la OU raíz (Se bloqueó la petición para evitar Error 404).");
    }

    const targetResource = `orgunits/${rootOuId}`;
    Logger.log(`[ID-167] Target Resource definitivo para la API: ${targetResource}`);

    let safeBrowsingProtectionLevel = null;
    let anyFound = false;

    // 3. Preparar la llamada a la Chrome Policy API
    const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;
    const payload = {
      policyTargetKey: {
        targetResource: targetResource
      },
      policySchemaFilter: "chrome.users.SafeBrowsingProtectionLevel",
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

    Logger.log("[ID-167] Solicitando política chrome.users.SafeBrowsingProtectionLevel...");
    try {
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      const text = response.getContentText();
      
      Logger.log(`[ID-167 - DETALLE API] HTTP Code: ${code}`);
      Logger.log(`[ID-167 - DETALLE API] RAW JSON: ${text}`);

      if (code === 200) {
        const json = JSON.parse(text);
        const resolvedPolicies = json.resolvedPolicies || [];
        
        if (resolvedPolicies.length > 0) {
          anyFound = true;
          resolvedPolicies.forEach((policy) => {
            const val = policy.value && policy.value.value;
            // Extracción de la variable confirmada en tus logs
            if (val && val.safeBrowsingProtectionLevel !== undefined) {
              safeBrowsingProtectionLevel = val.safeBrowsingProtectionLevel;
              Logger.log(`[ID-167 - PARSEO] Encontrada variable 'safeBrowsingProtectionLevel'. Valor: ${safeBrowsingProtectionLevel}`);
            }
          });
        } else {
          Logger.log("[ID-167 - INFO] La API no devolvió políticas explícitas en la raíz. Chrome heredará el comportamiento por defecto (Protección Estándar).");
        }
      } else {
        Logger.log(`[ID-167 - ERROR] Petición fallida a la API con HTTP ${code}`);
      }
    } catch (e) {
      Logger.log(`[ID-167 - ERROR EXCEPCIÓN] Fallo de red: ${e.message}`);
    }

    // 4. Lógica de Riesgos y Construcción de la Respuesta
    // Valores estándar esperados del ENUM:
    // - "SAFE_BROWSING_PROTECTION_LEVEL_ENUM_DISABLED" (0): Deshabilitado
    // - "SAFE_BROWSING_PROTECTION_LEVEL_ENUM_STANDARD_PROTECTION" (1): Protección Estándar
    // - "SAFE_BROWSING_PROTECTION_LEVEL_ENUM_ENHANCED_PROTECTION" (2): Protección Mejorada
    
    let riesgo167, comentario167, valorPrincipal;

    if (!anyFound || safeBrowsingProtectionLevel === null) {
      riesgo167 = "Medio";
      valorPrincipal = "No Configurado (Estándar por defecto)";
      comentario167 = "El nivel de Navegación Segura no está configurado explícitamente por el administrador en la raíz. Chrome opera bajo el modo estándar por defecto, permitiendo que los usuarios lo desactiven manualmente y perdiendo los beneficios de la telemetría avanzada y el escaneo de amenazas en tiempo real.";
    } else {
      const levelStr = safeBrowsingProtectionLevel.toString();

      if (levelStr.includes("ENHANCED") || levelStr === "2") {
        riesgo167 = "Bajo";
        valorPrincipal = "Protección Mejorada (Seguro)";
        comentario167 = "La Navegación Segura está forzada en el modo de PROTECCIÓN MEJORADA de manera corporativa. Esto garantiza una protección proactiva y en tiempo real contra sitios web peligrosos, malware y descargas sospechosas mediante análisis heurístico en la nube de Google.";
      } else if (levelStr.includes("DISABLED") || levelStr === "0") {
        riesgo167 = "Alto";
        valorPrincipal = "Deshabilitado (Crítico)";
        comentario167 = "La Navegación Segura está explícitamente DESACTIVADA por política. Los usuarios no tienen ninguna protección nativa contra phishing, suplantación de identidad o malware, exponiendo críticamente los datos y credenciales de la compañía.";
      } else {
        // Modo STANDARD / 1
        riesgo167 = "Medio";
        valorPrincipal = "Protección Estándar Forzada";
        comentario167 = "Se encuentra forzada la Protección Estándar. Aunque los usuarios no pueden desactivar la protección, este modo no proporciona la evaluación y el bloqueo predictivo e inmediato de amenazas avanzadas que ofrece el nivel mejorado.";
      }
    }

    Logger.log(`[ID-167] Diagnóstico Terminado. Valor Detectado: ${safeBrowsingProtectionLevel} | Riesgo Asignado: ${riesgo167}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-167 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario167: comentario167,
      riesgo167: riesgo167,
      score167: this.calcularScoreDeRiesgo(riesgo167)
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
    Logger.log(`[ID-167] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario167: `Ocurrió un error inesperado al procesar la API: ${msg}`,
      riesgo167: "Medio",
      score167: 2
    };
  }
}