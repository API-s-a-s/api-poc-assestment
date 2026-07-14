/**
 * Estrategia de Auditoría para el Programa de Protección Avanzada de Chrome (ID-166).
 * Configuración Evaluada: Programa de Protección Avanzada (protecciones adicionales habilitadas por defecto)
 * Filtro de Esquema / Búsqueda: chrome.users.AdvancedProtectionAllowed
 * Variable de Configuración Real API: advancedProtectionAllowed (camelCase)
 */
class ChromeAdvancedProtectionStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-166",
        valueKey: "valorPrincipal",
        noteKey: "comentario166",
        riskKey: "riesgo166",
        scoreKey: "score166"
      }
    ];

    super("Chrome Advanced Protection Program Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Gestión de navegadores";
  }

  /**
   * Evalúa la política 'chrome.users.AdvancedProtectionAllowed' en la raíz del dominio.
   * @param {Object} globalContext Contexto global de ejecución.
   */
  evaluateInMemory(globalContext) {
    const auth = globalContext.auth || new AuthService();
    const adminEmail = auth.getCurrentUserEmail();

    Logger.log("========== INICIO DIAGNÓSTICO ID-166 (ADVANCED PROTECTION) ==========");

    // 1. Obtener Token DWD
    let dwdHeader = null;
    try {
      dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/chrome.management.policy.readonly"
      ]);
      Logger.log("[ID-166] Token DWD generado con éxito para Chrome Policy API.");
    } catch (e) {
      Logger.log(`[ID-166 - ERROR] No se pudo obtener el token DWD: ${e.message}`);
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
        Logger.log(`[ID-166] Raíz resuelta por hija directa: ${rootOuId}`);
      } else if (orgUnits.length > 0) {
        const anyOuWithParent = orgUnits.find(ou => ou.parentOrgUnitId);
        if (anyOuWithParent) {
          rootOuId = anyOuWithParent.parentOrgUnitId.replace(/^id:/, "");
          Logger.log(`[ID-166] Raíz resuelta por OU genérica: ${rootOuId}`);
        }
      }
    } catch (e) {
      Logger.log(`[ID-166 - WARN] No se pudo mapear la raíz vía AdminDirectory: ${e.message}`);
    }

    if (!rootOuId && this.customerId && this.customerId !== "my_customer") {
      rootOuId = this.customerId;
    }

    // Bloqueo preventivo de 404
    if (!rootOuId || rootOuId === "my_customer") {
      Logger.log("[ID-166 - ERROR CRÍTICO] No se pudo obtener el ID real de la OU.");
      return this._buildErrorResponse("No se pudo resolver el ID de la OU raíz (Se bloqueó la petición para evitar Error 404).");
    }

    const targetResource = `orgunits/${rootOuId}`;
    Logger.log(`[ID-166] Target Resource definitivo para la API: ${targetResource}`);

    let advancedProtectionAllowed = null;
    let anyFound = false;

    // 3. Preparar la llamada a la Chrome Policy API
    const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;
    const payload = {
      policyTargetKey: {
        targetResource: targetResource
      },
      policySchemaFilter: "chrome.users.AdvancedProtectionAllowed",
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

    Logger.log("[ID-166] Solicitando política chrome.users.AdvancedProtectionAllowed...");
    try {
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      const text = response.getContentText();
      
      Logger.log(`[ID-166 - DETALLE API] HTTP Code: ${code}`);
      Logger.log(`[ID-166 - DETALLE API] RAW JSON: ${text}`);

      if (code === 200) {
        const json = JSON.parse(text);
        const resolvedPolicies = json.resolvedPolicies || [];
        
        if (resolvedPolicies.length > 0) {
          anyFound = true;
          resolvedPolicies.forEach((policy) => {
            const val = policy.value && policy.value.value;
            // Se valida extrayendo el campo en camelCase corregido
            if (val && val.advancedProtectionAllowed !== undefined) {
              advancedProtectionAllowed = val.advancedProtectionAllowed;
              Logger.log(`[ID-166 - PARSEO] Encontrada variable 'advancedProtectionAllowed'. Valor: ${advancedProtectionAllowed}`);
            }
          });
        } else {
          Logger.log("[ID-166 - INFO] La API no devolvió políticas explícitas. Chrome aplicará su comportamiento nativo.");
        }
      } else {
        Logger.log(`[ID-166 - ERROR] Petición fallida a la API con HTTP ${code}`);
      }
    } catch (e) {
      Logger.log(`[ID-166 - ERROR EXCEPCIÓN] Fallo de red: ${e.message}`);
    }

    // 4. Lógica de Riesgos y Construcción de la Respuesta
    let riesgo166, comentario166, valorPrincipal;

    if (advancedProtectionAllowed === true) {
      riesgo166 = "Bajo";
      valorPrincipal = "Habilitado / Permitido";
      comentario166 = "El Programa de Protección Avanzada de Google está explícitamente permitido para los usuarios. Esto habilita capas adicionales de seguridad automática dentro de Chrome (controles antifraude reforzados, bloqueos estrictos de archivos sospechosos) para perfiles corporativos expuestos a riesgos dirigidos.";
    } else if (advancedProtectionAllowed === false) {
      riesgo166 = "Alto";
      valorPrincipal = "Deshabilitado";
      comentario166 = "El Programa de Protección Avanzada de Google está explícitamente DESACTIVADO por política. Esto impide de forma directa que los perfiles corporativos o usuarios de alto nivel aprovechen el conjunto de escudos avanzados de Google contra ataques persistentes de phishing o descargas de malware avanzado.";
    } else {
      // anyFound === false o advancedProtectionAllowed === null (No configurado)
      riesgo166 = "Medio";
      valorPrincipal = "Sin Configurar (Hereda por defecto)";
      comentario166 = "La Chrome Policy API respondió exitosamente sin encontrar una configuración explícita en la OU raíz para la Protección Avanzada. Si bien de forma nativa Chrome no bloquea estas cuentas, la falta de una política formal no garantiza el cumplimiento uniforme de esta directiva de endurecimiento en todos los dispositivos.";
    }

    Logger.log(`[ID-166] Diagnóstico Terminado. Valor Detectado: ${advancedProtectionAllowed} | Riesgo Asignado: ${riesgo166}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-166 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario166: comentario166,
      riesgo166: riesgo166,
      score166: this.calcularScoreDeRiesgo(riesgo166)
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
    Logger.log(`[ID-166] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario166: `Ocurrió un error inesperado al procesar la API: ${msg}`,
      riesgo166: "Medio",
      score166: 2
    };
  }
}