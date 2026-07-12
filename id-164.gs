/**
 * Estrategia de Auditoría para Conjunto de Cifrado (ID-164).
 * a través de la política CipherSuiteBlacklist.
 * Configuración Evaluada: Conjunto de cifrado RC4 en TLS (deshabilitado por defecto)
 * Filtro de Esquema / Búsqueda: chrome.users.CipherSuiteBlacklist
 * Variable de Configuración Real API: cipherSuiteBlacklist
 */
class ChromeCipherSuiteBlacklistStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-164",
        valueKey: "valorPrincipal",
        noteKey: "comentario164",
        riskKey: "riesgo164",
        scoreKey: "score164"
      }
    ];

    super("Chrome Cipher Suite Blacklist Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Gestión de navegadores";
  }

  /**
   * Evalúa la política 'chrome.users.CipherSuiteBlacklist' en la raíz del dominio.
   * @param {Object} globalContext Contexto global de ejecución.
   */
  evaluateInMemory(globalContext) {
    const auth = globalContext.auth || new AuthService();
    const adminEmail = auth.getCurrentUserEmail();

    Logger.log("========== INICIO DIAGNÓSTICO ID-164 (CIPHER SUITE BLACKLIST) ==========");

    // 1. Obtener Token DWD
    let dwdHeader = null;
    try {
      dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/chrome.management.policy.readonly"
      ]);
      Logger.log("[ID-164] Token DWD generado con éxito para Chrome Policy API.");
    } catch (e) {
      Logger.log(`[ID-164 - ERROR] No se pudo obtener el token DWD: ${e.message}`);
      return this._buildErrorResponse(`Fallo al generar token DWD: ${e.message}`);
    }

    // 2. Mapeo Robusto de la OU raíz (Estrategias A, B, C para evitar Error 404)
    let rootOuId = "";
    try {
      const response = AdminDirectory.Orgunits.list(this.customerId, { type: "all" });
      const orgUnits = response.organizationUnits || [];
      
      const childOfRoot = orgUnits.find(ou => ou.parentOrgUnitPath === "/");
      if (childOfRoot && childOfRoot.parentOrgUnitId) {
        rootOuId = childOfRoot.parentOrgUnitId.replace(/^id:/, "");
        Logger.log(`[ID-164] Raíz resuelta por hija directa: ${rootOuId}`);
      } else if (orgUnits.length > 0) {
        const anyOuWithParent = orgUnits.find(ou => ou.parentOrgUnitId);
        if (anyOuWithParent) {
          rootOuId = anyOuWithParent.parentOrgUnitId.replace(/^id:/, "");
          Logger.log(`[ID-164] Raíz resuelta por OU genérica: ${rootOuId}`);
        }
      }
    } catch (e) {
      Logger.log(`[ID-164 - WARN] No se pudo mapear la raíz vía AdminDirectory: ${e.message}`);
    }

    if (!rootOuId && this.customerId && this.customerId !== "my_customer") {
      rootOuId = this.customerId;
    }

    // Bloqueo preventivo de 404
    if (!rootOuId || rootOuId === "my_customer") {
      Logger.log("[ID-164 - ERROR CRÍTICO] No se pudo obtener el ID real de la OU.");
      return this._buildErrorResponse("No se pudo resolver el ID de la OU raíz (Se bloqueó la petición para evitar Error 404).");
    }

    const targetResource = `orgunits/${rootOuId}`;
    Logger.log(`[ID-164] Target Resource definitivo para la API: ${targetResource}`);

    let cipherSuiteBlacklist = [];
    let anyFound = false;

    // 3. Preparar la llamada a la Chrome Policy API
    const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;
    const payload = {
      policyTargetKey: {
        targetResource: targetResource
      },
      policySchemaFilter: "chrome.users.CipherSuiteBlacklist",
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

    Logger.log("[ID-164] Solicitando política chrome.users.CipherSuiteBlacklist...");
    try {
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      const text = response.getContentText();
      
      Logger.log(`[ID-164 - DETALLE API] HTTP Code: ${code}`);
      Logger.log(`[ID-164 - DETALLE API] RAW JSON: ${text}`);

      if (code === 200) {
        const json = JSON.parse(text);
        const resolvedPolicies = json.resolvedPolicies || [];
        
        if (resolvedPolicies.length > 0) {
          anyFound = true;
          resolvedPolicies.forEach((policy) => {
            const val = policy.value && policy.value.value;
            // Se extrae la lista de cifrados bloqueados (suele ser un array)
            if (val && val.cipherSuiteBlacklist !== undefined) {
              cipherSuiteBlacklist = val.cipherSuiteBlacklist;
              Logger.log(`[ID-164 - PARSEO] Encontrada lista 'cipherSuiteBlacklist' con ${cipherSuiteBlacklist.length} elementos.`);
            }
          });
        } else {
          Logger.log("[ID-164 - INFO] La API no devolvió políticas activas para este esquema (Hereda comportamiento por defecto del navegador).");
        }
      } else {
        Logger.log(`[ID-164 - ERROR] Petición fallida a la API con HTTP ${code}`);
      }
    } catch (e) {
      Logger.log(`[ID-164 - ERROR EXCEPCIÓN] Fallo de red: ${e.message}`);
    }

    // 4. Lógica de Riesgos y Construcción de la Respuesta
    let riesgo164, comentario164, valorPrincipal;

    if (!anyFound || cipherSuiteBlacklist.length === 0) {
      riesgo164 = "Medio";
      valorPrincipal = "No Configurado (Por Defecto) / 0";
      comentario164 = "No se detectó una lista negra de suites de cifrado (CipherSuiteBlacklist) configurada. Si bien las versiones modernas de Chrome deshabilitan cifrados débiles como RC4 por defecto, carecer de una política explícita impide al administrador bloquear rápidamente cifrados comprometidos en el futuro (ej. vulnerabilidades TLS zero-day).";
    } else {
      riesgo164 = "Bajo";
      valorPrincipal = `Configurado (${cipherSuiteBlacklist.length} bloqueos)`;
      comentario164 = `Se identificaron ${cipherSuiteBlacklist.length} suites de cifrado explícitamente bloqueadas por política corporativa. Esto garantiza conexiones TLS seguras, superponiendo restricciones estrictas que no dependen de la versión base del navegador.`;
    }

    Logger.log(`[ID-164] Diagnóstico Terminado. Riesgo Asignado: ${riesgo164} | Bloqueos detectados: ${cipherSuiteBlacklist.length}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-164 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario164: comentario164,
      riesgo164: riesgo164,
      score164: this.calcularScoreDeRiesgo(riesgo164)
    };
  }

  /**
   * Mapeo de puntajes.
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
    Logger.log(`[ID-164] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario164: `Ocurrió un error inesperado al procesar la API: ${msg}`,
      riesgo164: "Medio",
      score164: 2
    };
  }
}