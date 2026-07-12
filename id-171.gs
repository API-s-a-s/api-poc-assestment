/**
 * Configuración Evaluada: Actualizaciones del navegador Chrome
 * Filtro de Esquema / Búsqueda: chrome.devices.updates.UpdatePolicyOverride
 * Variable de Configuración Real API: updatePolicyOverride (camelCase)
 */
class ChromeUpdatePolicyOverrideStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-171",
        valueKey: "valorPrincipal",
        noteKey: "comentario171",
        riskKey: "riesgo171",
        scoreKey: "score171"
      }
    ];

    super("Chrome Browser Update Policy Override Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Gestión de navegadores";
  }

  /**
   * Evalúa la política 'chrome.devices.updates.UpdatePolicyOverride' en la raíz del dominio.
   * @param {Object} globalContext Contexto global de ejecución.
   */
  evaluateInMemory(globalContext) {
    const auth = globalContext.auth || new AuthService();
    const adminEmail = auth.getCurrentUserEmail();

    Logger.log("========== INICIO DIAGNÓSTICO ID-171 (UPDATE POLICY OVERRIDE) ==========");

    // 1. Obtener Token DWD
    let dwdHeader = null;
    try {
      dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/chrome.management.policy.readonly"
      ]);
      Logger.log("[ID-171] Token DWD generado con éxito para Chrome Policy API.");
    } catch (e) {
      Logger.log(`[ID-171 - ERROR] No se pudo obtener el token DWD: ${e.message}`);
      return this._buildErrorResponse(`Fallo al generar token DWD: ${e.message}`);
    }

    // 2. Mapeo Robusto de la OU raíz (Estrategias A, B y C para evitar Error 404)
    let rootOuId = "";
    try {
      const response = AdminDirectory.Orgunits.list(this.customerId, { type: "all" });
      const orgUnits = response.organizationUnits || [];
      
      const childOfRoot = orgUnits.find(ou => ou.parentOrgUnitPath === "/");
      if (childOfRoot && childOfRoot.parentOrgUnitId) {
        rootOuId = childOfRoot.parentOrgUnitId.replace(/^id:/, "");
        Logger.log(`[ID-171] Raíz resuelta por hija directa: ${rootOuId}`);
      } else if (orgUnits.length > 0) {
        const anyOuWithParent = orgUnits.find(ou => ou.parentOrgUnitId);
        if (anyOuWithParent) {
          rootOuId = anyOuWithParent.parentOrgUnitId.replace(/^id:/, "");
          Logger.log(`[ID-171] Raíz resuelta por OU genérica: ${rootOuId}`);
        }
      }
    } catch (e) {
      Logger.log(`[ID-171 - WARN] No se pudo mapear la raíz vía AdminDirectory: ${e.message}`);
    }

    if (!rootOuId && this.customerId && this.customerId !== "my_customer") {
      rootOuId = this.customerId;
    }

    // Bloqueo preventivo de 404
    if (!rootOuId || rootOuId === "my_customer") {
      Logger.log("[ID-171 - ERROR CRÍTICO] No se pudo obtener el ID real de la OU.");
      return this._buildErrorResponse("No se pudo resolver el ID de la OU raíz (Se bloqueó la petición para evitar Error 404).");
    }

    const targetResource = `orgunits/${rootOuId}`;
    Logger.log(`[ID-171] Target Resource definitivo para la API: ${targetResource}`);

    let updatePolicyOverrideValue = null;
    let anyFound = false;

    // 3. Preparar la llamada a la Chrome Policy API
    const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;
    const payload = {
      policyTargetKey: {
        targetResource: targetResource
      },
      policySchemaFilter: "chrome.devices.updates.UpdatePolicyOverride",
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

    Logger.log("[ID-171] Solicitando política chrome.devices.updates.UpdatePolicyOverride...");
    try {
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      const text = response.getContentText();
      
      Logger.log(`[ID-171 - DETALLE API] HTTP Code: ${code}`);
      Logger.log(`[ID-171 - DETALLE API] RAW JSON: ${text}`);

      if (code === 200) {
        const json = JSON.parse(text);
        const resolvedPolicies = json.resolvedPolicies || [];
        
        if (resolvedPolicies.length > 0) {
          anyFound = true;
          resolvedPolicies.forEach((policy) => {
            const val = policy.value && policy.value.value;
            if (val && val.updatePolicyOverride !== undefined) {
              updatePolicyOverrideValue = val.updatePolicyOverride;
              Logger.log(`[ID-171 - PARSEO] Encontrada variable 'updatePolicyOverride'. Valor: ${updatePolicyOverrideValue}`);
            }
          });
        } else {
          Logger.log("[ID-171 - INFO] La API no devolvió políticas explícitas en la raíz. Chrome heredará el comportamiento por defecto (Permitir actualizaciones automáticas siempre).");
        }
      } else {
        Logger.log(`[ID-171 - ERROR] Petición fallida a la API con HTTP ${code}`);
      }
    } catch (e) {
      Logger.log(`[ID-171 - ERROR EXCEPCIÓN] Fallo de red: ${e.message}`);
    }

    // 4. Lógica de Riesgos y Construcción de la Respuesta
    // Valores estándar conocidos del ENUM de UpdatePolicyOverride:
    // - "UPDATE_POLICY_ENUM_DEFAULT" o 0: Actualizaciones siempre permitidas por defecto
    // - "UPDATE_POLICY_ENUM_UPDATES_DISABLED" o 1: Actualizaciones completamente desactivadas (CRÍTICO)
    // - "UPDATE_POLICY_ENUM_MANUAL_UPDATES_ONLY" o 2: Solo actualizaciones manuales
    // - "UPDATE_POLICY_ENUM_AUTOMATIC_UPDATES_ONLY" o 3: Forzar estrictamente actualizaciones automáticas
    
    let riesgo171, comentario171, valorPrincipal;

    if (!anyFound || updatePolicyOverrideValue === null) {
      riesgo171 = "Bajo";
      valorPrincipal = "No Configurado (Permitido por defecto / 0)";
      comentario171 = "La política de actualización de Chrome no está configurada de manera explícita en la raíz del dominio. El navegador adopta el comportamiento nativo seguro de Google, el cual permite y descarga de forma automática las últimas versiones estables tan pronto son publicadas.";
    } else {
      const overrideStr = updatePolicyOverrideValue.toString();

      if (overrideStr.includes("DISABLED") || overrideStr === "1") {
        riesgo171 = "Alto";
        valorPrincipal = "Actualizaciones Deshabilitadas";
        comentario171 = "Las actualizaciones del navegador Chrome se encuentran completamente DESACTIVADAS por política corporativa. Esto impide que los dispositivos mitiguen fallos críticos de seguridad o vulnerabilidades de día cero explotadas en la naturaleza, lo que representa un riesgo de intrusión inminente.";
      } else if (overrideStr.includes("MANUAL") || overrideStr === "2") {
        riesgo171 = "Alto";
        valorPrincipal = "Solo Actualizaciones Manuales";
        comentario171 = "La política restringe las actualizaciones a ejecución puramente manual por parte del usuario final o de herramientas externas. Esto fragmenta la homogeneidad de parches de seguridad en la flota de dispositivos corporativos, elevando significativamente el nivel de riesgo.";
      } else if (overrideStr.includes("AUTOMATIC") || overrideStr.includes("DEFAULT") || overrideStr === "3" || overrideStr === "0") {
        riesgo171 = "Bajo";
        valorPrincipal = overrideStr.includes("AUTOMATIC") ? "Actualizaciones Automáticas Forzadas" : "Permitido por Defecto";
        comentario171 = `La configuración de actualización del navegador es segura (${overrideStr}). Se garantiza que la flota de navegadores Chrome descargará e instalará de forma continua parches de seguridad y mejoras de código sin requerir intervención manual extensa.`;
      } else {
        riesgo171 = "Medio";
        valorPrincipal = `Configuración Alternativa (${overrideStr})`;
        comentario171 = `Se detectó un valor inusual o personalizado para la directiva de actualizaciones (${overrideStr}). Se recomienda validar que el comportamiento resultante no cause retrasos prolongados en el ciclo de parches del navegador corporativo.`;
      }
    }

    Logger.log(`[ID-171] Diagnóstico Terminado. Valor Detectado: ${updatePolicyOverrideValue} | Riesgo Asignado: ${riesgo171}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-171 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario171: comentario171,
      riesgo171: riesgo171,
      score171: this.calcularScoreDeRiesgo(riesgo171)
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
    Logger.log(`[ID-171] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario171: `Ocurrió un error inesperado al procesar la API: ${msg}`,
      riesgo171: "Medio",
      score171: 2
    };
  }
}