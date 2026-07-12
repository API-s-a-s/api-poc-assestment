/**
 * Configuración Evaluada: Password alert
 * Filtro de Esquema / Búsqueda: chrome.users.PasswordProtectionWarningTrigger y chrome.users.PasswordProtectionLoginURLs
 * Variables de Configuración Real API: passwordProtectionWarningTrigger y passwordProtectionLoginURLs
 */
class ChromePasswordAlertStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-169",
        valueKey: "valorPrincipal",
        noteKey: "comentario169",
        riskKey: "riesgo169",
        scoreKey: "score169"
      }
    ];

    super("Chrome Password Alert Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Navegación segura de Chrome";
  }

  /**
   * Evalúa las políticas de alerta de contraseñas en la raíz del dominio.
   * @param {Object} globalContext Contexto global de ejecución.
   */
  evaluateInMemory(globalContext) {
    const auth = globalContext.auth || new AuthService();
    const adminEmail = auth.getCurrentUserEmail();

    Logger.log("========== INICIO DIAGNÓSTICO ID-169 (PASSWORD ALERT) ==========");

    // 1. Obtener Token DWD
    let dwdHeader = null;
    try {
      dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/chrome.management.policy.readonly"
      ]);
      Logger.log("[ID-169] Token DWD generado con éxito para Chrome Policy API.");
    } catch (e) {
      Logger.log(`[ID-169 - ERROR] No se pudo obtener el token DWD: ${e.message}`);
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
        Logger.log(`[ID-169] Raíz resuelta por hija directa: ${rootOuId}`);
      } else if (orgUnits.length > 0) {
        const anyOuWithParent = orgUnits.find(ou => ou.parentOrgUnitId);
        if (anyOuWithParent) {
          rootOuId = anyOuWithParent.parentOrgUnitId.replace(/^id:/, "");
          Logger.log(`[ID-169] Raíz resuelta por UO genérica: ${rootOuId}`);
        }
      }
    } catch (e) {
      Logger.log(`[ID-169 - WARN] No se pudo mapear la raíz vía AdminDirectory: ${e.message}`);
    }

    if (!rootOuId && this.customerId && this.customerId !== "my_customer") {
      rootOuId = this.customerId;
    }

    if (!rootOuId || rootOuId === "my_customer") {
      Logger.log("[ID-169 - ERROR CRÍTICO] No se pudo obtener el ID real de la OU.");
      return this._buildErrorResponse("No se pudo resolver el ID de la OU raíz (Se bloqueó la petición para evitar Error 404).");
    }

    const targetResource = `orgunits/${rootOuId}`;
    Logger.log(`[ID-169] Target Resource definitivo para la API: ${targetResource}`);

    let warningTriggerValue = null;
    let loginUrlsValue = [];
    let anyFound = false;

    // 3. Consultar las dos políticas secuencialmente
    const schemasToFetch = [
      "chrome.users.PasswordProtectionWarningTrigger",
      "chrome.users.PasswordProtectionLoginURLs"
    ];

    for (const schema of schemasToFetch) {
      const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;
      const payload = {
        policyTargetKey: { targetResource: targetResource },
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

      Logger.log(`[ID-169] Solicitando política: ${schema}...`);
      try {
        const response = UrlFetchApp.fetch(url, options);
        const code = response.getResponseCode();
        const text = response.getContentText();
        
        if (code === 200) {
          const json = JSON.parse(text);
          const resolvedPolicies = json.resolvedPolicies || [];
          
          if (resolvedPolicies.length > 0) {
            anyFound = true;
            resolvedPolicies.forEach((policy) => {
              const val = policy.value && policy.value.value;
              if (val) {
                if (schema.includes("WarningTrigger") && val.passwordProtectionWarningTrigger !== undefined) {
                  warningTriggerValue = val.passwordProtectionWarningTrigger;
                  Logger.log(`[ID-169 - PARSEO] Trigger detectado: ${warningTriggerValue}`);
                }
                if (schema.includes("LoginURLs") && val.passwordProtectionLoginURLs !== undefined) {
                  loginUrlsValue = val.passwordProtectionLoginURLs;
                  Logger.log(`[ID-169 - PARSEO] Login URLs detectadas: ${loginUrlsValue.length} URLs configuradas.`);
                }
              }
            });
          } else {
            Logger.log(`[ID-169 - INFO] Sin políticas explícitas en la raíz para ${schema}.`);
          }
        } else {
          Logger.log(`[ID-169 - ERROR] HTTP ${code} al consultar ${schema}`);
        }
      } catch (e) {
        Logger.log(`[ID-169 - ERROR EXCEPCIÓN] Fallo de red en ${schema}: ${e.message}`);
      }
    }

    // 4. Lógica de Riesgos y Construcción de la Respuesta
    // Valores típicos de PasswordProtectionWarningTrigger:
    // - "PASSWORD_PROTECTION_TRIGGER_ENUM_OFF" o 0 (Desactivado)
    // - "PASSWORD_PROTECTION_TRIGGER_ENUM_PASSWORD_REUSE" o 1 (Advertir al reutilizar)
    // - "PASSWORD_PROTECTION_TRIGGER_ENUM_PHISHING_REUSE" o 2 (Advertir solo en sitios de phishing)

    let riesgo169, comentario169, valorPrincipal;
    const triggerStr = warningTriggerValue ? warningTriggerValue.toString() : "";

    if (!anyFound || warningTriggerValue === null || triggerStr.includes("OFF") || triggerStr === "0") {
      riesgo169 = "Alto";
      valorPrincipal = "Deshabilitado / No Configurado";
      comentario169 = "La protección contra la reutilización de contraseñas (Password Alert) no está configurada o está desactivada. Esto expone a la organización al riesgo de que los usuarios introduzcan sus credenciales corporativas en sitios web de phishing o servicios de terceros no confiables sin recibir ninguna advertencia por parte de Chrome.";
    } else {
      riesgo169 = "Bajo";
      
      let protectionType = triggerStr.includes("PHISHING") ? "Alerta en Phishing" : "Alerta por Reutilización Global";
      valorPrincipal = `Habilitado (${protectionType})`;
      
      comentario169 = `La protección de contraseñas está activa (${triggerStr}). Chrome advertirá a los usuarios si introducen su contraseña corporativa en sitios web peligrosos o no autorizados.`;
      
      if (loginUrlsValue && loginUrlsValue.length > 0) {
        comentario169 += ` Además, se han configurado explícitamente ${loginUrlsValue.length} URL(s) corporativas para delimitar el alcance de la protección.`;
      } else {
        comentario169 += ` (Nota: No se detectaron URLs de inicio de sesión específicas configuradas en 'PasswordProtectionLoginURLs', lo que podría hacer que la protección asuma las configuraciones por defecto de sincronización).`;
      }
    }

    Logger.log(`[ID-169] Diagnóstico Terminado. Trigger: ${warningTriggerValue} | URLs: ${loginUrlsValue.length} | Riesgo: ${riesgo169}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-169 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario169: comentario169,
      riesgo169: riesgo169,
      score169: this.calcularScoreDeRiesgo(riesgo169)
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
    Logger.log(`[ID-169] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario169: `Ocurrió un error inesperado al procesar la API: ${msg}`,
      riesgo169: "Medio",
      score169: 2
    };
  }
}