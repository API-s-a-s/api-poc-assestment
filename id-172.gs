/**
 * ID Evaluado: ID-172
 * Configuración Evaluada: Precedencia de políticas (por defecto Machine > OS User > Chrome profile)
 * Filtro de Esquema / Búsqueda: chrome.users.CloudUserPolicyOverridesCloudPolicy
 * Variable de Configuración Real API: cloudUserPolicyOverridesCloudPolicy (camelCase)
 */
class ChromePolicyPrecedenceStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-172",
        valueKey: "valorPrincipal",
        noteKey: "comentario172",
        riskKey: "riesgo172",
        scoreKey: "score172"
      }
    ];

    super("Chrome Policy Precedence Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Gestión de navegadores";
  }

  /**
   * Evalúa la política 'chrome.users.CloudUserPolicyOverridesCloudPolicy' en la raíz.
   * @param {Object} globalContext Contexto global de ejecución.
   */
  evaluateInMemory(globalContext) {
    const auth = globalContext.auth || new AuthService();
    const adminEmail = auth.getCurrentUserEmail();

    Logger.log("========== INICIO DIAGNÓSTICO ID-172 (POLICY PRECEDENCE) ==========");

    // 1. Obtener Token DWD
    let dwdHeader = null;
    try {
      dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/chrome.management.policy.readonly"
      ]);
      Logger.log("[ID-172] Token DWD generado con éxito para Chrome Policy API.");
    } catch (e) {
      Logger.log(`[ID-172 - ERROR] No se pudo obtener el token DWD: ${e.message}`);
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
        Logger.log(`[ID-172] Raíz resuelta por hija directa: ${rootOuId}`);
      } else if (orgUnits.length > 0) {
        const anyOuWithParent = orgUnits.find(ou => ou.parentOrgUnitId);
        if (anyOuWithParent) {
          rootOuId = anyOuWithParent.parentOrgUnitId.replace(/^id:/, "");
          Logger.log(`[ID-172] Raíz resuelta por OU genérica: ${rootOuId}`);
        }
      }
    } catch (e) {
      Logger.log(`[ID-172 - WARN] No se pudo mapear la raíz vía AdminDirectory: ${e.message}`);
    }

    if (!rootOuId && this.customerId && this.customerId !== "my_customer") {
      rootOuId = this.customerId;
    }

    // Bloqueo preventivo de 404
    if (!rootOuId || rootOuId === "my_customer") {
      Logger.log("[ID-172 - ERROR CRÍTICO] No se pudo obtener el ID real de la OU.");
      return this._buildErrorResponse("No se pudo resolver el ID de la OU raíz (Se bloqueó la petición para evitar Error 404).");
    }

    const targetResource = `orgunits/${rootOuId}`;
    Logger.log(`[ID-172] Target Resource definitivo para la API: ${targetResource}`);

    let overridesCloudPolicyValue = null;
    let anyFound = false;

    // 3. Preparar la llamada a la Chrome Policy API
    const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;
    const payload = {
      policyTargetKey: {
        targetResource: targetResource
      },
      policySchemaFilter: "chrome.users.CloudUserPolicyOverridesCloudPolicy",
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

    Logger.log("[ID-172] Solicitando política chrome.users.CloudUserPolicyOverridesCloudPolicy...");
    try {
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      const text = response.getContentText();
      
      Logger.log(`[ID-172 - DETALLE API] HTTP Code: ${code}`);
      Logger.log(`[ID-172 - DETALLE API] RAW JSON: ${text}`);

      if (code === 200) {
        const json = JSON.parse(text);
        const resolvedPolicies = json.resolvedPolicies || [];
        
        if (resolvedPolicies.length > 0) {
          anyFound = true;
          resolvedPolicies.forEach((policy) => {
            const val = policy.value && policy.value.value;
            if (val && val.cloudUserPolicyOverridesCloudPolicy !== undefined) {
              overridesCloudPolicyValue = val.cloudUserPolicyOverridesCloudPolicy;
              Logger.log(`[ID-172 - PARSEO] Encontrada variable 'cloudUserPolicyOverridesCloudPolicy'. Valor: ${overridesCloudPolicyValue}`);
            }
          });
        } else {
          Logger.log("[ID-172 - INFO] La API no devolvió políticas explícitas en la raíz. Chrome respetará la jerarquía por defecto (Máquina > Usuario).");
        }
      } else {
        Logger.log(`[ID-172 - ERROR] Petición fallida a la API con HTTP ${code}`);
      }
    } catch (e) {
      Logger.log(`[ID-172 - ERROR EXCEPCIÓN] Fallo de red: ${e.message}`);
    }

    // 4. Lógica de Riesgos y Construcción de la Respuesta
    let riesgo172, comentario172, valorPrincipal;

    if (overridesCloudPolicyValue === true) {
      riesgo172 = "Alto";
      valorPrincipal = "Anulación Permitida (Inseguro)";
      comentario172 = "La política permite que las directivas a nivel de usuario en la nube anulen las directivas a nivel de máquina. Esto rompe la jerarquía recomendada de seguridad y permite que configuraciones más débiles vinculadas a un perfil de usuario sobreescriban los controles del dispositivo corporativo.";
    } else {
      // overridesCloudPolicyValue === false || null (comportamiento por defecto)
      riesgo172 = "Bajo";
      valorPrincipal = "Jerarquía por Defecto (Seguro)";
      comentario172 = "La precedencia de políticas se mantiene en su jerarquía segura por defecto (Máquina > Máquina en la Nube > Usuario). Esto asegura que las configuraciones de endurecimiento a nivel de dispositivo no puedan ser evadidas o sobreescritas por políticas a nivel de perfil de usuario.";
    }

    Logger.log(`[ID-172] Diagnóstico Terminado. Valor Detectado: ${overridesCloudPolicyValue} | Riesgo Asignado: ${riesgo172}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-172 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario172: comentario172,
      riesgo172: riesgo172,
      score172: this.calcularScoreDeRiesgo(riesgo172)
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
    Logger.log(`[ID-172] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario172: `Ocurrió un error inesperado al procesar la API: ${msg}`,
      riesgo172: "Medio",
      score172: 2
    };
  }
}