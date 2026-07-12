/**
 * Estrategia de Auditoría para Política de máquina de Chrome (Ámbito Machine).
 * Evalúa si la organización tiene aplicadas políticas a nivel de dispositivo.
 * 
 * ID Evaluado: ID-160
 * Configuración Evaluada: Política de máquina de Chrome
 * Filtro de Esquema / Búsqueda: chrome.devices.*
 * Variable de Configuración: Modificadores del ámbito machine (políticas de dispositivo)
 */
class ChromeMachinePolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-160",
        valueKey: "valorPrincipal",
        noteKey: "comentario160",
        riskKey: "riesgo160",
        scoreKey: "score160"
      }
    ];

    super("Chrome Machine Policy Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Gestión de navegadores";
  }

  /**
   * Evalúa las políticas de dispositivos (chrome.devices.*) en memoria y mediante DWD.
   * @param {Object} globalContext Contexto global de ejecución.
   */
  evaluateInMemory(globalContext) {
    const auth = globalContext.auth || new AuthService();
    const adminEmail = auth.getCurrentUserEmail();

    Logger.log("========== INICIO DIAGNÓSTICO ID-160 (POLÍTICA DE MÁQUINA CHROME) ==========");

    // 1. Obtener la cabecera de autenticación mediante DWD
    let dwdHeader = null;
    try {
      dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/chrome.management.policy.readonly"
      ]);
      Logger.log("[ID-160] Token DWD generado con éxito para Chrome Policy API.");
    } catch (e) {
      Logger.log(`[ID-160 - ERROR] No se pudo obtener el token DWD: ${e.message}`);
      return this._buildErrorResponse(`Fallo al generar token DWD: ${e.message}`);
    }

    // 2. Resolver dinámicamente el ID de la OU raíz.
    let rootOuId = "";
    try {
      const response = AdminDirectory.Orgunits.list(this.customerId, { type: "all" });
      const orgUnits = response.organizationUnits || [];
      
      const childOfRoot = orgUnits.find(ou => ou.parentOrgUnitPath === "/");
      if (childOfRoot && childOfRoot.parentOrgUnitId) {
        rootOuId = childOfRoot.parentOrgUnitId.replace(/^id:/, "");
        Logger.log(`[ID-160] ID de OU raíz resuelto desde parentOrgUnitId de '${childOfRoot.orgUnitPath}': ${rootOuId}`);
      } else {
        const anyOuWithParent = orgUnits.find(ou => ou.parentOrgUnitId);
        if (anyOuWithParent && anyOuWithParent.parentOrgUnitId) {
          rootOuId = anyOuWithParent.parentOrgUnitId.replace(/^id:/, "");
          Logger.log(`[ID-160] ID de OU raíz resuelto desde parentOrgUnitId alternativo de '${anyOuWithParent.orgUnitPath}': ${rootOuId}`);
        }
      }
    } catch (e) {
      Logger.log(`[ID-160 - ERROR] No se pudo obtener la lista de OUs de AdminDirectory: ${e.message}`);
    }

    if (!rootOuId) {
      Logger.log("[ID-160 - ERROR CRÍTICO] No se pudo resolver el ID de la OU raíz.");
      return this._buildErrorResponse("No se pudo resolver el ID de la OU raíz.");
    }

    const targetResource = `orgunits/${rootOuId}`;
    let resolvedCount = 0;
    let details = [];

    // 3. Consultar las políticas efectivas de dispositivos a la API
    const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;
    const payload = {
      policyTargetKey: {
        targetResource: targetResource
      },
      policySchemaFilter: "chrome.devices.*",
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

    Logger.log("[ID-160] Consultando políticas de ámbito dispositivo (chrome.devices.*)...");
    try {
      const response = UrlFetchApp.fetch(url, options);
      const code = response.getResponseCode();
      const text = response.getContentText();
      Logger.log(`[ID-160] Respuesta HTTP ${code} de API resolve: ${text}`);

      if (code === 200) {
        const json = JSON.parse(text);
        const resolvedPolicies = json.resolvedPolicies || [];
        resolvedCount = resolvedPolicies.length;
        
        resolvedPolicies.forEach(policy => {
          const schemaId = policy.value && policy.value.policySchema;
          if (schemaId) {
            details.push(schemaId.split("/").pop());
          }
        });
      } else {
        Logger.log(`[ID-160 - ERROR] La API de resolución devolvió el código HTTP ${code}`);
      }
    } catch (e) {
      Logger.log(`[ID-160 - ERROR] Excepción al invocar resolve API: ${e.message}`);
    }

    // 4. Asignación de riesgo y construcción de respuesta
    let riesgo160, comentario160, valorPrincipal;

    if (resolvedCount > 0) {
      riesgo160 = "Bajo";
      valorPrincipal = "Configurado";
      comentario160 = `Se detectaron ${resolvedCount} políticas a nivel de dispositivo (ámbito Machine) activas en la raíz del dominio. Políticas: ${details.join(", ")}. Esto asegura controles de máquina persistentes.`;
    } else {
      riesgo160 = "Medio";
      valorPrincipal = "Sin Configurar";
      comentario160 = "No se encontraron políticas activas a nivel de dispositivo (ámbito Machine, bajo el filtro chrome.devices.*). Toda la gestión de políticas está orientada a nivel de usuario o perfil. Se recomienda evaluar la aplicación de políticas de máquina para endurecer los controles de los dispositivos corporativos.";
    }

    Logger.log(`[ID-160] Diagnóstico completado. Políticas encontradas: ${resolvedCount} | Riesgo: ${riesgo160}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-160 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario160: comentario160,
      riesgo160: riesgo160,
      score160: this.calcularScoreDeRiesgo(riesgo160)
    };
  }

  /**
   * Calcula el score numérico a partir del nivel de riesgo.
   * @param {string} nivelRiesgo
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
   * Respuesta en caso de excepción irrecuperable.
   */
  _buildErrorResponse(msg) {
    Logger.log(`[ID-160] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario160: `Ocurrió un error en la evaluación de la directiva: ${msg}`,
      riesgo160: "Medio",
      score160: 2
    };
  }
}
