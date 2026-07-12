/**
 * Estrategia de Auditoría para Gestión en la nube del navegador Chrome (CBCM).
 * Evalúa si la organización tiene activado el reporte en la nube de navegadores y perfiles Chrome.
 * 
 * ID Evaluado: ID-159
 * Configuración Evaluada: Gestión en la nube del navegador Chrome: Inscribir nuevos navegadores Chrome
 * Filtro de Esquema / Búsqueda: chrome.users.CloudReporting, chrome.users.CloudProfileReportingEnabled
 * Variables de Configuración: cloudReportingEnabled, cloudProfileReportingEnabled
 */
class ChromeCloudEnrollmentStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-159",
        valueKey: "valorPrincipal",
        noteKey: "comentario159",
        riskKey: "riesgo159",
        scoreKey: "score159"
      }
    ];

    super("Chrome Cloud Browser Enrollment and Reporting Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Gestión de navegadores";
  }

  /**
   * Evalúa las políticas de reportes en la nube en memoria y mediante DWD.
   * @param {Object} globalContext Contexto global de ejecución.
   */
  evaluateInMemory(globalContext) {
    const auth = globalContext.auth || new AuthService();
    const adminEmail = auth.getCurrentUserEmail();

    Logger.log("========== INICIO DIAGNÓSTICO ID-159 (GESTIÓN NAVEGADOR CHROME) ==========");

    // 1. Obtener la cabecera de autenticación mediante DWD
    let dwdHeader = null;
    try {
      dwdHeader = auth.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/chrome.management.policy.readonly"
      ]);
      Logger.log("[ID-159] Token DWD generado con éxito para Chrome Policy API.");
    } catch (e) {
      Logger.log(`[ID-159 - ERROR] No se pudo obtener el token DWD: ${e.message}`);
      return this._buildErrorResponse(`Fallo al generar token DWD: ${e.message}`);
    }

    // 2. Resolver dinámicamente el ID de la OU raíz.
    //    AdminDirectory.Orgunits.list() NUNCA devuelve la raíz ("/") explícitamente.
    //    Pero las OUs hijas directas de "/" sí exponen el campo parentOrgUnitId,
    //    que contiene el ID real de la OU raíz.
    let rootOuId = "";
    try {
      const response = AdminDirectory.Orgunits.list(this.customerId, { type: "all" });
      const orgUnits = response.organizationUnits || [];

      // Buscar cualquier OU hija directa de "/" y usar su parentOrgUnitId
      const childOfRoot = orgUnits.find(ou => ou.parentOrgUnitPath === "/");
      if (childOfRoot && childOfRoot.parentOrgUnitId) {
        rootOuId = childOfRoot.parentOrgUnitId.replace(/^id:/, "");
        Logger.log(`[ID-159] ID de OU raíz resuelto desde parentOrgUnitId de '${childOfRoot.orgUnitPath}': ${rootOuId}`);
      } else {
        Logger.log("[ID-159 - WARN] No se encontró ninguna OU hija de '/' con parentOrgUnitId. Verificando OUs disponibles...");
        orgUnits.slice(0, 5).forEach(ou => {
          Logger.log(`[ID-159 - DEBUG OU] path=${ou.orgUnitPath}, id=${ou.orgUnitId}, parentPath=${ou.parentOrgUnitPath}, parentId=${ou.parentOrgUnitId}`);
        });
      }
    } catch (e) {
      Logger.log(`[ID-159 - ERROR] No se pudo obtener la lista de OUs de AdminDirectory: ${e.message}`);
    }

    if (!rootOuId) {
      Logger.log("[ID-159 - ERROR CRÍTICO] No se pudo resolver el ID de la OU raíz. La Chrome Policy API requiere un Org Unit ID explícito.");
      return this._buildErrorResponse("No se pudo resolver el ID de la OU raíz. Verifique que existan OUs hijas de '/' en el dominio.");
    }

    const targetResource = `orgunits/${rootOuId}`;
    
    let cloudReportingEnabled = false;
    let cloudProfileReportingEnabled = false;
    let anyFound = false;

    // 3. Consultar las dos variables de reporte del navegador Chrome a la API
    const schemas = ["chrome.users.CloudReporting", "chrome.users.CloudProfileReportingEnabled"];
    
    for (const schema of schemas) {
      const url = `https://chromepolicy.googleapis.com/v1/customers/${this.customerId}/policies:resolve`;
      const payload = {
        policyTargetKey: {
          targetResource: targetResource
        },
        policySchemaFilter: schema,
        pageSize: 10
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

      Logger.log(`[ID-159] Consultando políticas efectivas para el esquema: ${schema}`);
      try {
        const response = UrlFetchApp.fetch(url, options);
        const code = response.getResponseCode();
        const text = response.getContentText();
        Logger.log(`[ID-159] Respuesta HTTP ${code} de API resolve: ${text}`);

        if (code === 200) {
          const json = JSON.parse(text);
          const resolvedPolicies = json.resolvedPolicies || [];
          if (resolvedPolicies.length > 0) {
            anyFound = true;
            resolvedPolicies.forEach(policy => {
              const val = policy.value && policy.value.value;
              if (val) {
                if (schema === "chrome.users.CloudReporting" && val.cloudReportingEnabled !== undefined) {
                  cloudReportingEnabled = val.cloudReportingEnabled === true;
                }
                if (schema === "chrome.users.CloudProfileReportingEnabled" && val.cloudProfileReportingEnabled !== undefined) {
                  cloudProfileReportingEnabled = val.cloudProfileReportingEnabled === true;
                }
              }
            });
          }
        } else {
          Logger.log(`[ID-159 - ERROR] La API de resolución devolvió el código HTTP ${code}`);
        }
      } catch (e) {
        Logger.log(`[ID-159 - ERROR] Excepción al invocar resolve API: ${e.message}`);
      }
    }

    // 4. Asignación de riesgo y construcción de respuesta
    // El reporte del estado en la nube de Chrome (CBCM) es la base para verificar el estado de inscripción y auditoría
    const reportingActive = cloudReportingEnabled || cloudProfileReportingEnabled;
    let riesgo159, comentario159, valorPrincipal;

    if (reportingActive) {
      riesgo159 = "Bajo";
      valorPrincipal = "Habilitado";
      comentario159 = `El reporte en la nube de Chrome está activo en la raíz. (CloudReportingEnabled: ${cloudReportingEnabled ? "Sí" : "No"}, CloudProfileReportingEnabled: ${cloudProfileReportingEnabled ? "Sí" : "No"}). Permite monitorear navegadores inscritos y auditoría.`;
    } else {
      riesgo159 = "Alto";
      valorPrincipal = "Deshabilitado";
      comentario159 = "El reporte en la nube de navegadores y perfiles de Chrome se encuentra deshabilitado o no configurado en la raíz. Los navegadores empresariales no enviarán telemetría ni datos de auditoría a la consola.";
    }

    Logger.log(`[ID-159] Diagnóstico completado. Reporte activo: ${reportingActive} | Riesgo: ${riesgo159}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-159 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario159: comentario159,
      riesgo159: riesgo159,
      score159: this.calcularScoreDeRiesgo(riesgo159)
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
    Logger.log(`[ID-159] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario159: `Ocurrió un error en la evaluación de la directiva: ${msg}`,
      riesgo159: "Medio",
      score159: 2
    };
  }
}
